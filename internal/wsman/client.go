// Package wsman implements a simple WSMAN client interface.
// It assumes you are talking to WSMAN over http(s) and using
// basic authentication.
package wsman

/*
Copyright 2015 Victor Lowther <victor.lowther@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import (
	"context"
	"crypto/md5" //nolint: gosec // we're constrained to MD5 by Intel AMT
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/VictorLowther/simplexml/dom"
	"github.com/VictorLowther/soap"
	"github.com/go-logr/logr"
)

type challenge struct {
	Username   string
	Password   string
	Realm      string
	CSRFToken  string
	Domain     string
	Nonce      string
	Opaque     string
	Stale      string
	Algorithm  string
	Qop        string
	Cnonce     string
	NonceCount int
}

func h(data string) string {
	hf := md5.New() //nolint: gosec // we're constrained to MD5 by Intel AMT
	_, _ = io.WriteString(hf, data)
	return fmt.Sprintf("%x", hf.Sum(nil))
}

func kd(secret, data string) string {
	return h(fmt.Sprintf("%s:%s", secret, data))
}

func (c *challenge) ha1() string {
	return h(fmt.Sprintf("%s:%s:%s", c.Username, c.Realm, c.Password))
}

func (c *challenge) ha2(method, uri string) string {
	return h(fmt.Sprintf("%s:%s", method, uri))
}

func (c *challenge) resp(method, uri, cnonce string) (string, error) {
	c.NonceCount++
	if c.Qop == "auth" {
		if cnonce != "" {
			c.Cnonce = cnonce
		} else {
			b := make([]byte, 8)
			if _, err := io.ReadFull(rand.Reader, b); err != nil {
				return "", err
			}
			c.Cnonce = fmt.Sprintf("%x", b)[:16]
		}
		return kd(c.ha1(), fmt.Sprintf("%s:%08x:%s:%s:%s",
			c.Nonce, c.NonceCount, c.Cnonce, c.Qop, c.ha2(method, uri))), nil
	} else if c.Qop == "" {
		return kd(c.ha1(), fmt.Sprintf("%s:%s", c.Nonce, c.ha2(method, uri))), nil
	}
	return "", fmt.Errorf("alg not implemented")
}

// source https://code.google.com/p/mlab-ns2/source/browse/gae/ns/digest/digest.go#178
func (c *challenge) authorize(method, uri string) (string, error) {
	// Note that this is only implemented for MD5 and NOT MD5-sess.
	// MD5-sess is rarely supported and those that do are a big mess.
	if c.Algorithm != "MD5" {
		return "", fmt.Errorf("alg not implemented")
	}
	// Note that this is NOT implemented for "qop=auth-int".  Similarly the
	// auth-int server side implementations that do exist are a mess.
	if c.Qop != "auth" && c.Qop != "" {
		return "", fmt.Errorf("alg not implemented")
	}
	resp, err := c.resp(method, uri, "")
	if err != nil {
		return "", fmt.Errorf("alg not implemented")
	}
	sl := []string{fmt.Sprintf(`username="%s"`, c.Username)}
	sl = append(sl, fmt.Sprintf(`realm="%s"`, c.Realm))
	sl = append(sl, fmt.Sprintf(`nonce="%s"`, c.Nonce))
	sl = append(sl, fmt.Sprintf(`uri="%s"`, uri))
	sl = append(sl, fmt.Sprintf(`response="%s"`, resp))
	if c.Algorithm != "" {
		sl = append(sl, fmt.Sprintf(`algorithm="%s"`, c.Algorithm))
	}
	if c.Opaque != "" {
		sl = append(sl, fmt.Sprintf(`opaque="%s"`, c.Opaque))
	}
	if c.Qop != "" {
		sl = append(sl, fmt.Sprintf("qop=%s", c.Qop))
		sl = append(sl, fmt.Sprintf("nc=%08x", c.NonceCount))
		sl = append(sl, fmt.Sprintf(`cnonce="%s"`, c.Cnonce))
	}
	return fmt.Sprintf("Digest %s", strings.Join(sl, ",")), nil
}

// origin https://code.google.com/p/mlab-ns2/source/browse/gae/ns/digest/digest.go#90
func (c *challenge) parseChallenge(input string) error {
	const ws = " \n\r\t"
	const qs = `"`
	s := strings.Trim(input, ws)
	if !strings.HasPrefix(s, "Digest ") {
		return fmt.Errorf("challenge is bad, missing prefix: %s", input)
	}
	s = strings.Trim(s[7:], ws)
	sl := strings.Split(s, ",")
	c.Algorithm = "MD5"
	var r []string
	for i := range sl {
		r = strings.SplitN(sl[i], "=", 2)
		switch strings.TrimSpace(r[0]) {
		case "realm":
			c.Realm = strings.Trim(r[1], qs)
		case "domain":
			c.Domain = strings.Trim(r[1], qs)
		case "nonce":
			c.Nonce = strings.Trim(r[1], qs)
		case "opaque":
			c.Opaque = strings.Trim(r[1], qs)
		case "stale":
			c.Stale = strings.Trim(r[1], qs)
		case "algorithm":
			c.Algorithm = strings.Trim(r[1], qs)
		case "qop":
			// TODO(gavaletz) should be an array of strings?
			c.Qop = strings.Trim(r[1], qs)
		default:
			return fmt.Errorf("challenge is bad, unexpected token: %s", sl)
		}
	}
	return nil
}

// Client is a thin wrapper around http.Client.
type Client struct {
	OptimizeEnum bool
	Logger       logr.Logger

	http.Client
	target     string
	targetPath string
	username   string
	password   string
	useDigest  bool
	challenge  *challenge
}

// NewClient creates a new wsman.Client.
//
// target must be a URL, and username and password must be the
// username and password to authenticate to the controller with.  If
// username or password are empty, we will not try to authenticate.
// If useDigest is true, we will try to use digest auth instead of
// basic auth.
func NewClient(ctx context.Context, log logr.Logger, target, username, password string, useDigest bool) (*Client, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target as url %v", err)
	}
	logger := logr.Discard()
	if log.GetSink() != nil {
		logger = log
	}
	res := &Client{
		target:     target,
		targetPath: u.Path,
		username:   username,
		password:   password,
		useDigest:  useDigest,
		Logger:     logger,
	}
	// res.Timeout = 10 * time.Second
	res.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // not handling certs right now
	}
	if res.useDigest {
		res.challenge = &challenge{Username: res.username, Password: res.password}
		req, err := http.NewRequestWithContext(ctx, "POST", res.target, nil)
		if err != nil {
			return nil, fmt.Errorf("unable to create request digest auth with %s: %v", res.target, err)
		}
		resp, err := res.Do(req)
		if err != nil {
			return nil, fmt.Errorf("unable to perform digest auth with %s: %v", res.target, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 401 {
			return nil, fmt.Errorf("no digest auth at %s", res.target)
		}
		if err := res.challenge.parseChallenge(resp.Header.Get("WWW-Authenticate")); err != nil {
			return nil, fmt.Errorf("failed to parse auth header %v", err)
		}
	}
	return res, nil
}

// Endpoint returns the endpoint that the Client will try to ocmmunicate with.
func (c *Client) Endpoint() string {
	return c.target
}

// Post overrides http.Client's Post method and adds digext auth handling
// and SOAP pre and post processing.
func (c *Client) Post(ctx context.Context, msg *soap.Message) (response *soap.Message, err error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.target, msg.Reader())
	if err != nil {
		return nil, err
	}
	if c.username != "" && c.password != "" {
		if c.useDigest {
			auth, err := c.challenge.authorize("POST", c.targetPath)
			if err != nil {
				return nil, fmt.Errorf("failed digest auth %v", err)
			}
			req.Header.Set("Authorization", auth)
		} else {
			req.SetBasicAuth(c.username, c.password)
		}
	}
	req.Header.Add("content-type", soap.ContentType)
	c.Logger.V(1).Info("debug", "request", req, "body", msg.String())

	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if c.useDigest && res.StatusCode == 401 {
		c.Logger.V(1).Info("Digest reauthorizing")
		if err := c.challenge.parseChallenge(res.Header.Get("WWW-Authenticate")); err != nil {
			return nil, err
		}
		auth, err := c.challenge.authorize("POST", c.targetPath)
		if err != nil {
			return nil, fmt.Errorf("failed digest auth %v", err)
		}
		req, err = http.NewRequestWithContext(ctx, "POST", c.target, msg.Reader())
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", auth)
		req.Header.Add("content-type", soap.ContentType)
		res, err = c.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
	}

	if res.StatusCode >= 400 {
		b, _ := ioutil.ReadAll(res.Body)
		return nil, fmt.Errorf("wsman.Client: post received %v\n'%v'", res.Status, string(b))
	}
	response, err = soap.Parse(res.Body)
	if err != nil {
		return nil, err
	}

	c.Logger.V(1).Info("debug", "body", response.String())

	return response, nil
}

// Identify performs a basic WSMAN IDENTIFY call.
// The response will provide the version of WSMAN the endpoint
// speaks, along with some details about the WSMAN endpoint itself.
// Note that identify uses soap.Message directly instead of wsman.Message.
func (c *Client) Identify(ctx context.Context) (*soap.Message, error) {
	message := soap.NewMessage()
	message.SetBody(dom.Elem("Identify", NSWSMID))
	return c.Post(ctx, message)
}
