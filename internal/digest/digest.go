// Package digest implements HTTP digest authentication for Intel AMT.
// This is a patched version that handles malformed headers from some Intel NUCs.
package digest

import (
	"crypto/md5" //nolint: gosec // we're constrained to MD5 by Intel AMT
	"crypto/rand"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Package level compiled regular expressions to avoid compilation on each call.
var (
	// digestFieldRe extracts key="value" pairs from digest auth headers.
	// Handles both comma-separated and space-separated fields, and supports escaped quotes in values.
	digestFieldRe = regexp.MustCompile(`(\w+)="((?:\\.|[^"\\])*)"`)
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

// parseChallenge is based on https://code.google.com/p/mlab-ns2/source/browse/gae/ns/digest/digest.go#90
// but modified to handle malformed Intel AMT headers:
//   - Space-separated fields instead of comma-separated.
//   - Malformed qop values like "auth auth-int  auth".
func (c *challenge) parseChallenge(input string) error {
	const ws = " \n\r\t"
	s := strings.Trim(input, ws)
	if !strings.HasPrefix(s, "Digest ") {
		return fmt.Errorf("challenge is bad, missing prefix: %s", input)
	}
	s = strings.Trim(s[7:], ws)
	c.Algorithm = "MD5"

	matches := digestFieldRe.FindAllStringSubmatch(s, -1)

	for _, match := range matches {
		// match is [fullMatch, key, value] from the regex (\w+)="((?:\\.|[^"\\])*)", which supports escaped characters in values.
		key := strings.TrimSpace(match[1])
		value := match[2]

		switch key {
		case "realm":
			c.Realm = value
		case "domain":
			c.Domain = value
		case "nonce":
			c.Nonce = value
		case "opaque":
			c.Opaque = value
		case "stale":
			c.Stale = value
		case "algorithm":
			c.Algorithm = value
		case "qop":
			c.Qop = normalizeQop(value)
		}
	}
	return nil
}

// normalizeQop handles malformed qop values from some Intel AMT implementations.
// Some Intel NUCs return qop like "auth auth-int  auth" (space-separated with
// duplicates and extra whitespace) instead of the standard comma-separated format.
// If "auth" is not found, returns empty string to fall back to no-qop behavior.
func normalizeQop(qop string) string {
	// Normalize separators and pad with spaces for word boundary check.
	// This avoids array allocation from splitting.
	padded := " " + strings.ReplaceAll(qop, ",", " ") + " "
	if strings.Contains(padded, " auth ") {
		return "auth"
	}
	return ""
}
