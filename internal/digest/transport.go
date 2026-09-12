package digest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
)

// Transport is an http.RoundTripper that performs HTTP digest authentication
// against Intel AMT, and rewrites the request port and path.
//
// It exists because go-wsman-messages, which builds and parses the WS-Man
// messages, cannot be used for either job:
//
//   - Its digest challenge parser splits on `","`, so it silently mis-parses
//     the space-separated WWW-Authenticate headers some Intel NUCs emit --
//     realm swallows the rest of the header and nonce comes back empty, which
//     surfaces as an authentication failure rather than a parse error. The
//     parser in this package handles those headers; see digest_test.go.
//   - It derives the port from whether TLS is in use and hardcodes the path,
//     so a device on a non-standard port is unreachable through it.
//
// Wiring this in as client.Parameters.Transport with UseDigest false leaves
// go-wsman-messages doing what it is good at and keeps authentication here.
type Transport struct {
	// Base is the underlying transport. http.DefaultTransport when nil.
	Base http.RoundTripper

	Username string
	Password string

	// Port, when non-zero, replaces the port in the request URL.
	Port uint32
	// Path, when non-empty, replaces the request URL path.
	Path string

	// mu guards challenge, which carries the server nonce and its use count
	// across requests. Reusing a challenge avoids a 401 round trip per
	// request; AMT is slow enough that the saving is worth the lock.
	mu        sync.Mutex
	challenge *challenge
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := drainBody(req)
	if err != nil {
		return nil, err
	}

	first := t.prepare(req, body)
	resp, err := t.base().RoundTrip(first)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	// The cached challenge is missing or stale. Take the fresh one and retry
	// once; a second 401 is a real authentication failure and is returned to
	// the caller as-is rather than retried forever.
	header := resp.Header.Get("WWW-Authenticate")
	if header == "" {
		return resp, nil
	}
	if err := t.setChallenge(header); err != nil {
		// Return the 401 rather than the parse error: the caller learns that
		// authentication failed, which is true and more useful than an error
		// about header syntax.
		return resp, nil //nolint:nilerr // the 401 is the more informative result
	}
	drainAndClose(resp)

	return t.base().RoundTrip(t.prepare(req, body))
}

// Prime performs an unauthenticated request to elicit a challenge and cache
// it.
//
// It preserves the pre-migration Open() contract: a 401 carrying a parseable
// digest challenge means the endpoint really is an AMT WS-Man service, and
// anything else is an error. Credentials are deliberately not verified -- only
// the challenge is taken -- because that is what the previous implementation
// did and callers such as bmclib use Open purely to decide whether the
// provider applies to a host.
func (t *Transport) Prime(ctx context.Context, endpoint string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return fmt.Errorf("digest: building probe request for %s: %w", endpoint, err)
	}
	t.rewriteURL(req)

	resp, err := t.base().RoundTrip(req)
	if err != nil {
		return fmt.Errorf("digest: probing %s: %w", req.URL, err)
	}
	defer drainAndClose(resp)

	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("digest: no digest auth at %s: %s", req.URL, resp.Status)
	}
	return t.setChallenge(resp.Header.Get("WWW-Authenticate"))
}

// Reset discards the cached challenge.
func (t *Transport) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.challenge = nil
}

// prepare clones the request with the rewritten URL, a replayable body, and an
// Authorization header when a challenge is known.
func (t *Transport) prepare(req *http.Request, body []byte) *http.Request {
	out := req.Clone(req.Context())
	t.rewriteURL(out)

	if body != nil {
		out.Body = io.NopCloser(bytes.NewReader(body))
		out.ContentLength = int64(len(body))
		out.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}

	if auth := t.authorization(out); auth != "" {
		out.Header.Set("Authorization", auth)
	}
	return out
}

// rewriteURL applies the port and path overrides.
func (t *Transport) rewriteURL(req *http.Request) {
	if t.Port != 0 {
		req.URL.Host = net.JoinHostPort(req.URL.Hostname(), strconv.FormatUint(uint64(t.Port), 10))
		req.Host = req.URL.Host
	}
	if t.Path != "" {
		req.URL.Path = t.Path
	}
}

// authorization returns the Authorization header value for a request, or ""
// when no challenge has been seen yet.
func (t *Transport) authorization(req *http.Request) string {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.challenge == nil {
		return ""
	}
	auth, err := t.challenge.authorize(req.Method, req.URL.RequestURI())
	if err != nil {
		return ""
	}
	return auth
}

// setChallenge parses a WWW-Authenticate header and caches it.
func (t *Transport) setChallenge(header string) error {
	c := &challenge{Username: t.Username, Password: t.Password}
	if err := c.parseChallenge(header); err != nil {
		return fmt.Errorf("digest: parsing challenge: %w", err)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.challenge = c
	return nil
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// drainBody reads a request body so it can be replayed on the retry after a
// 401. WS-Man request bodies are small SOAP envelopes, so buffering them is
// cheap and avoids depending on the caller having set GetBody.
func drainBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("digest: reading request body: %w", err)
	}
	if err := req.Body.Close(); err != nil {
		return nil, fmt.Errorf("digest: closing request body: %w", err)
	}
	return body, nil
}

// drainAndClose consumes and closes a response so its connection can be
// reused for the retry rather than abandoned.
func drainAndClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}
