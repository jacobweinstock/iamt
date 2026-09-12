package digest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// digestServer is a minimal digest-auth server whose WWW-Authenticate header
// format is caller-controlled, so the malformed Intel NUC shapes can be
// exercised end to end.
func digestServer(t *testing.T, challengeHeader string) (*httptest.Server, *int32) {
	t.Helper()

	var authed int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", challengeHeader)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		atomic.AddInt32(&authed, 1)
		// Echo back what the client sent so assertions can inspect it.
		w.Header().Set("X-Echo-Authorization", r.Header.Get("Authorization"))
		w.Header().Set("X-Echo-Path", r.URL.Path)
		w.Header().Set("X-Echo-Host", r.Host)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, &authed
}

// The whole reason this transport exists: a space-separated challenge, which
// go-wsman-messages' comma-splitting parser mis-reads, must authenticate.
func TestTransportHandlesIntelNUCChallenge(t *testing.T) {
	t.Parallel()

	headers := map[string]string{
		"standard comma-separated": `Digest realm="Digest:AB", nonce="abc123", qop="auth"`,
		"space-separated":          `Digest realm="Digest:AB"  nonce="abc123" qop="auth"`,
		"malformed qop":            `Digest realm="Digest:AB" nonce="abc123" qop="auth auth-int  auth"`,
		"mixed separators":         `Digest realm="Digest:AB", nonce="abc123"  qop="auth"`,
		"no qop":                   `Digest realm="Digest:AB", nonce="abc123"`,
	}

	for name, header := range headers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv, authed := digestServer(t, header)
			client := &http.Client{Transport: &Transport{Username: "admin", Password: "hunter2"}}

			resp, err := client.Get(srv.URL + "/wsman")
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200: the challenge was not handled", resp.StatusCode)
			}
			if *authed != 1 {
				t.Errorf("server saw %d authenticated requests, want 1", *authed)
			}

			auth := resp.Header.Get("X-Echo-Authorization")
			if !strings.HasPrefix(auth, "Digest ") {
				t.Fatalf("Authorization = %q, want a Digest header", auth)
			}
			// A mis-parsed challenge yields an empty nonce, which is the
			// silent-failure mode this transport exists to avoid.
			if !strings.Contains(auth, `nonce="abc123"`) {
				t.Errorf("Authorization did not carry the server nonce: %q", auth)
			}
			if !strings.Contains(auth, `realm="Digest:AB"`) {
				t.Errorf("Authorization did not carry the server realm: %q", auth)
			}
		})
	}
}

// The cached challenge should be reused so a steady stream of requests does
// not pay a 401 round trip each.
func TestTransportReusesChallenge(t *testing.T) {
	t.Parallel()

	var challenges int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			atomic.AddInt32(&challenges, 1)
			w.Header().Set("WWW-Authenticate", `Digest realm="Digest:AB", nonce="abc123", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{Transport: &Transport{Username: "admin", Password: "hunter2"}}
	for i := 0; i < 3; i++ {
		resp, err := client.Get(srv.URL + "/wsman")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
	}

	if challenges != 1 {
		t.Errorf("server issued %d challenges for 3 requests, want 1", challenges)
	}
}

// go-wsman-messages derives the port from TLS and hardcodes the path, so the
// transport has to override both or a device on a non-standard port is
// unreachable.
func TestTransportRewritesPortAndPath(t *testing.T) {
	t.Parallel()

	srv, _ := digestServer(t, `Digest realm="Digest:AB", nonce="abc123", qop="auth"`)
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parsing server URL: %v", err)
	}
	port, err := strconv.ParseUint(target.Port(), 10, 32)
	if err != nil {
		t.Fatalf("parsing port: %v", err)
	}

	tr := &Transport{Username: "admin", Password: "hunter2", Port: uint32(port), Path: "/custom"}
	client := &http.Client{Transport: tr}

	// Point at a port nothing is listening on; the transport must rewrite it
	// to the real one.
	resp, err := client.Get("http://" + target.Hostname() + ":1/wsman")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Echo-Path"); got != "/custom" {
		t.Errorf("server saw path %q, want /custom", got)
	}
	if got := resp.Header.Get("X-Echo-Host"); got != target.Host {
		t.Errorf("server saw Host %q, want %q", got, target.Host)
	}
}

// A POST body must survive the retry that follows the 401, otherwise every
// WS-Man request would reach the device with an empty envelope.
func TestTransportReplaysBodyAfterChallenge(t *testing.T) {
	t.Parallel()

	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Digest realm="Digest:AB", nonce="abc123", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{Transport: &Transport{Username: "admin", Password: "hunter2"}}
	resp, err := client.Post(srv.URL+"/wsman", "application/soap+xml", strings.NewReader("<Envelope/>"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if len(bodies) != 2 {
		t.Fatalf("server saw %d requests, want 2", len(bodies))
	}
	for i, b := range bodies {
		if b != "<Envelope/>" {
			t.Errorf("request %d body = %q, want the original envelope", i, b)
		}
	}
}

// A wrong password must surface as a 401 rather than looping.
func TestTransportDoesNotRetryForever(t *testing.T) {
	t.Parallel()

	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("WWW-Authenticate", `Digest realm="Digest:AB", nonce="abc123", qop="auth"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{Transport: &Transport{Username: "admin", Password: "wrong"}}
	resp, err := client.Get(srv.URL + "/wsman")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if requests > 2 {
		t.Errorf("server saw %d requests; the transport should retry at most once", requests)
	}
}

// Prime preserves the pre-migration Open() contract.
func TestPrime(t *testing.T) {
	t.Parallel()

	t.Run("digest endpoint primes", func(t *testing.T) {
		t.Parallel()
		srv, _ := digestServer(t, `Digest realm="Digest:AB"  nonce="abc123" qop="auth"`)
		tr := &Transport{Username: "admin", Password: "hunter2"}
		if err := tr.Prime(context.Background(), srv.URL+"/wsman"); err != nil {
			t.Fatalf("Prime: %v", err)
		}
		if tr.challenge == nil || tr.challenge.Nonce != "abc123" {
			t.Errorf("challenge was not cached: %+v", tr.challenge)
		}
	})

	t.Run("non-digest endpoint is an error", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "hello")
		}))
		t.Cleanup(srv.Close)

		tr := &Transport{Username: "admin", Password: "hunter2"}
		if err := tr.Prime(context.Background(), srv.URL); err == nil {
			t.Error("Prime succeeded against a non-digest endpoint")
		}
	})

	t.Run("reset clears the challenge", func(t *testing.T) {
		t.Parallel()
		srv, _ := digestServer(t, `Digest realm="Digest:AB", nonce="abc123", qop="auth"`)
		tr := &Transport{Username: "admin", Password: "hunter2"}
		if err := tr.Prime(context.Background(), srv.URL+"/wsman"); err != nil {
			t.Fatalf("Prime: %v", err)
		}
		tr.Reset()
		if tr.challenge != nil {
			t.Error("Reset did not clear the cached challenge")
		}
	})
}
