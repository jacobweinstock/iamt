package wsman

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The digest challenge is the first request Open makes, so it is enough to see whether
// the TLS handshake was accepted.
func digestServer() *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Digest realm="Digest:0000", nonce="abc", stale="false", qop="auth"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
}

func TestWithTLSConfig(t *testing.T) {
	srv := digestServer()
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/wsman")

	trusted := x509.NewCertPool()
	trusted.AddCert(srv.Certificate())

	tests := map[string]struct {
		opts    []Option
		wantErr string
	}{
		"default keeps the historical behaviour": {},
		"verified against the server's CA":       {opts: []Option{WithTLSConfig(&tls.Config{RootCAs: trusted})}},
		"refused with an unrelated CA": {
			opts:    []Option{WithTLSConfig(&tls.Config{RootCAs: x509.NewCertPool()})},
			wantErr: "certificate",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := NewClient(u, "admin", "pw", tt.opts...)
			err := c.Open(context.Background())
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("want an error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}
