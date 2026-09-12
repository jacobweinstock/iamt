package digest

import "testing"

func TestParseChallenge(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantRealm string
		wantNonce string
		wantQop   string
		wantAlg   string
		wantErr   bool
	}{
		{
			name:      "standard comma-separated header",
			input:     `Digest realm="test@example.com", nonce="abc123", qop="auth", algorithm="MD5"`,
			wantRealm: "test@example.com",
			wantNonce: "abc123",
			wantQop:   "auth",
			wantAlg:   "MD5",
		},
		{
			name:      "space-separated fields (Intel NUC style)",
			input:     `Digest realm="Digest:12345678"  nonce="abcdefghij" qop="auth"`,
			wantRealm: "Digest:12345678",
			wantNonce: "abcdefghij",
			wantQop:   "auth",
			wantAlg:   "MD5",
		},
		{
			name:      "malformed qop with duplicates and extra whitespace",
			input:     `Digest realm="test" nonce="xyz" qop="auth auth-int  auth"`,
			wantRealm: "test",
			wantNonce: "xyz",
			wantQop:   "auth",
			wantAlg:   "MD5",
		},
		{
			name:      "qop with only auth-int returns empty",
			input:     `Digest realm="test" nonce="xyz" qop="auth-int"`,
			wantRealm: "test",
			wantNonce: "xyz",
			wantQop:   "",
			wantAlg:   "MD5",
		},
		{
			name:      "mixed comma and space separators",
			input:     `Digest realm="mixed", nonce="123"  qop="auth" algorithm="MD5"`,
			wantRealm: "mixed",
			wantNonce: "123",
			wantQop:   "auth",
			wantAlg:   "MD5",
		},
		{
			name:    "missing Digest prefix",
			input:   `Basic realm="test"`,
			wantErr: true,
		},
		{
			name:      "no qop specified defaults to empty",
			input:     `Digest realm="test", nonce="abc"`,
			wantRealm: "test",
			wantNonce: "abc",
			wantQop:   "",
			wantAlg:   "MD5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &challenge{}
			err := c.parseChallenge(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if c.Realm != tt.wantRealm {
				t.Errorf("Realm = %q, want %q", c.Realm, tt.wantRealm)
			}
			if c.Nonce != tt.wantNonce {
				t.Errorf("Nonce = %q, want %q", c.Nonce, tt.wantNonce)
			}
			if c.Qop != tt.wantQop {
				t.Errorf("Qop = %q, want %q", c.Qop, tt.wantQop)
			}
			if c.Algorithm != tt.wantAlg {
				t.Errorf("Algorithm = %q, want %q", c.Algorithm, tt.wantAlg)
			}
		})
	}
}

func TestNormalizeQop(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "standard auth",
			input: "auth",
			want:  "auth",
		},
		{
			name:  "auth-int only returns empty",
			input: "auth-int",
			want:  "",
		},
		{
			name:  "space-separated with auth",
			input: "auth auth-int",
			want:  "auth",
		},
		{
			name:  "malformed with duplicates and extra whitespace",
			input: "auth auth-int  auth",
			want:  "auth",
		},
		{
			name:  "comma-separated with auth",
			input: "auth,auth-int",
			want:  "auth",
		},
		{
			name:  "auth-int first then auth",
			input: "auth-int auth",
			want:  "auth",
		},
		{
			name:  "empty string returns empty",
			input: "",
			want:  "",
		},
		{
			name:  "unknown qop returns empty",
			input: "unknown",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeQop(tt.input)
			if got != tt.want {
				t.Errorf("normalizeQop(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
