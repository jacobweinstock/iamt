package iamt

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewClientDefaults(t *testing.T) {
	t.Parallel()

	c := NewClient("10.0.0.1", "admin", "hunter2")
	if c.Host != "10.0.0.1" || c.User != "admin" || c.Pass != "hunter2" {
		t.Errorf("identity not set: %+v", c)
	}
	if c.Port != PortPlaintext {
		t.Errorf("Port = %d, want %d", c.Port, PortPlaintext)
	}
	if c.Scheme != "http" {
		t.Errorf("Scheme = %q, want http", c.Scheme)
	}
	if c.Path != "/wsman" {
		t.Errorf("Path = %q, want /wsman", c.Path)
	}
	if c.timeout() != DefaultTimeout {
		t.Errorf("timeout() = %v, want %v", c.timeout(), DefaultTimeout)
	}
}

func TestNewClientOptions(t *testing.T) {
	t.Parallel()

	c := NewClient("10.0.0.1", "admin", "hunter2",
		WithScheme("https"),
		WithPort(PortTLS),
		WithPath("/other"),
		WithTimeout(5*time.Second),
		WithPinnedCert("abc"),
	)
	if c.Scheme != "https" || c.Port != PortTLS || c.Path != "/other" {
		t.Errorf("options not applied: %+v", c)
	}
	if c.timeout() != 5*time.Second {
		t.Errorf("timeout = %v", c.timeout())
	}
	if c.PinnedCert != "abc" {
		t.Errorf("PinnedCert = %q", c.PinnedCert)
	}
}

func TestEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []Option
		want string
	}{
		{"defaults", nil, "http://10.0.0.1:16992/wsman"},
		{"tls", []Option{WithScheme("https"), WithPort(PortTLS)}, "https://10.0.0.1:16993/wsman"},
		{"custom port", []Option{WithPort(8080)}, "http://10.0.0.1:8080/wsman"},
		{"custom path", []Option{WithPath("/amt")}, "http://10.0.0.1:16992/amt"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := NewClient("10.0.0.1", "u", "p", tc.opts...).endpoint(); got != tc.want {
				t.Errorf("endpoint() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The numbering is the canonical DMTF valuemap, not go-wsman-messages' labels.
// Getting this wrong sends a device the wrong transition.
func TestPowerStateNumbering(t *testing.T) {
	t.Parallel()

	want := map[PowerState]int{
		PowerStateOn:              2,
		PowerCycleOffSoft:         5,
		PowerOffHard:              6,
		PowerOffSoft:              8,
		PowerCycleOffHard:         9,
		PowerMasterBusReset:       10,
		PowerOffSoftGraceful:      12,
		PowerOffHardGraceful:      13,
		PowerMasterBusResetGrace:  14,
		PowerCycleOffSoftGraceful: 15,
		PowerCycleOffHardGraceful: 16,
	}
	for state, value := range want {
		if int(state) != value {
			t.Errorf("power state %d should be %d", state, value)
		}
	}
}

func TestStatusPoweredOn(t *testing.T) {
	t.Parallel()

	if !(Status{PowerState: PowerStateOn}).PoweredOn() {
		t.Error("PowerStateOn should report powered on")
	}
	for _, s := range []PowerState{PowerOffHard, PowerOffSoft, PowerSleepDeep, PowerUnknown} {
		if (Status{PowerState: s}).PoweredOn() {
			t.Errorf("state %d should not report powered on", s)
		}
	}
}

func TestGeneratePassword(t *testing.T) {
	t.Parallel()

	for _, length := range []int{8, 12, 24, 32} {
		for i := 0; i < 50; i++ {
			pw, err := GeneratePassword(length)
			if err != nil {
				t.Fatalf("GeneratePassword(%d): %v", length, err)
			}
			if len(pw) != length {
				t.Fatalf("GeneratePassword(%d) returned %d characters", length, len(pw))
			}
			if err := ValidatePassword(pw); err != nil {
				t.Fatalf("generated password %q fails validation: %v", pw, err)
			}
		}
	}

	for _, length := range []int{0, 7, 33, -1} {
		if _, err := GeneratePassword(length); !errors.Is(err, ErrPasswordPolicy) {
			t.Errorf("GeneratePassword(%d) error = %v, want ErrPasswordPolicy", length, err)
		}
	}
}

// A password AMT rejects is written before it is discovered to be invalid,
// which locks the caller out of the device.
func TestGeneratePasswordAvoidsRiskyCharacters(t *testing.T) {
	t.Parallel()

	const risky = `:,"'\` + "`"
	for i := 0; i < 500; i++ {
		pw, err := GeneratePassword(32)
		if err != nil {
			t.Fatalf("GeneratePassword: %v", err)
		}
		if strings.ContainsAny(pw, risky) {
			t.Fatalf("password %q contains a character outside the safe set", pw)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	t.Parallel()

	tests := map[string]bool{
		"Abcdef1!":                true,
		strings.Repeat("Ab1!", 8): true,
		"Abc1!":                   false,
		"abcdef1!":                false,
		"ABCDEF1!":                false,
		"Abcdefg!":                false,
		"Abcdefg1":                false,
		"Abcdef1:":                false,
		`Abcdef1"`:                false,
		"Abcdef1,":                false,
		strings.Repeat("Ab1!", 9): false,
	}

	for pw, valid := range tests {
		err := ValidatePassword(pw)
		if valid && err != nil {
			t.Errorf("ValidatePassword(%q) = %v, want nil", pw, err)
		}
		if !valid && err == nil {
			t.Errorf("ValidatePassword(%q) = nil, want an error", pw)
		}
	}
}

// The digest is what actually reaches the device, so a regression here sets a
// password nobody can use.
// Vector: printf 'admin:Digest:AB:hunter2' | md5sum
func TestDigestPassword(t *testing.T) {
	t.Parallel()

	const want = "172bdd4d350a6568d29e715bf3b00a02"
	if got := DigestPassword("admin", "Digest:AB", "hunter2"); got != want {
		t.Fatalf("DigestPassword = %q, want %q", got, want)
	}
	if DigestPassword("admin", "Digest:AB", "hunter3") == want {
		t.Error("DigestPassword ignores the password")
	}
	if DigestPassword("admin", "Digest:AC", "hunter2") == want {
		t.Error("DigestPassword ignores the realm")
	}
	if DigestPassword("root", "Digest:AB", "hunter2") == want {
		t.Error("DigestPassword ignores the username")
	}
}

// AMT reports MACs without separators, and reports all-zero addresses for
// unpopulated ports.
func TestNormalizeMAC(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, in, want string }{
		{"bare hex as AMT reports it", "88AEDD753DA0", "88:ae:dd:75:3d:a0"},
		{"already colon separated", "88:ae:dd:75:3d:a0", "88:ae:dd:75:3d:a0"},
		{"dash separated", "88-AE-DD-75-3D-A0", "88:ae:dd:75:3d:a0"},
		{"surrounding whitespace", " 88aedd753da0 ", "88:ae:dd:75:3d:a0"},
		{"empty", "", ""},
		{"not hex", "not-a-mac", ""},
		{"too short", "88AEDD753DA", ""},
		{"non hex digits", "ZZAEDD753DA0", ""},
		{"too long", "00000000000000", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeMAC(tc.in); got != tc.want {
				t.Errorf("NormalizeMAC(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFactsHelpers(t *testing.T) {
	t.Parallel()

	if !(Facts{ProvisioningState: ProvisioningPost}).Provisioned() {
		t.Error("PostProvisioning should report Provisioned")
	}
	for _, state := range []string{ProvisioningPre, ProvisioningIn, "Unknown(9)"} {
		if (Facts{ProvisioningState: state}).Provisioned() {
			t.Errorf("%q should not report Provisioned", state)
		}
	}

	if !(Facts{AllowedControlModes: []string{ControlModeAdmin}}).AllowsAdminControlMode() {
		t.Error("Admin in AllowedControlModes should report true")
	}
	if (Facts{AllowedControlModes: []string{ControlModeClient}}).AllowsAdminControlMode() {
		t.Error("Client-only should report false")
	}
	if (Facts{}).AllowsAdminControlMode() {
		t.Error("empty AllowedControlModes should report false")
	}
}

func TestInventoryMemoryBytes(t *testing.T) {
	t.Parallel()

	inv := Inventory{Memory: []MemoryModule{
		{CapacityBytes: 51539607552},
		{CapacityBytes: 51539607552},
	}}
	if got := inv.MemoryBytes(); got != 103079215104 {
		t.Errorf("MemoryBytes() = %d, want 103079215104", got)
	}
	if got := (Inventory{}).MemoryBytes(); got != 0 {
		t.Errorf("empty MemoryBytes() = %d, want 0", got)
	}
}
