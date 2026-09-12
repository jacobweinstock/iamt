package iamt_test

import (
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/jacobweinstock/iamt"
)

// Integration tests run only when AMT_HOST is set, so the default `go test`
// run stays hermetic:
//
//	AMT_HOST=10.0.0.160 AMT_USER=admin AMT_PASS='…' AMT_SCHEME=https AMT_PORT=16993 \
//	  go test . -run Integration -v
//
// These are read-only: nothing here changes power state or boot configuration.
func testClient(t *testing.T) *iamt.Client {
	t.Helper()

	host := os.Getenv("AMT_HOST")
	if host == "" {
		t.Skip("AMT_HOST not set; skipping live-device integration test")
	}

	opts := []iamt.Option{}
	if scheme := os.Getenv("AMT_SCHEME"); scheme != "" {
		opts = append(opts, iamt.WithScheme(scheme))
	}
	if p := os.Getenv("AMT_PORT"); p != "" {
		port, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			t.Fatalf("AMT_PORT: %v", err)
		}
		opts = append(opts, iamt.WithPort(uint32(port)))
	}
	if fp := os.Getenv("AMT_FINGERPRINT"); fp != "" {
		opts = append(opts, iamt.WithPinnedCert(fp))
	}

	return iamt.NewClient(host, os.Getenv("AMT_USER"), os.Getenv("AMT_PASS"), opts...)
}

// Open must still mean what it meant before the migration: the endpoint is an
// AMT WS-Man service that offers digest auth.
func TestIntegrationOpen(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := c.Open(ctx); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := c.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestIntegrationIsPoweredOn(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := c.Open(ctx); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close(ctx)

	on, err := c.IsPoweredOn(ctx)
	if err != nil {
		t.Fatalf("IsPoweredOn: %v", err)
	}
	t.Logf("powered on: %v", on)

	status, err := c.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	t.Logf("powerState=%d requested=%d available=%v",
		status.PowerState, status.RequestedPowerState, status.AvailableRequestedPowerStates)
	if status.PoweredOn() != on {
		t.Errorf("Status.PoweredOn()=%v disagrees with IsPoweredOn()=%v", status.PoweredOn(), on)
	}
}

func TestIntegrationFacts(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	f, err := c.Facts(ctx)
	if err != nil {
		t.Fatalf("Facts: %v", err)
	}
	t.Logf("platformGUID=%s provisioningState=%s controlMode=%s allowed=%v",
		f.PlatformGUID, f.ProvisioningState, f.ControlMode, f.AllowedControlModes)
	t.Logf("firmware amt=%s build=%s sku=%s", f.Firmware.AMT, f.Firmware.Build, f.Firmware.SKU)
	t.Logf("bootCapabilities=%+v", f.BootCapabilities)
	t.Logf("redirection=%+v digestRealm=%s", f.Redirection, f.DigestRealm)

	if f.ProvisioningState == "" {
		t.Error("provisioning state is empty")
	}
	if f.Provisioned() && f.DigestRealm == "" {
		t.Error("provisioned device reported no digest realm")
	}
}

func TestIntegrationInventory(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	inv, err := c.Inventory(ctx)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	t.Logf("manufacturer=%q model=%q serial=%q", inv.Manufacturer, inv.Model, inv.SerialNumber)
	t.Logf("baseboard=%+v", inv.Baseboard)
	t.Logf("bios=%+v", inv.BIOS)
	t.Logf("cpus=%d memory=%d bytes nics=%v drives=%v",
		len(inv.CPUs), inv.MemoryBytes(), inv.NICs, inv.Drives)

	if inv.Model == "" {
		t.Error("inventory reported no model")
	}
	if inv.SerialNumber == "" {
		t.Error("inventory reported no serial number")
	}
	for _, n := range inv.NICs {
		if n.MACAddress == "00:00:00:00:00:00" {
			t.Error("an all-zero MAC reached the inventory")
		}
	}
}

func TestIntegrationFingerprint(t *testing.T) {
	c := testClient(t)
	if os.Getenv("AMT_SCHEME") != "https" {
		t.Skip("AMT_SCHEME is not https; no certificate to read")
	}

	fp, err := c.Fingerprint(context.Background())
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if len(fp) != 64 {
		t.Fatalf("Fingerprint returned %d characters, want 64 hex", len(fp))
	}
	t.Logf("device certificate fingerprint: %s", fp)
}

// A wrong pin must fail closed, otherwise pinning is silently inert.
func TestIntegrationPinnedCertMismatchIsRefused(t *testing.T) {
	if os.Getenv("AMT_HOST") == "" {
		t.Skip("AMT_HOST not set; skipping live-device integration test")
	}
	if os.Getenv("AMT_SCHEME") != "https" {
		t.Skip("AMT_SCHEME is not https; pinning does not apply")
	}

	c := iamt.NewClient(os.Getenv("AMT_HOST"), os.Getenv("AMT_USER"), os.Getenv("AMT_PASS"),
		iamt.WithScheme("https"),
		iamt.WithPort(16993),
		iamt.WithPinnedCert("0000000000000000000000000000000000000000000000000000000000000000"),
	)

	if _, err := c.Facts(context.Background()); err == nil {
		t.Fatal("Facts succeeded against a mismatched certificate pin; pinning is not enforced")
	} else {
		t.Logf("pin correctly refused: %v", err)
	}
}
