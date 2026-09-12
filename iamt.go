// Package iamt manages Intel AMT devices over WS-Management.
//
// WS-Man messages are built and parsed by
// github.com/device-management-toolkit/go-wsman-messages, Intel's own message
// library, which covers the full AMT, CIM and IPS class surface. Transport and
// authentication are this package's own: see internal/digest for why.
//
// This file is the public surface. Everything behind it lives in internal and
// is free to change.
package iamt

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman"
	wsmanclient "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/client"
	"github.com/go-logr/logr"
	"github.com/jacobweinstock/iamt/internal"
	"github.com/jacobweinstock/iamt/internal/digest"
)

// Default AMT WS-Man ports.
const (
	// PortPlaintext is the plaintext WS-Man port.
	PortPlaintext uint32 = 16992
	// PortTLS is the TLS WS-Man port.
	PortTLS uint32 = 16993
)

// DefaultTimeout bounds each operation. AMT firmware is slow to wake, so this
// is deliberately generous.
const DefaultTimeout = 30 * time.Second

// Types returned by this package. They are aliases so the implementation can
// stay in internal while callers can still name what they receive.
type (
	// Status is the observed power state of a device.
	Status = internal.Status
	// PowerState is a CIM power state value.
	PowerState = internal.PowerState
	// Facts is everything about a device that is not hardware inventory.
	Facts = internal.Facts
	// Firmware holds AMT firmware versions.
	Firmware = internal.Firmware
	// BootCapabilities is what a device can be told to boot.
	BootCapabilities = internal.BootCapabilities
	// Redirection is the state of AMT's redirection service.
	Redirection = internal.Redirection
	// Inventory is a device's hardware inventory.
	Inventory = internal.Inventory
	// Baseboard is the system board.
	Baseboard = internal.Baseboard
	// BIOS is the system firmware.
	BIOS = internal.BIOS
	// CPU is one processor package.
	CPU = internal.CPU
	// MemoryModule is one installed DIMM.
	MemoryModule = internal.MemoryModule
	// NIC is one host network interface.
	NIC = internal.NIC
	// Drive is one storage device.
	Drive = internal.Drive
	// BootTarget names a boot device.
	BootTarget = internal.BootTarget
)

// Power states, using the canonical DMTF valuemap.
const (
	PowerUnknown              = internal.PowerUnknown
	PowerOther                = internal.PowerOther
	PowerStateOn              = internal.PowerStateOn
	PowerSleepLight           = internal.PowerSleepLight
	PowerSleepDeep            = internal.PowerSleepDeep
	PowerCycleOffSoft         = internal.PowerCycleOffSoft
	PowerOffHard              = internal.PowerOffHard
	PowerHibernateOffSoft     = internal.PowerHibernateOffSoft
	PowerOffSoft              = internal.PowerOffSoft
	PowerCycleOffHard         = internal.PowerCycleOffHard
	PowerMasterBusReset       = internal.PowerMasterBusReset
	PowerDiagnosticInterrupt  = internal.PowerDiagnosticInterrupt
	PowerOffSoftGraceful      = internal.PowerOffSoftGraceful
	PowerOffHardGraceful      = internal.PowerOffHardGraceful
	PowerMasterBusResetGrace  = internal.PowerMasterBusResetGrace
	PowerCycleOffSoftGraceful = internal.PowerCycleOffSoftGraceful
	PowerCycleOffHardGraceful = internal.PowerCycleOffHardGraceful
)

// Boot targets, named with Redfish vocabulary.
const (
	BootPxe       = internal.BootPxe
	BootHdd       = internal.BootHdd
	BootCd        = internal.BootCd
	BootUefiHTTP  = internal.BootUefiHTTP
	BootBiosSetup = internal.BootBiosSetup
)

// Control modes reported by IPS_HostBasedSetupService.
const (
	ControlModeNotProvisioned = internal.ControlModeNotProvisioned
	ControlModeClient         = internal.ControlModeClient
	ControlModeAdmin          = internal.ControlModeAdmin
)

// Provisioning states reported by AMT_SetupAndConfigurationService.
const (
	ProvisioningPre  = internal.ProvisioningPre
	ProvisioningIn   = internal.ProvisioningIn
	ProvisioningPost = internal.ProvisioningPost
)

// Password length bounds, enforced by AMT firmware.
const (
	MinPasswordLength = internal.MinPasswordLength
	MaxPasswordLength = internal.MaxPasswordLength
)

// Errors callers may want to match.
var (
	// ErrPasswordPolicy is returned when a password violates AMT's rules.
	ErrPasswordPolicy = internal.ErrPasswordPolicy
	// ErrUnsupportedBootTarget is returned for a target a device cannot boot.
	ErrUnsupportedBootTarget = internal.ErrUnsupportedBootTarget
	// ErrVirtualMediaUnsupported is returned when firmware does not report
	// UEFI HTTPS boot.
	ErrVirtualMediaUnsupported = internal.ErrVirtualMediaUnsupported
	// ErrCertificatePinning is returned when a device presents a certificate
	// that does not match the configured pin.
	ErrCertificatePinning = digest.ErrCertificatePinning
)

// Client used to perform actions on the machine.
type Client struct {
	Host   string
	Logger logr.Logger
	Pass   string
	Path   string
	Port   uint32
	Scheme string
	User   string

	// Timeout bounds each operation. Zero means DefaultTimeout.
	Timeout time.Duration

	// PinnedCert, when set, is the hex-encoded SHA-256 of the device's DER
	// leaf certificate. A device presenting anything else is refused.
	//
	// AMT ships a self-signed certificate that no chain can validate, so
	// pinning is what makes a TLS connection trustworthy rather than merely
	// encrypted.
	PinnedCert string

	conn internal.Client
}

// Option for setting optional Client values.
type Option func(*Client)

// WithScheme sets the URL scheme, "http" or "https".
func WithScheme(scheme string) Option {
	return func(c *Client) {
		c.Scheme = scheme
	}
}

// WithLogger sets the logger.
func WithLogger(logger logr.Logger) Option {
	return func(c *Client) {
		c.Logger = logger
	}
}

// WithPort sets the port used to reach the device.
func WithPort(port uint32) Option {
	return func(c *Client) {
		c.Port = port
	}
}

// WithPath sets the WS-Man request path.
func WithPath(path string) Option {
	return func(c *Client) {
		c.Path = path
	}
}

// WithTimeout bounds each operation.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		c.Timeout = timeout
	}
}

// WithPinnedCert pins the device's TLS certificate by its hex-encoded SHA-256
// fingerprint. See Client.PinnedCert.
func WithPinnedCert(fingerprint string) Option {
	return func(c *Client) {
		c.PinnedCert = fingerprint
	}
}

// NewClient creates an amt client to use.
func NewClient(host, user, passwd string, opts ...Option) *Client {
	defaultClient := &Client{
		Logger: logr.Discard(),
		Path:   "/wsman",
		Port:   PortPlaintext,
		Scheme: "http",
	}

	for _, opt := range opts {
		opt(defaultClient)
	}

	defaultClient.Host = host
	defaultClient.User = user
	defaultClient.Pass = passwd

	useTLS := strings.EqualFold(defaultClient.Scheme, "https")

	transport := &digest.Transport{
		Base:     baseTransport(useTLS, defaultClient.PinnedCert),
		Username: user,
		Password: passwd,
		Port:     defaultClient.Port,
		Path:     defaultClient.Path,
	}

	// UseDigest is false on purpose: authentication is handled by the
	// transport above, whose challenge parser copes with the malformed
	// WWW-Authenticate headers some Intel NUCs emit. go-wsman-messages' own
	// parser silently mis-reads them.
	defaultClient.conn = internal.Client{
		Log:       defaultClient.Logger,
		Transport: transport,
		Endpoint:  defaultClient.endpoint(),
		Msg: wsman.NewMessages(wsmanclient.Parameters{
			Target:            host,
			Username:          user,
			Password:          passwd,
			UseDigest:         false,
			UseTLS:            useTLS,
			SelfSignedAllowed: true,
			Transport:         transport,
			Timeout:           defaultClient.timeout(),
		}),
	}

	return defaultClient
}

func (c *Client) timeout() time.Duration {
	if c.Timeout <= 0 {
		return DefaultTimeout
	}
	return c.Timeout
}

// endpoint is the WS-Man URL for this client.
func (c *Client) endpoint() string {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	path := c.Path
	if path == "" {
		path = "/wsman"
	}
	return scheme + "://" + net.JoinHostPort(c.Host, strconv.FormatUint(uint64(c.Port), 10)) + path
}

// Open the client.
func (c *Client) Open(ctx context.Context) error { return c.conn.Open(ctx) }

// Close the client.
func (c *Client) Close(ctx context.Context) error { return c.conn.Close(ctx) }

// PowerOn will power on a given machine.
func (c *Client) PowerOn(ctx context.Context) error { return c.conn.PowerOn(ctx) }

// PowerOff will power off a given machine.
func (c *Client) PowerOff(ctx context.Context) error { return c.conn.PowerOff(ctx) }

// PowerCycle will power cycle a given machine.
func (c *Client) PowerCycle(ctx context.Context) error { return c.conn.PowerCycle(ctx) }

// IsPoweredOn checks current power state.
func (c *Client) IsPoweredOn(ctx context.Context) (bool, error) { return c.conn.IsPoweredOn(ctx) }

// Status reads the current power status.
func (c *Client) Status(ctx context.Context) (Status, error) { return c.conn.Status(ctx) }

// RequestPowerState asks the device for a specific transition.
func (c *Client) RequestPowerState(ctx context.Context, requested PowerState) error {
	return c.conn.RequestPowerState(ctx, requested)
}

// SetPXE makes sure the node will pxe boot next time.
func (c *Client) SetPXE(ctx context.Context) error { return c.conn.SetPXE(ctx) }

// SetBootOverride arms a one-shot boot override.
func (c *Client) SetBootOverride(ctx context.Context, target BootTarget) error {
	return c.conn.SetBootOverride(ctx, target)
}

// ClearBootOverride disarms any pending one-shot boot override.
func (c *Client) ClearBootOverride(ctx context.Context) error {
	return c.conn.ClearBootOverride(ctx)
}

// InsertVirtualMedia arms a one-shot boot from an HTTPS-hosted image.
func (c *Client) InsertVirtualMedia(ctx context.Context, imageURL string, enforceSecureBoot bool) error {
	return c.conn.InsertVirtualMedia(ctx, imageURL, enforceSecureBoot)
}

// EjectVirtualMedia clears a pending media boot.
func (c *Client) EjectVirtualMedia(ctx context.Context) error {
	return c.conn.EjectVirtualMedia(ctx)
}

// Facts reads the device's identity, provisioning state and capabilities.
func (c *Client) Facts(ctx context.Context) (*Facts, error) { return c.conn.Facts(ctx) }

// Inventory reads the device's hardware inventory.
func (c *Client) Inventory(ctx context.Context) (*Inventory, error) { return c.conn.Inventory(ctx) }

// SetAdminPassword changes the admin account password.
func (c *Client) SetAdminPassword(ctx context.Context, username, realm, newPassword string) error {
	return c.conn.SetAdminPassword(ctx, username, realm, newPassword)
}

// GeneratePassword returns a random password satisfying AMT's complexity
// rules.
func GeneratePassword(length int) (string, error) { return internal.GeneratePassword(length) }

// ValidatePassword reports whether a password satisfies AMT's rules.
func ValidatePassword(pw string) error { return internal.ValidatePassword(pw) }

// DigestPassword returns the MD5 digest AMT expects when setting a password:
// MD5(username:realm:password), hex encoded.
func DigestPassword(username, realm, password string) string {
	return internal.DigestPassword(username, realm, password)
}

// NormalizeMAC renders a MAC address as lower-case colon-separated octets.
func NormalizeMAC(s string) string { return internal.NormalizeMAC(s) }

// Fingerprint dials the device and returns the hex SHA-256 of its leaf
// certificate, without authenticating.
//
// It is how a fingerprint is learned on first contact so it can be pinned for
// every subsequent connection.
func (c *Client) Fingerprint(ctx context.Context) (string, error) {
	if !strings.EqualFold(c.Scheme, "https") {
		return "", fmt.Errorf("iamt: a plaintext endpoint presents no certificate")
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: c.timeout()},
		Config:    &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // reading the cert is the point
	}
	addr := net.JoinHostPort(c.Host, strconv.FormatUint(uint64(c.Port), 10))

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("iamt: dialing %s: %w", addr, err)
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return "", fmt.Errorf("iamt: dialer did not return a TLS connection")
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("iamt: device presented no certificate")
	}
	return digest.Fingerprint(certs[0].Raw), nil
}

// baseTransport builds the underlying HTTP transport.
//
// Supplying a transport to go-wsman-messages bypasses the TLS configuration it
// would otherwise build, so the TLS settings have to be established here.
func baseTransport(useTLS bool, pinnedCert string) http.RoundTripper {
	if !useTLS {
		return &http.Transport{
			MaxIdleConns:    2,
			IdleConnTimeout: 90 * time.Second,
		}
	}

	cfg := &tls.Config{
		// AMT's factory certificate is self-signed, so chain verification can
		// never pass. Trust comes from the pin below when one is configured.
		InsecureSkipVerify: true, //nolint:gosec // see PinnedCert
	}
	if pinnedCert != "" {
		cfg.VerifyPeerCertificate = digest.PinnedCertVerifier(pinnedCert)
	}

	return &http.Transport{
		MaxIdleConns:    2,
		IdleConnTimeout: 90 * time.Second,
		TLSClientConfig: cfg,
	}
}
