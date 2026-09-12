package digest

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ErrCertificatePinning is returned when a device presents a certificate that
// does not match the configured pin.
var ErrCertificatePinning = errors.New("iamt: device certificate does not match the pinned fingerprint")

// Fingerprint returns the hex-encoded SHA-256 of a DER certificate, the form
// PinnedCertVerifier expects.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// PinnedCertVerifier returns a tls.Config.VerifyPeerCertificate callback that
// compares the peer's leaf certificate against a hex-encoded SHA-256
// fingerprint.
//
// Only the leaf is compared. AMT presents a self-signed certificate, so there
// is no chain to validate and the pin is the entire basis for trust.
func PinnedCertVerifier(pinned string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("%w: no certificate presented", ErrCertificatePinning)
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("%w: %w", ErrCertificatePinning, err)
		}
		if strings.EqualFold(Fingerprint(cert.Raw), pinned) {
			return nil
		}
		return ErrCertificatePinning
	}
}
