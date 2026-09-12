package internal

import (
	"context"
	"crypto/md5" //nolint:gosec // AMT digest authentication is defined in terms of MD5
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// AMT password length bounds, enforced by firmware.
const (
	MinPasswordLength = 8
	MaxPasswordLength = 32
)

// Character classes for generated passwords.
//
// The special set is deliberately narrower than what AMT documents as legal.
// Several characters that appear in Intel's list -- notably ':', ',' and '"'
// -- are rejected by some firmware revisions or corrupt the digest realm
// string, and a password AMT refuses is indistinguishable from a wrong
// password once it has been written. Staying inside a conservative set costs
// negligible entropy and removes a whole class of unexplainable failures.
const (
	lowerChars   = "abcdefghijkmnopqrstuvwxyz"
	upperChars   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	digitChars   = "23456789"
	specialChars = "!@#$%^&*()-_+=?"
)

var allChars = lowerChars + upperChars + digitChars + specialChars

// ErrPasswordPolicy is returned when a password violates AMT's complexity
// rules.
var ErrPasswordPolicy = errors.New("iamt: password does not satisfy AMT complexity rules")

// GeneratePassword returns a random password satisfying AMT's complexity
// rules: one lower, one upper, one digit and one special character.
func GeneratePassword(length int) (string, error) {
	if length < MinPasswordLength || length > MaxPasswordLength {
		return "", fmt.Errorf("%w: length must be %d-%d, got %d",
			ErrPasswordPolicy, MinPasswordLength, MaxPasswordLength, length)
	}

	// Seed one character from each required class, then fill the remainder
	// from the full alphabet and shuffle so the required characters are not
	// always in the first four positions.
	out := make([]byte, 0, length)
	for _, class := range []string{lowerChars, upperChars, digitChars, specialChars} {
		c, err := randomChar(class)
		if err != nil {
			return "", err
		}
		out = append(out, c)
	}
	for len(out) < length {
		c, err := randomChar(allChars)
		if err != nil {
			return "", err
		}
		out = append(out, c)
	}
	if err := shuffle(out); err != nil {
		return "", err
	}

	pw := string(out)
	if err := ValidatePassword(pw); err != nil {
		// Unreachable by construction; treated as a hard error rather than
		// returning a password the device would reject.
		return "", err
	}
	return pw, nil
}

// ValidatePassword reports whether a password satisfies AMT's rules.
func ValidatePassword(pw string) error {
	if len(pw) < MinPasswordLength || len(pw) > MaxPasswordLength {
		return fmt.Errorf("%w: length must be %d-%d, got %d",
			ErrPasswordPolicy, MinPasswordLength, MaxPasswordLength, len(pw))
	}

	var hasLower, hasUpper, hasDigit, hasSpecial bool
	for _, r := range pw {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case strings.ContainsRune(specialChars, r):
			hasSpecial = true
		default:
			return fmt.Errorf("%w: character %q is not permitted", ErrPasswordPolicy, r)
		}
	}

	var missing []string
	if !hasLower {
		missing = append(missing, "lowercase")
	}
	if !hasUpper {
		missing = append(missing, "uppercase")
	}
	if !hasDigit {
		missing = append(missing, "digit")
	}
	if !hasSpecial {
		missing = append(missing, "special")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: missing %s", ErrPasswordPolicy, strings.Join(missing, ", "))
	}
	return nil
}

// DigestPassword returns the MD5 digest AMT expects when setting a password:
// MD5(username:realm:password), hex encoded.
//
// The realm is the full DigestRealm string from AMT_GeneralSettings, including
// its "Digest:" prefix.
func DigestPassword(username, realm, password string) string {
	sum := md5.Sum([]byte(username + ":" + realm + ":" + password)) //nolint:gosec // required by AMT
	return hex.EncodeToString(sum[:])
}

// SetAdminPassword changes the admin account password.
//
// The caller must have the device's DigestRealm, which comes from Facts. AMT
// takes the digest rather than the plaintext, so realm and username must match
// exactly what the device reports or the new password will be unusable.
//
// This operation is not reversible and has no confirmation step: the moment it
// succeeds the old password stops working. A caller that cannot verify the new
// password afterwards has no way to tell whether the write landed, which is
// why callers should retain the previous password and try both.
func (c *Client) SetAdminPassword(_ context.Context, username, realm, newPassword string) error {
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	if realm == "" {
		return errors.New("iamt: digest realm is required to set a password")
	}

	digest := DigestPassword(username, realm, newPassword)
	resp, err := c.Msg.AMT.AuthorizationService.SetAdminAclEntryEx(username, digest)
	if err != nil {
		return fmt.Errorf("iamt: setting admin password: %w", err)
	}
	if rv := resp.Body.SetAdminResponse.ReturnValue; rv != 0 {
		return fmt.Errorf("iamt: setting admin password rejected with return value %d", rv)
	}
	return nil
}

func randomChar(alphabet string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
	if err != nil {
		return 0, fmt.Errorf("iamt: generating password: %w", err)
	}
	return alphabet[n.Int64()], nil
}

// shuffle performs a Fisher-Yates shuffle using crypto/rand.
func shuffle(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return fmt.Errorf("iamt: generating password: %w", err)
		}
		b[i], b[j.Int64()] = b[j.Int64()], b[i]
	}
	return nil
}
