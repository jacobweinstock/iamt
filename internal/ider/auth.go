// SPDX-License-Identifier: Apache-2.0

package ider

import (
	"crypto/md5" //nolint:gosec // AMT redirection auth mandates MD5 digest
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// processAuth consumes as many complete redirection-auth messages as are
// buffered. On successful authentication it sends OPEN_SESSION, sets
// s.authed, and returns any bytes buffered past the success message (which
// belong to the IDER stream). It returns nil, nil when it needs more bytes.
func (s *Session) processAuth() (leftover []byte, err error) {
	for len(s.authAcc) >= 1 {
		var cmdsize int
		switch s.authAcc[0] {
		case 0x11: // StartRedirectionSessionReply
			if len(s.authAcc) < 4 {
				return nil, nil
			}
			if status := s.authAcc[1]; status != 0 {
				return nil, fmt.Errorf("ider: redirection session refused, status %d", status)
			}
			if len(s.authAcc) < 13 {
				return nil, nil
			}
			oemLen := int(s.authAcc[12])
			if len(s.authAcc) < 13+oemLen {
				return nil, nil
			}
			// Query which authentication types the device supports.
			if err := s.send([]byte{0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
				return nil, err
			}
			cmdsize = 13 + oemLen

		case 0x14: // AuthenticateSessionReply
			if len(s.authAcc) < 9 {
				return nil, nil
			}
			authDataLen := int(binary.LittleEndian.Uint32(s.authAcc[5:9]))
			if len(s.authAcc) < 9+authDataLen {
				return nil, nil
			}
			status := s.authAcc[1]
			authType := s.authAcc[4]
			authData := s.authAcc[9 : 9+authDataLen]
			cmdsize = 9 + authDataLen

			switch {
			case authType == 0: // reply to the support query
				if !containsByte(authData, 4) {
					return nil, errors.New("ider: device does not offer digest (type 4) redirection auth")
				}
				if err := s.sendDigestRequest(); err != nil {
					return nil, err
				}
			case (authType == 3 || authType == 4) && status == 1: // challenge
				if err := s.sendDigestResponse(authType, authData); err != nil {
					return nil, err
				}
			case status == 0: // authenticated
				s.authed = true
				if err := s.startIDER(); err != nil {
					return nil, err
				}
				leftover = append([]byte(nil), s.authAcc[cmdsize:]...)
				s.authAcc = nil
				return leftover, nil
			default:
				return nil, fmt.Errorf("ider: redirection auth failed, type %d status %d", authType, status)
			}

		default:
			return nil, fmt.Errorf("ider: unexpected redirection command 0x%02x during auth", s.authAcc[0])
		}

		s.authAcc = s.authAcc[cmdsize:]
	}
	return nil, nil
}

// sendDigestRequest asks the device to open digest auth, which prompts it to
// return a realm/nonce challenge.
func (s *Session) sendDigestRequest() error {
	user := []byte(s.cfg.User)
	uri := []byte(authURI)
	// [userlen] user [0 0] [urilen] uri [0 0 0 0]
	payload := make([]byte, 0, len(user)+len(uri)+8)
	payload = append(payload, byte(len(user)))
	payload = append(payload, user...)
	payload = append(payload, 0x00, 0x00)
	payload = append(payload, byte(len(uri)))
	payload = append(payload, uri...)
	payload = append(payload, 0x00, 0x00, 0x00, 0x00)

	msg := []byte{0x13, 0x00, 0x00, 0x00, 0x04}
	msg = appendLE32(msg, uint32(len(payload)))
	msg = append(msg, payload...)
	return s.send(msg)
}

// sendDigestResponse answers a realm/nonce (and, for type 4, qop) challenge.
func (s *Session) sendDigestResponse(authType byte, authData []byte) error {
	realm, rest, ok := lenPrefixed(authData)
	if !ok {
		return errors.New("ider: malformed auth challenge (realm)")
	}
	nonce, rest, ok := lenPrefixed(rest)
	if !ok {
		return errors.New("ider: malformed auth challenge (nonce)")
	}
	var qop []byte
	if authType == 4 {
		qop, _, ok = lenPrefixed(rest)
		if !ok {
			return errors.New("ider: malformed auth challenge (qop)")
		}
	}

	cnonce, err := randomHex(32)
	if err != nil {
		return err
	}
	const snc = "00000002"

	ha1 := md5hex(fmt.Sprintf("%s:%s:%s", s.cfg.User, realm, s.cfg.Pass))
	ha2 := md5hex("POST:" + authURI)
	var digest string
	if authType == 4 {
		digest = md5hex(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, nonce, snc, cnonce, qop, ha2))
	} else {
		digest = md5hex(fmt.Sprintf("%s:%s:%s", ha1, nonce, ha2))
	}

	user := []byte(s.cfg.User)
	uri := []byte(authURI)
	body := make([]byte, 0, 64)
	body = appendField(body, user)
	body = appendField(body, realm)
	body = appendField(body, nonce)
	body = appendField(body, uri)
	body = appendField(body, []byte(cnonce))
	body = appendField(body, []byte(snc))
	body = appendField(body, []byte(digest))
	if authType == 4 {
		body = appendField(body, qop)
	}

	msg := []byte{0x13, 0x00, 0x00, 0x00, authType}
	msg = appendLE32(msg, uint32(len(body)))
	msg = append(msg, body...)
	return s.send(msg)
}

// --- helpers ---

func containsByte(b []byte, v byte) bool {
	for _, x := range b {
		if x == v {
			return true
		}
	}
	return false
}

// lenPrefixed reads a single-byte-length-prefixed field.
func lenPrefixed(b []byte) (val, rest []byte, ok bool) {
	if len(b) < 1 {
		return nil, nil, false
	}
	n := int(b[0])
	if len(b) < 1+n {
		return nil, nil, false
	}
	return b[1 : 1+n], b[1+n:], true
}

// appendField appends a single-byte-length-prefixed field.
func appendField(dst, val []byte) []byte {
	dst = append(dst, byte(len(val)))
	return append(dst, val...)
}

func appendLE32(dst []byte, v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return append(dst, b[:]...)
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec // protocol-mandated
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) (string, error) {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("ider: cnonce: %w", err)
	}
	return hex.EncodeToString(b)[:n], nil
}
