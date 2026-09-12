// SPDX-License-Identifier: Apache-2.0

// Package ider implements the Intel AMT storage-redirection data plane
// (IDE-R on older firmware, USB-R on AMT 11 and later; the management-side
// wire protocol is identical). It opens a redirection session to TCP
// 16994/16995, authenticates with the redirection digest handshake, then
// emulates an ATAPI CD-ROM whose sectors are served from a local image, so
// the managed host can boot from that image over the AMT channel with no
// dependency on the host firmware's DHCP, DNS, or TLS trust.
//
// The protocol is a direct port of MeshCentral's amt-redir-mesh.js and
// amt-ider-module.js (Intel Corporation, Apache-2.0), which are the de facto
// reference for AMT redirection.
package ider

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

// authURI is the realm URI the redirection digest is computed against.
const authURI = "/RedirectionService"

// Config configures a redirection Session.
type Config struct {
	// Host is the AMT host (no port).
	Host string
	// Port is the redirection port: 16994 plaintext, 16995 TLS.
	Port int
	// TLS, when non-nil, wraps the connection (AMT presents a self-signed
	// certificate, so this is typically InsecureSkipVerify with a pin).
	TLS *tls.Config
	// User and Pass authenticate the redirection session.
	User string
	Pass string
	// Image is the CD image served to the host, read on demand.
	Image io.ReaderAt
	// ImageSize is the image length in bytes; must be a multiple of 2048.
	ImageSize int64
	// Logger is optional.
	Logger logr.Logger
	// DialTimeout bounds the initial TCP/TLS connect. Zero means 30s.
	DialTimeout time.Duration
}

// Session is a running redirection session. Create with Start; stop with Close.
type Session struct {
	cfg     Config
	log     logr.Logger
	conn    net.Conn
	writeMu sync.Mutex

	// engine state (single reader goroutine, so no lock needed there)
	authed     bool
	authAcc    []byte
	iderAcc    []byte
	outSeq     uint32
	inSeq      uint32
	readBfr    int
	cdromReady bool

	debug     bool
	closeOnce sync.Once
	done      chan struct{}
	errMu     sync.Mutex
	err       error
}

// blockSize is the CD sector size the emulated drive reports.
const blockSize = 2048

// Start dials the redirection port, performs the handshake, arms the IDER
// session for boot-on-next-reset, and serves the image in the background
// until ctx is cancelled or Close is called. It returns once the session is
// established and the host boot has been armed.
func Start(ctx context.Context, cfg Config) (*Session, error) {
	if cfg.Image == nil || cfg.ImageSize <= 0 {
		return nil, errors.New("ider: image is required")
	}
	if cfg.ImageSize%blockSize != 0 {
		return nil, fmt.Errorf("ider: image size %d is not a multiple of %d", cfg.ImageSize, blockSize)
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 30 * time.Second
	}
	s := &Session{cfg: cfg, log: cfg.Logger, done: make(chan struct{}), debug: os.Getenv("IAMT_IDER_DEBUG") != ""}

	dialer := &net.Dialer{Timeout: cfg.DialTimeout}
	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ider: dial %s: %w", addr, err)
	}
	if cfg.TLS != nil {
		tlsConn := tls.Client(rawConn, cfg.TLS)
		hsCtx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
		defer cancel()
		if err := tlsConn.HandshakeContext(hsCtx); err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("ider: tls handshake: %w", err)
		}
		s.conn = tlsConn
	} else {
		s.conn = rawConn
	}

	// Begin the redirection session: "IDER".
	if err := s.send([]byte{0x10, 0x00, 0x00, 0x00, 'I', 'D', 'E', 'R'}); err != nil {
		_ = s.conn.Close()
		return nil, fmt.Errorf("ider: start redirection: %w", err)
	}

	// Wait for the IDER session to become established (OPEN_SESSION reply
	// processed) or fail, so the caller knows boot is armed before it
	// power-cycles the host.
	established := make(chan error, 1)
	go s.run(established)

	select {
	case <-ctx.Done():
		s.finish(ctx.Err())
		return nil, ctx.Err()
	case err := <-established:
		if err != nil {
			s.finish(err)
			return nil, err
		}
	}

	// Tie the session lifetime to ctx.
	go func() {
		<-ctx.Done()
		s.finish(ctx.Err())
	}()

	return s, nil
}

// Done is closed when the session ends. Err reports why.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err returns the terminating error, or nil if Close was called cleanly.
func (s *Session) Err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.err
}

// Close tears down the session.
func (s *Session) Close() error {
	s.finish(nil)
	return nil
}

func (s *Session) finish(err error) {
	s.closeOnce.Do(func() {
		s.dbg("session closing: err=%v", err)
		s.errMu.Lock()
		s.err = err
		s.errMu.Unlock()
		if s.conn != nil {
			_ = s.conn.Close()
		}
		close(s.done)
	})
}

// run is the read loop. It signals established exactly once (nil on the
// OPEN_SESSION reply, or an error if the handshake fails first).
func (s *Session) run(established chan<- error) {
	signalled := false
	signal := func(err error) {
		if !signalled {
			signalled = true
			established <- err
		}
	}
	defer func() {
		signal(errors.New("ider: session closed before it was established"))
	}()

	buf := make([]byte, 16384)
	for {
		n, err := s.conn.Read(buf)
		if n > 0 {
			estd, perr := s.onData(buf[:n])
			if perr != nil {
				signal(perr)
				s.finish(perr)
				return
			}
			if estd {
				signal(nil)
			}
		}
		if err != nil {
			if s.isClosed() {
				return
			}
			if err != io.EOF {
				s.finish(fmt.Errorf("ider: read: %w", err))
			} else {
				s.finish(nil)
			}
			return
		}
	}
}

func (s *Session) isClosed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *Session) dbg(format string, args ...any) {
	if s.debug {
		fmt.Fprintf(os.Stderr, "[ider] "+format+"\n", args...)
	}
}

func (s *Session) send(b []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.conn.Write(b)
	return err
}

// onData routes bytes to the auth handshake or the IDER engine. It returns
// true once the IDER OPEN_SESSION reply has been processed (boot armed).
func (s *Session) onData(data []byte) (established bool, err error) {
	if !s.authed {
		s.authAcc = append(s.authAcc, data...)
		leftover, err := s.processAuth()
		if err != nil {
			return false, err
		}
		if !s.authed {
			return false, nil
		}
		// Auth just succeeded; OPEN_SESSION has been sent. Feed any leftover.
		if len(leftover) > 0 {
			return s.feedIDER(leftover)
		}
		return false, nil
	}
	return s.feedIDER(data)
}
