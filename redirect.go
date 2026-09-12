// SPDX-License-Identifier: MPL-2.0

package iamt

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"strings"

	"github.com/jacobweinstock/iamt/internal/digest"
	"github.com/jacobweinstock/iamt/internal/ider"
)

// Redirection ports. AMT serves storage/serial redirection on these,
// distinct from the WS-Man ports (16992/16993).
const (
	// RedirectionPortPlaintext is the non-TLS redirection port.
	RedirectionPortPlaintext = 16994
	// RedirectionPortTLS is the TLS redirection port.
	RedirectionPortTLS = 16995
)

// RedirectSession is a running storage-redirection (IDE-R/USB-R) session that
// serves an image to the managed host as a bootable CD-ROM. It runs in the
// background until Close is called or the context passed to MountISO is
// cancelled.
type RedirectSession struct {
	inner *ider.Session
}

// MountISO enables AMT redirection, opens a redirection session, and serves
// the given CD image to the host, arming a one-shot boot from it on the next
// host reset. The image is read on demand for the life of the session, so the
// caller must keep it open until Close.
//
// The returned session does not itself reset the host; the caller issues a
// power action (PowerCycle/PowerOn) to boot the redirected image, then holds
// the session open until the OS has finished reading from it.
//
// image must be a valid ISO 9660 CD image whose length (size) is a multiple of
// 2048 bytes.
func (c *Client) MountISO(ctx context.Context, image io.ReaderAt, size int64) (*RedirectSession, error) {
	if err := c.conn.EnableRedirection(ctx); err != nil {
		return nil, err
	}

	useTLS := strings.EqualFold(c.Scheme, "https")
	port := RedirectionPortPlaintext
	var tlsCfg *tls.Config
	if useTLS {
		port = RedirectionPortTLS
		tlsCfg = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // AMT is self-signed; trust comes from the pin
			MinVersion:         tls.VersionTLS10,
		}
		if c.PinnedCert != "" {
			tlsCfg.VerifyPeerCertificate = digest.PinnedCertVerifier(c.PinnedCert)
		}
	}

	sess, err := ider.Start(ctx, ider.Config{
		Host:        c.Host,
		Port:        port,
		TLS:         tlsCfg,
		User:        c.User,
		Pass:        c.Pass,
		Image:       image,
		ImageSize:   size,
		Logger:      c.Logger,
		DialTimeout: c.timeout(),
	})
	if err != nil {
		return nil, fmt.Errorf("iamt: mounting ISO over redirection: %w", err)
	}

	// Select the redirected CD as the boot source and let AMT disable Secure
	// Boot for it, so an unsigned image boots. Do this after the data session
	// is up so the disk is ready the moment the host boots.
	if err := c.conn.ArmIDERBoot(ctx, false); err != nil {
		_ = sess.Close()
		return nil, err
	}

	return &RedirectSession{inner: sess}, nil
}

// MountURL is like MountISO but streams the image directly from a URL using
// HTTP Range requests, so nothing is written to local disk. The URL may
// redirect once to presigned object storage (as the Talos Image Factory does);
// the resolved location is fetched from with range requests and hot sectors are
// cached in memory. The server must support range requests (HTTP 206).
func (c *Client) MountURL(ctx context.Context, url string) (*RedirectSession, error) {
	reader, err := newHTTPRangeReaderAt(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	if reader.Size()%isoSectorSize != 0 {
		return nil, fmt.Errorf("iamt: image %s size %d is not a multiple of %d", url, reader.Size(), isoSectorSize)
	}
	return c.MountISO(ctx, reader, reader.Size())
}

// Close ends the redirection session.
func (r *RedirectSession) Close() error { return r.inner.Close() }

// Done is closed when the session ends (by Close, context cancellation, or a
// protocol error).
func (r *RedirectSession) Done() <-chan struct{} { return r.inner.Done() }

// Err reports why the session ended, or nil if it was closed cleanly.
func (r *RedirectSession) Err() error { return r.inner.Err() }
