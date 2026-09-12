// SPDX-License-Identifier: MPL-2.0

package iamt_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/jacobweinstock/iamt"
)

// rangeServer serves body with Range support (http.ServeContent) and counts
// requests, so tests can assert the reader caches instead of refetching.
func rangeServer(t *testing.T, body []byte) (*httptest.Server, *int64) {
	t.Helper()
	var reqs int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&reqs, 1)
		http.ServeContent(w, r, "image.iso", timeZero, bytes.NewReader(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &reqs
}

func makeISO(sectors int) []byte {
	b := make([]byte, sectors*2048)
	for i := range b {
		b[i] = byte(i / 2048)
	}
	return b
}

func TestHTTPImageReadAt(t *testing.T) {
	iso := makeISO(4096) // 8 MiB
	srv, reqs := rangeServer(t, iso)

	img, err := iamt.NewHTTPImage(context.Background(), srv.URL, iamt.WithWindowSize(1<<20), iamt.WithMaxWindows(8))
	if err != nil {
		t.Fatalf("NewHTTPImage: %v", err)
	}
	if img.Size() != int64(len(iso)) {
		t.Fatalf("Size = %d, want %d", img.Size(), len(iso))
	}
	afterProbe := atomic.LoadInt64(reqs)

	// A read spanning a window boundary returns the exact bytes.
	off := int64(1<<20) - 2048
	buf := make([]byte, 4096)
	n, err := img.ReadAt(buf, off)
	if err != nil || n != len(buf) {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
	if !bytes.Equal(buf, iso[off:off+4096]) {
		t.Fatalf("ReadAt returned wrong bytes at %d", off)
	}

	// Re-reading sector 0 and sector 16 (both in the first window, now cached)
	// must not hit the network again.
	before := atomic.LoadInt64(reqs)
	for _, s := range []int64{0, 16, 0, 16} {
		if _, err := img.ReadAt(make([]byte, 2048), s*2048); err != nil {
			t.Fatalf("ReadAt sector %d: %v", s, err)
		}
	}
	if got := atomic.LoadInt64(reqs); got != before {
		t.Errorf("cached re-reads made %d extra requests, want 0", got-before)
	}

	// The boundary-spanning read touched two 1 MiB windows: at most two fetches
	// beyond size probing.
	if fetches := before - afterProbe; fetches > 2 {
		t.Errorf("boundary read made %d window fetches, want <=2", fetches)
	}
}

func TestHTTPImageReadAtEOF(t *testing.T) {
	iso := makeISO(2)
	srv, _ := rangeServer(t, iso)
	img, err := iamt.NewHTTPImage(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := img.ReadAt(buf, 2048) // one sector available past offset, one short
	if n != 2048 || err == nil {
		t.Fatalf("ReadAt past EOF = %d, %v; want 2048 and io.EOF", n, err)
	}
	if !bytes.Equal(buf[:2048], iso[2048:]) {
		t.Fatal("partial ReadAt returned wrong bytes")
	}
}

func TestHTTPImageRejectsNoRangeSupport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ignore Range entirely and send the whole body with 200.
		_, _ = w.Write(makeISO(8))
	}))
	t.Cleanup(srv.Close)
	if _, err := iamt.NewHTTPImage(context.Background(), srv.URL); err == nil {
		t.Fatal("expected error when the server does not honor Range requests")
	}
}
