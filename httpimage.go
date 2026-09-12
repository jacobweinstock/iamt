// SPDX-License-Identifier: MPL-2.0

package iamt

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HTTPImage is an io.ReaderAt over a remote ISO fetched with HTTP Range
// requests, so an image can be redirected to a host as a bootable CD without
// ever staging it on local disk. It is meant to be handed to Client.MountISO:
//
//	img, err := iamt.NewHTTPImage(ctx, "https://factory.talos.dev/image/<id>/<ver>/metal-amd64.iso")
//	sess, err := client.MountISO(ctx, img, img.Size())
//
// The IDER emulator issues small, repeated, non-sequential reads (boot catalog,
// volume descriptors at sector 16, kernel, initramfs). HTTPImage serves them
// from an aligned in-memory window cache so those reads collapse onto a few
// large Range fetches rather than one request per read. It is safe for
// concurrent use.
type HTTPImage struct {
	url        string
	client     *http.Client
	size       int64
	window     int64
	maxWindows int

	mu    sync.Mutex
	cache map[int64][]byte // window index -> bytes
	lru   []int64          // window indices, most-recently-used last
}

// HTTPImageOption configures an HTTPImage.
type HTTPImageOption func(*HTTPImage)

// WithHTTPClient sets the HTTP client. The default disables compression (a
// gzip transfer-encoding would defeat byte-range addressing) and keeps
// connections alive so sector reads reuse one TLS session.
func WithHTTPClient(c *http.Client) HTTPImageOption {
	return func(h *HTTPImage) { h.client = c }
}

// WithWindowSize sets the fetch/cache granularity in bytes (rounded up to a
// multiple of the 2048-byte CD sector). Larger windows mean fewer, bigger
// Range requests. Default 4 MiB.
func WithWindowSize(bytes int64) HTTPImageOption {
	return func(h *HTTPImage) { h.window = bytes }
}

// WithMaxWindows caps how many windows are cached before the least-recently-used
// is evicted. Memory is at most maxWindows*windowSize. Default 8.
func WithMaxWindows(n int) HTTPImageOption {
	return func(h *HTTPImage) { h.maxWindows = n }
}

const (
	defaultWindow     = 4 << 20
	defaultMaxWindows = 8
)

// NewHTTPImage probes the URL for byte-range support, learns the image size,
// and returns a ready reader. It fails if the server does not honor Range
// requests, since whole-file delivery would defeat the purpose.
func NewHTTPImage(ctx context.Context, url string, opts ...HTTPImageOption) (*HTTPImage, error) {
	h := &HTTPImage{
		url:        url,
		window:     defaultWindow,
		maxWindows: defaultMaxWindows,
		cache:      map[int64][]byte{},
	}
	for _, opt := range opts {
		opt(h)
	}
	if h.client == nil {
		h.client = &http.Client{
			Timeout: 5 * time.Minute,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  true,
			},
		}
	}
	h.window = roundUp(h.window, blockSize)
	if h.window <= 0 {
		h.window = defaultWindow
	}
	if h.maxWindows < 1 {
		h.maxWindows = 1
	}

	size, err := h.probe(ctx)
	if err != nil {
		return nil, err
	}
	h.size = size
	return h, nil
}

// blockSize is the CD sector size; the image size must be a multiple of it.
const blockSize = 2048

// Size returns the image length in bytes.
func (h *HTTPImage) Size() int64 { return h.size }

// probe issues a one-byte Range request. A compliant server answers 206 with a
// Content-Range whose total is the image size; a server that ignores Range and
// answers 200 is rejected.
func (h *HTTPImage) probe(ctx context.Context) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Range", "bytes=0-0")
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("iamt: probing %s: %w", h.url, err)
	}
	defer drainClose(resp.Body)

	if resp.StatusCode != http.StatusPartialContent {
		return 0, fmt.Errorf("iamt: %s does not support Range requests (status %d); a byte-addressable server is required", h.url, resp.StatusCode)
	}
	total, err := totalFromContentRange(resp.Header.Get("Content-Range"))
	if err != nil {
		return 0, err
	}
	if total <= 0 || total%blockSize != 0 {
		return 0, fmt.Errorf("iamt: image size %d is not a positive multiple of %d", total, blockSize)
	}
	return total, nil
}

// ReadAt implements io.ReaderAt, serving from cached windows and fetching any
// window it needs. A read past the end fills what it can and returns io.EOF,
// per the io.ReaderAt contract.
func (h *HTTPImage) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("iamt: negative offset %d", off)
	}
	if off >= h.size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(want) > h.size-off {
		want = int(h.size - off)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	filled := 0
	for filled < want {
		cur := off + int64(filled)
		idx := cur / h.window
		win, err := h.windowLocked(idx)
		if err != nil {
			return filled, err
		}
		start := cur - idx*h.window
		n := copy(p[filled:want], win[start:])
		filled += n
	}
	if filled < len(p) {
		return filled, io.EOF
	}
	return filled, nil
}

// windowLocked returns window idx, fetching it on a cache miss. Caller holds mu.
func (h *HTTPImage) windowLocked(idx int64) ([]byte, error) {
	if win, ok := h.cache[idx]; ok {
		h.touch(idx)
		return win, nil
	}
	start := idx * h.window
	end := start + h.window
	if end > h.size {
		end = h.size
	}
	win, err := h.fetch(start, end-1)
	if err != nil {
		return nil, err
	}
	h.cache[idx] = win
	h.lru = append(h.lru, idx)
	h.evictLocked()
	return win, nil
}

// fetch performs a Range GET for the inclusive byte range and returns its body.
func (h *HTTPImage) fetch(start, end int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("iamt: fetching bytes %d-%d: %w", start, end, err)
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusPartialContent {
		return nil, fmt.Errorf("iamt: range request for %d-%d returned status %d", start, end, resp.StatusCode)
	}
	buf := make([]byte, end-start+1)
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		return nil, fmt.Errorf("iamt: reading bytes %d-%d: %w", start, end, err)
	}
	return buf, nil
}

// touch marks idx most-recently-used. Caller holds mu.
func (h *HTTPImage) touch(idx int64) {
	for i, v := range h.lru {
		if v == idx {
			h.lru = append(h.lru[:i], h.lru[i+1:]...)
			break
		}
	}
	h.lru = append(h.lru, idx)
}

// evictLocked drops least-recently-used windows past the cap. Caller holds mu.
func (h *HTTPImage) evictLocked() {
	for len(h.lru) > h.maxWindows {
		victim := h.lru[0]
		h.lru = h.lru[1:]
		delete(h.cache, victim)
	}
}

func roundUp(v, mult int64) int64 {
	if v <= 0 {
		return mult
	}
	return ((v + mult - 1) / mult) * mult
}

// totalFromContentRange parses the total length from a "bytes A-B/TOTAL" header.
func totalFromContentRange(v string) (int64, error) {
	i := strings.LastIndex(v, "/")
	if i < 0 || i == len(v)-1 {
		return 0, fmt.Errorf("iamt: missing total in Content-Range %q", v)
	}
	total := v[i+1:]
	if total == "*" {
		return 0, fmt.Errorf("iamt: server reported an unknown total size (Content-Range %q)", v)
	}
	n, err := strconv.ParseInt(total, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("iamt: bad Content-Range total %q: %w", v, err)
	}
	return n, nil
}

func drainClose(rc io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, 4<<10))
	_ = rc.Close()
}
