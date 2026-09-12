// SPDX-License-Identifier: MPL-2.0

package iamt

import (
	"container/list"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// isoSectorSize is the logical block size of ISO 9660 / UDF optical media.
const isoSectorSize = 2048

const (
	// rangeChunkSize is the granularity fetched per cache miss. It is a
	// multiple of the sector size and large enough that the boot's mostly
	// sequential reads amortise the HTTP round trip, while small enough that
	// the LRU cache stays bounded.
	rangeChunkSize = 1 << 20 // 1 MiB (512 sectors)
	// rangeMaxChunks bounds the in-memory cache (chunkSize * maxChunks).
	rangeMaxChunks = 64 // 64 MiB
)

// httpRangeReaderAt streams a remote image to the host on demand: it satisfies
// each io.ReaderAt call with HTTP Range requests instead of downloading the
// whole image to local disk. A factory-style URL that 302-redirects to
// presigned object storage is resolved once and Range requests are then issued
// against the resolved URL (the Range header is not part of a typical presigned
// signature). Recently used chunks are held in a small LRU so the firmware's
// repeated reads of hot sectors (0, the ISO PVD at sector 16, the El Torito
// boot catalog) do not re-hit the network.
type httpRangeReaderAt struct {
	client    *http.Client
	origURL   string
	chunkSize int64
	size      int64

	mu       sync.Mutex
	resolved string
	lru      *list.List // front = most recently used; values are *rangeChunk
	index    map[int64]*list.Element
}

type rangeChunk struct {
	idx  int64
	data []byte
}

// newRangeHTTPClient builds an HTTP client tuned for range streaming: no
// transparent compression (which would corrupt Range semantics) and persistent
// connections so each chunk does not pay a fresh TLS handshake.
func newRangeHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Minute,
		Transport: &http.Transport{
			MaxIdleConns:        16,
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  true,
			ForceAttemptHTTP2:   true,
		},
	}
}

// newHTTPRangeReaderAt resolves the image's size and final URL and verifies the
// server supports range requests.
func newHTTPRangeReaderAt(ctx context.Context, url string, client *http.Client) (*httpRangeReaderAt, error) {
	if client == nil {
		client = newRangeHTTPClient()
	}
	r := &httpRangeReaderAt{
		client:    client,
		origURL:   url,
		chunkSize: rangeChunkSize,
		lru:       list.New(),
		index:     make(map[int64]*list.Element),
	}
	if err := r.resolve(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// resolve follows redirects once with a probing range request to learn the
// total size (from Content-Range) and the resolved URL to fetch chunks from.
func (r *httpRangeReaderAt) resolve(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.origURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Range", "bytes=0-0")
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("iamt: resolving %s: %w", r.origURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1))

	if resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("iamt: %s does not support range requests (HTTP %d)", r.origURL, resp.StatusCode)
	}
	total, err := parseContentRangeTotal(resp.Header.Get("Content-Range"))
	if err != nil {
		return fmt.Errorf("iamt: %s: %w", r.origURL, err)
	}
	r.size = total
	if resp.Request != nil && resp.Request.URL != nil {
		r.resolved = resp.Request.URL.String()
	} else {
		r.resolved = r.origURL
	}
	return nil
}

// parseContentRangeTotal extracts SIZE from a "bytes START-END/SIZE" header.
func parseContentRangeTotal(v string) (int64, error) {
	i := strings.LastIndex(v, "/")
	if i < 0 || i == len(v)-1 {
		return 0, fmt.Errorf("missing total in Content-Range %q", v)
	}
	total, err := strconv.ParseInt(strings.TrimSpace(v[i+1:]), 10, 64)
	if err != nil || total <= 0 {
		return 0, fmt.Errorf("invalid total in Content-Range %q", v)
	}
	return total, nil
}

// Size is the total image length in bytes.
func (r *httpRangeReaderAt) Size() int64 { return r.size }

// ReadAt implements io.ReaderAt, assembling the result from cached and freshly
// fetched chunks.
func (r *httpRangeReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("iamt: negative offset %d", off)
	}
	if off >= r.size {
		return 0, io.EOF
	}
	end := off + int64(len(p))
	if end > r.size {
		end = r.size
	}
	n := 0
	for pos := off; pos < end; {
		idx := pos / r.chunkSize
		data, err := r.chunk(idx)
		if err != nil {
			return n, err
		}
		start := pos - idx*r.chunkSize
		avail := int64(len(data)) - start
		want := end - pos
		if avail > want {
			avail = want
		}
		copy(p[n:], data[start:start+avail])
		n += int(avail)
		pos += avail
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// chunk returns chunk idx from the cache, fetching and caching it on a miss.
func (r *httpRangeReaderAt) chunk(idx int64) ([]byte, error) {
	r.mu.Lock()
	if el, ok := r.index[idx]; ok {
		r.lru.MoveToFront(el)
		data := el.Value.(*rangeChunk).data
		r.mu.Unlock()
		return data, nil
	}
	r.mu.Unlock()

	data, err := r.fetchChunk(idx)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	if el, ok := r.index[idx]; ok { // another caller may have raced us
		r.lru.MoveToFront(el)
		data = el.Value.(*rangeChunk).data
	} else {
		el := r.lru.PushFront(&rangeChunk{idx: idx, data: data})
		r.index[idx] = el
		for r.lru.Len() > rangeMaxChunks {
			oldest := r.lru.Back()
			if oldest == nil {
				break
			}
			r.lru.Remove(oldest)
			delete(r.index, oldest.Value.(*rangeChunk).idx)
		}
	}
	r.mu.Unlock()
	return data, nil
}

// fetchChunk downloads a single chunk via a Range request, re-resolving the URL
// once if the (possibly time-limited) resolved URL has expired.
func (r *httpRangeReaderAt) fetchChunk(idx int64) ([]byte, error) {
	data, err := r.rangeGet(idx)
	if err == nil {
		return data, nil
	}
	// A presigned URL may have expired; re-resolve and try once more.
	if rerr := r.resolve(context.Background()); rerr != nil {
		return nil, err
	}
	return r.rangeGet(idx)
}

func (r *httpRangeReaderAt) rangeGet(idx int64) ([]byte, error) {
	start := idx * r.chunkSize
	length := r.chunkSize
	if start+length > r.size {
		length = r.size - start
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	r.mu.Lock()
	url := r.resolved
	r.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", "bytes="+strconv.FormatInt(start, 10)+"-"+strconv.FormatInt(start+length-1, 10))
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("iamt: range GET: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusPartialContent {
		return nil, fmt.Errorf("iamt: range GET returned HTTP %d", resp.StatusCode)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		return nil, fmt.Errorf("iamt: reading range: %w", err)
	}
	return buf, nil
}
