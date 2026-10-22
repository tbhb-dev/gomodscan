// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

package cachehttp_test

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbhb-dev/gomodscan/internal/cachehttp"
)

// The transport's freshness logic turns on timing, so the tests that cross a
// freshness window run inside a testing/synctest bubble against an in-memory
// RoundTripper. The bubble's fake clock advances every time.Sleep instantly,
// so the tests use the real 3600 s max-age the server sends yet finish in
// microseconds. The disk-store tests run in real time: they assert hits
// inside the window (no clock advance needed) and exercise file IO directly.

const okBody = `{"ok":true}`

const moduleURL = "http://example.test/v1/versions/example.com/m"

// roundTripperFunc adapts a function to an http.RoundTripper. It replaces the
// network and lets the cache policy run without real I/O.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// memStore gives the transport tests an in-memory [cachehttp.Store] that
// exercises the caching policy without touching disk.
type memStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemStore() *memStore { return &memStore{data: make(map[string][]byte)} }

func (m *memStore) Get(key string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	blob, ok := m.data[key]
	return blob, ok
}

func (m *memStore) Put(key string, blob []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = blob
}

func (m *memStore) len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.data)
}

// reply builds an inner response with the given Cache-Control directive
// (omitted when cacheControl is empty).
func reply(req *http.Request, status int, body, cacheControl string) *http.Response {
	header := make(http.Header)
	if cacheControl != "" {
		header.Set("Cache-Control", cacheControl)
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

// cachingClient builds an http.Client whose transport wraps a counting
// in-memory RoundTripper with the on-disk cache backed by store. respond runs
// once per origin request; the returned counter records how many requests
// reached the origin rather than the cache.
func cachingClient(
	store cachehttp.Store,
	respond func(req *http.Request) *http.Response,
) (*http.Client, *atomic.Int32) {
	var count atomic.Int32
	inner := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		count.Add(1)
		return respond(req), nil
	})
	return &http.Client{Transport: cachehttp.NewTransport(inner, store)}, &count
}

// result captures the part of a response the cache tests assert on, taken
// after fetch fully reads and closes the body.
type result struct {
	status int
	header http.Header
	body   string
}

// fromCache reports whether the transport served this result from the store.
func (r result) fromCache() bool { return r.header.Get(cachehttp.FromCacheHeader) == "1" }

// fetch issues a request for moduleURL through c, drains and closes the body,
// and returns the captured result. Closing the body here keeps the response
// out of the caller. Each test then reads cache state without juggling
// bodies.
func fetch(t *testing.T, c *http.Client, method string) result {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, moduleURL, nil)
	require.NoError(t, err)
	resp, err := c.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return result{status: resp.StatusCode, header: resp.Header, body: string(body)}
}

func TestTransport_ServesFreshHitThenRefreshesWhenStale(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c, count := cachingClient(newMemStore(), func(req *http.Request) *http.Response {
			return reply(req, http.StatusOK, okBody, "public, max-age=3600")
		})

		// First fetch reaches the origin and populates the cache.
		first := fetch(t, c, http.MethodGet)
		assert.Equal(t, http.StatusOK, first.status)
		assert.Equal(t, okBody, first.body)
		assert.False(t, first.fromCache())
		assert.Equal(t, int32(1), count.Load())

		// A second fetch inside the freshness window comes from the cache.
		hit := fetch(t, c, http.MethodGet)
		assert.Equal(t, okBody, hit.body)
		assert.True(t, hit.fromCache())
		assert.Equal(t, int32(1), count.Load(), "a fresh hit must not reach the origin")

		// Past the window the entry goes stale and the transport re-fetches.
		time.Sleep(3601 * time.Second)
		stale := fetch(t, c, http.MethodGet)
		assert.Equal(t, okBody, stale.body)
		assert.False(t, stale.fromCache())
		assert.Equal(t, int32(2), count.Load(), "a stale entry must re-fetch from the origin")
	})
}

func TestTransport_DoesNotCacheNoStore(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	c, count := cachingClient(store, func(req *http.Request) *http.Response {
		return reply(req, http.StatusNotFound, "not found", "no-store")
	})

	for range 3 {
		got := fetch(t, c, http.MethodGet)
		assert.Equal(t, http.StatusNotFound, got.status)
		assert.False(t, got.fromCache())
	}
	assert.Equal(t, int32(3), count.Load(), "a no-store response must re-hit the origin every time")
	assert.Zero(t, store.len(), "no-store must never write an entry")
}

func TestTransport_DoesNotCacheWithoutDirectives(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	c, count := cachingClient(store, func(req *http.Request) *http.Response {
		return reply(req, http.StatusOK, okBody, "") // no Cache-Control at all
	})

	fetch(t, c, http.MethodGet)
	fetch(t, c, http.MethodGet)
	assert.Equal(t, int32(2), count.Load(), "a response without freshness guidance must not be cached")
	assert.Zero(t, store.len())
}

// garbageStore returns a blob that never decodes, modeling a truncated or
// corrupt cache file.
type garbageStore struct{ puts atomic.Int32 }

func (g *garbageStore) Get(string) ([]byte, bool) { return []byte("not a valid gob stream"), true }
func (g *garbageStore) Put(string, []byte)        { g.puts.Add(1) }

func TestTransport_CorruptEntryDegradesToMiss(t *testing.T) {
	t.Parallel()
	store := &garbageStore{}
	c, count := cachingClient(store, func(req *http.Request) *http.Response {
		return reply(req, http.StatusOK, okBody, "max-age=3600")
	})

	got := fetch(t, c, http.MethodGet)
	assert.Equal(t, okBody, got.body)
	assert.False(t, got.fromCache(), "a corrupt entry must not be served")
	assert.Equal(t, int32(1), count.Load(), "a corrupt entry degrades to an origin fetch")
	assert.Equal(t, int32(1), store.puts.Load(), "the fresh response replaces the corrupt entry")
}

func TestTransport_PassesThroughNonGET(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	c, count := cachingClient(store, func(req *http.Request) *http.Response {
		// Only the method keeps this otherwise cacheable response out of the cache.
		return reply(req, http.StatusOK, okBody, "max-age=3600")
	})

	fetch(t, c, http.MethodPost)
	fetch(t, c, http.MethodPost)
	assert.Equal(t, int32(2), count.Load(), "a POST is never served from or written to the cache")
	assert.Zero(t, store.len())
}

func TestTransport_HonorsAgeHeader(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		// max-age 100 s minus an Age of 90 s leaves a 10 s effective window.
		c, count := cachingClient(newMemStore(), func(req *http.Request) *http.Response {
			resp := reply(req, http.StatusOK, okBody, "max-age=100")
			resp.Header.Set("Age", "90")
			return resp
		})

		fetch(t, c, http.MethodGet)
		assert.Equal(t, int32(1), count.Load())

		// Still inside the 10 s effective window: a cache hit.
		time.Sleep(5 * time.Second)
		assert.True(t, fetch(t, c, http.MethodGet).fromCache())
		assert.Equal(t, int32(1), count.Load())

		// Past it (11 s total > 10 s): the Age-shortened entry goes stale.
		time.Sleep(6 * time.Second)
		assert.False(t, fetch(t, c, http.MethodGet).fromCache())
		assert.Equal(t, int32(2), count.Load(), "Age must shorten the effective freshness window")
	})
}

func TestTransport_WithDiskStoreServesHit(t *testing.T) {
	t.Parallel()
	c, count := cachingClient(cachehttp.NewDiskStore(t.TempDir()), func(req *http.Request) *http.Response {
		return reply(req, http.StatusOK, okBody, "public, max-age=3600")
	})

	first := fetch(t, c, http.MethodGet)
	assert.Equal(t, okBody, first.body)
	assert.Equal(t, int32(1), count.Load())

	hit := fetch(t, c, http.MethodGet)
	assert.Equal(t, okBody, hit.body)
	assert.True(t, hit.fromCache(), "the second fetch reads from disk")
	assert.Equal(t, int32(1), count.Load())
}

func TestDiskStore_RoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := cachehttp.NewDiskStore(dir)

	_, ok := s.Get("absent")
	assert.False(t, ok, "an absent key is a miss")

	s.Put("k1", []byte("hello"))
	got, ok := s.Get("k1")
	require.True(t, ok)
	assert.Equal(t, []byte("hello"), got)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), ".tmp-", "an atomic write leaves no temp file behind")
	}
}

func TestDiskStore_ConcurrentPutSameKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := cachehttp.NewDiskStore(dir)

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			s.Put("hot", fmt.Appendf(nil, "value-%d", i))
		})
	}
	wg.Wait()

	got, ok := s.Get("hot")
	require.True(t, ok, "a concurrent write must leave a readable entry")
	assert.True(t, strings.HasPrefix(string(got), "value-"), "the stored value is one intact write, got %q", got)
}

func TestDefaultDir(t *testing.T) {
	t.Parallel()
	dir, err := cachehttp.DefaultDir()
	require.NoError(t, err)
	assert.True(t,
		strings.HasSuffix(filepath.ToSlash(dir), "gomodscan/pkgsite"),
		"default dir should sit under gomodscan/pkgsite, got %q", dir,
	)
}

var errBoom = errors.New("boom")

// A failing reader simulates a response body that breaks mid-stream.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errBoom }

func TestTransport_PropagatesInnerError(t *testing.T) {
	t.Parallel()
	inner := roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, errBoom })
	c := &http.Client{Transport: cachehttp.NewTransport(inner, newMemStore())}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, moduleURL, nil)
	require.NoError(t, err)
	_, err = c.Do(req) //nolint:bodyclose // the round trip errors, so no body exists to close.
	require.Error(t, err, "the transport surfaces an inner round-trip error")
}

func TestTransport_BodyReadErrorSkipsCache(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	c, _ := cachingClient(store, func(req *http.Request) *http.Response {
		header := make(http.Header)
		header.Set("Cache-Control", "max-age=3600")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     header,
			Body:       io.NopCloser(errReader{}),
			Request:    req,
		}
	})
	got := fetch(t, c, http.MethodGet)
	assert.Empty(t, got.body, "the unreadable body yields nothing")
	assert.Zero(t, store.len(), "a body read error skips the cache write")
}

func TestDiskStore_PutErrorsLeaveNoEntry(t *testing.T) {
	t.Parallel()

	t.Run("blocked directory creation", func(t *testing.T) {
		t.Parallel()
		// A regular file where the cache directory should sit blocks creation.
		file := filepath.Join(t.TempDir(), "blocker")
		require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))
		s := cachehttp.NewDiskStore(filepath.Join(file, "sub"))
		s.Put("k", []byte("v"))
		_, ok := s.Get("k")
		assert.False(t, ok)
	})

	t.Run("rename onto a directory", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		// A directory sitting at the key path makes the final rename fail.
		require.NoError(t, os.Mkdir(filepath.Join(dir, "taken"), 0o750))
		s := cachehttp.NewDiskStore(dir)
		s.Put("taken", []byte("v"))
		_, ok := s.Get("taken")
		assert.False(t, ok, "a rename onto a directory leaves no readable entry")
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		for _, e := range entries {
			assert.NotContains(t, e.Name(), ".tmp-", "a failed rename cleans up its temp file")
		}
	})
}

func TestDefaultDir_ErrorsWithoutHome(t *testing.T) {
	// Clearing every per-OS cache base forces the user-cache lookup to error.
	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("LocalAppData", "")
	_, err := cachehttp.DefaultDir()
	require.Error(t, err)
}

func TestTransport_DoesNotCacheMaxAgeZero(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	c, count := cachingClient(store, func(req *http.Request) *http.Response {
		return reply(req, http.StatusOK, okBody, "max-age=0")
	})

	fetch(t, c, http.MethodGet)
	fetch(t, c, http.MethodGet)
	assert.Equal(t, int32(2), count.Load(), "max-age=0 grants no freshness window, so nothing caches")
	assert.Zero(t, store.len())
}

func TestTransport_NoStoreOverridesMaxAge(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	c, count := cachingClient(store, func(req *http.Request) *http.Response {
		return reply(req, http.StatusOK, okBody, "no-store, max-age=3600")
	})

	fetch(t, c, http.MethodGet)
	fetch(t, c, http.MethodGet)
	assert.Equal(t, int32(2), count.Load(), "no-store wins over a max-age on the same response")
	assert.Zero(t, store.len())
}
