// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

package pkgsite_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbhb-dev/gomodscan/internal/cachehttp"
	"github.com/tbhb-dev/gomodscan/internal/pkgsite"
	"github.com/tbhb-dev/gomodscan/internal/retryhttp"
)

// TestVersions_CacheStackServesSecondCallFromDisk exercises the full transport
// composition the CLI assembles in newVersionsClient (the on-disk cache
// wrapped around the retry transport wrapped around a real HTTP transport)
// against a live httptest server. Where the cachehttp unit tests stub the
// origin with an in-memory RoundTripper, this drives the real stack end to
// end: real sockets, the real Cache-Control directive pkg.go.dev sends, real
// gob serialization, and real disk I/O. It proves the transport writes a 200
// with max-age to disk and serves the repeat lookup from that file without a
// second origin request.
func TestVersions_CacheStackServesSecondCallFromDisk(t *testing.T) {
	t.Parallel()

	const body = `{"items":[{"modulePath":"example.com/m","version":"v1.0.0","latestVersion":"v1.0.0"}],"total":1}`
	var originHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		originHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600") // the directive pkg.go.dev sends on 200
		mustWrite(t, w, body)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	transport := cachehttp.NewTransport(
		retryhttp.NewTransport(
			http.DefaultTransport, retryhttp.InitialDelay, retryhttp.MaxDelay, retryhttp.AttemptTimeout,
		),
		cachehttp.NewDiskStore(cacheDir),
	)
	c := &pkgsite.Client{BaseURL: srv.URL, HTTPClient: &http.Client{Transport: transport}}

	// First lookup reaches the origin and populates the on-disk cache.
	first, err := c.Versions(t.Context(), "example.com/m")
	require.NoError(t, err)
	require.Len(t, first, 1)
	assert.Equal(t, "v1.0.0", first[0].Version)
	assert.Equal(t, int32(1), originHits.Load())

	// The 200 max-age response wrote a real cache file to disk.
	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "the 200 max-age response should write exactly one cache file")

	// The repeat lookup comes from disk: identical result, same origin-hit count.
	second, err := c.Versions(t.Context(), "example.com/m")
	require.NoError(t, err)
	assert.Equal(t, first, second, "the cached result must match the origin result")
	assert.Equal(t, int32(1), originHits.Load(), "the repeat lookup must be served from the on-disk cache")
}

// TestVersions_CacheStackDoesNotCacheNotFound confirms the full stack honors
// the no-store 404 pkg.go.dev returns for a private module or one it never
// indexed: the negative lookup writes nothing and re-hits the origin every
// run, so a stale miss never masks a module that later gets indexed.
func TestVersions_CacheStackDoesNotCacheNotFound(t *testing.T) {
	t.Parallel()

	var originHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		originHits.Add(1)
		w.Header().Set("Cache-Control", "no-store") // the directive pkg.go.dev sends on 404
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	transport := cachehttp.NewTransport(
		retryhttp.NewTransport(
			http.DefaultTransport, retryhttp.InitialDelay, retryhttp.MaxDelay, retryhttp.AttemptTimeout,
		),
		cachehttp.NewDiskStore(cacheDir),
	)
	c := &pkgsite.Client{BaseURL: srv.URL, HTTPClient: &http.Client{Transport: transport}}

	_, err := c.Versions(t.Context(), "example.com/private")
	require.ErrorIs(t, err, pkgsite.ErrNotFound)
	_, err = c.Versions(t.Context(), "example.com/private")
	require.ErrorIs(t, err, pkgsite.ErrNotFound)

	assert.Equal(t, int32(2), originHits.Load(), "a no-store 404 must re-hit the origin every run")
	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "a no-store 404 must never write a cache file")
}
