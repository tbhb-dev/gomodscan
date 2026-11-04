// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

package pkgsite_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.tbhb.dev/gomodscan/internal/cachehttp"
	"go.tbhb.dev/gomodscan/internal/pkgsite"
	"go.tbhb.dev/gomodscan/internal/retryhttp"
)

// TestVersions_CacheStackServesSecondCallFromDisk exercises the full transport
// composition the command-line tool assembles in newVersionsClient (the on-disk cache
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
			serverOnlyTransport(srv), retryhttp.InitialDelay, retryhttp.MaxDelay, retryhttp.AttemptTimeout,
		),
		cachehttp.NewDiskStore(cacheDir),
	)
	client := newCachedClient(srv.URL, transport)

	// First lookup reaches the origin and populates the on-disk cache.
	first, err := client.Versions(t.Context(), "example.com/m")
	require.NoError(t, err)
	require.Len(t, first, 1)
	assert.Equal(t, "v1.0.0", first[0].Version)
	assert.Equal(t, int32(1), originHits.Load())

	// The 200 max-age response wrote a real cache file to disk.
	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "the 200 max-age response should write exactly one cache file")

	// The repeat lookup comes from disk: identical result, same origin-hit count.
	second, err := client.Versions(t.Context(), "example.com/m")
	require.NoError(t, err)
	assert.Equal(t, first, second, "the cached result must match the origin result")
	assert.Equal(t, int32(1), originHits.Load(), "the repeat lookup must be served from the on-disk cache")
}

// TestVersions_CacheStackDoesNotCacheNotFound confirms the full stack honors
// the no-store 404 pkg.go.dev returns for a private module or one it never
// indexed: the negative lookup doesn't write a cache entry and re-hits the
// origin every run, so a stale miss never masks a module that later gets
// indexed.
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
			serverOnlyTransport(srv), retryhttp.InitialDelay, retryhttp.MaxDelay, retryhttp.AttemptTimeout,
		),
		cachehttp.NewDiskStore(cacheDir),
	)
	client := newCachedClient(srv.URL, transport)

	_, err := client.Versions(t.Context(), "example.com/private")
	require.ErrorIs(t, err, pkgsite.ErrNotFound)
	_, err = client.Versions(t.Context(), "example.com/private")
	require.ErrorIs(t, err, pkgsite.ErrNotFound)

	assert.Equal(t, int32(2), originHits.Load(), "a no-store 404 must re-hit the origin every run")

	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "a no-store 404 must never write a cache file")
}

// TestVersions_CacheStackReportsCachedFailures checks the diagnostics of a
// page fault, first from the origin and then from the on-disk cache. From the
// origin, the fault reports the one attempt and the 200 it got. From the
// cache, it didn't make an attempt, so it reports 0 attempts and status 0,
// which keeps a 0 status meaning no HTTP response arrived.
func TestVersions_CacheStackReportsCachedFailures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		body       string
		wantErr    error
		wantFresh  string
		wantCached string
	}{
		{
			name:       "decode failure",
			body:       "not json at all",
			wantErr:    nil,
			wantFresh:  "decode example.com/m: ",
			wantCached: "decode cached response for example.com/m: ",
		},
		{
			name:       "stale page token",
			body:       `{"items":[],"total":0,"nextPageToken":"STUCK"}`,
			wantErr:    pkgsite.ErrStalePageToken,
			wantFresh:  "non-advancing nextPageToken: example.com/m (attempts: 1,",
			wantCached: "non-advancing nextPageToken: cached response for example.com/m (attempts: 0,",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var originHits atomic.Int32

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				originHits.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "public, max-age=3600")
				mustWrite(t, w, testCase.body)
			}))
			t.Cleanup(srv.Close)

			transport := cachehttp.NewTransport(
				retryhttp.NewTransport(
					serverOnlyTransport(srv), retryhttp.InitialDelay, retryhttp.MaxDelay, retryhttp.AttemptTimeout,
				),
				cachehttp.NewDiskStore(t.TempDir()),
			)
			client := newCachedClient(srv.URL, &budgetTransport{next: transport, served: atomic.Int32{}})

			_, err := client.Versions(t.Context(), "example.com/m")

			var response *retryhttp.Error
			require.ErrorAs(t, err, &response)
			assert.Equal(t, 1, response.Attempts)
			assert.Equal(t, http.StatusOK, response.LastStatus)
			assert.NotContains(t, err.Error(), "cached")
			assert.Contains(t, err.Error(), testCase.wantFresh)

			hits := originHits.Load()

			_, err = client.Versions(t.Context(), "example.com/m")
			require.ErrorAs(t, err, &response)
			assert.Equal(t, hits, originHits.Load(), "the repeat lookup must come from the cache")
			assert.Zero(t, response.Attempts)
			assert.Zero(t, response.LastStatus)
			assert.Contains(t, err.Error(), "(attempts: 0, last status: 0, no HTTP response)")

			if testCase.wantErr != nil {
				require.ErrorIs(t, err, testCase.wantErr)
			}

			assert.Contains(t, err.Error(), testCase.wantCached)
		})
	}
}

var errBudgetSpent = errors.New("request budget spent")

// budgetTransport fails every request after the first `requestBudget`. It wraps
// the cache, so it counts the pages the cache serves too. A client
// that pages forever then gets an error instead of hanging the test.
type budgetTransport struct {
	next   http.RoundTripper
	served atomic.Int32
}

func (b *budgetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if b.served.Add(1) > requestBudget {
		return nil, errBudgetSpent
	}

	return b.next.RoundTrip(req) //nolint:wrapcheck // a pass-through
}

// newCachedClient points a pkgsite client at baseURL through transport.
func newCachedClient(baseURL string, transport http.RoundTripper) *pkgsite.Client {
	return &pkgsite.Client{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Transport: transport, CheckRedirect: nil, Jar: nil, Timeout: 0},
		UserAgent:  "",
	}
}
