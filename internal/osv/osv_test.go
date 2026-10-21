// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

package osv_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbhb-dev/gomodscan/internal/osv"
	"github.com/tbhb-dev/gomodscan/internal/retryhttp"
)

// mustWrite writes body to w and records any error against t.
// The httptest handlers run in their own goroutine. t.Errorf stays
// safe from that context: it records the failure without panicking.
func mustWrite(t *testing.T, w http.ResponseWriter, body string) {
	t.Helper()
	if _, err := w.Write([]byte(body)); err != nil {
		t.Errorf("write response body: %v", err)
	}
}

// queryCase drives one TestQuery subtest. Each case supplies a
// handler, optional client overrides, the package and version under
// query, an error matcher set, and a verifier for the success path.
type queryCase struct {
	name       string
	handler    http.HandlerFunc
	clientOpts func(c *osv.Client)
	pkg        osv.Package
	version    string
	wantErr    []error
	notWantErr []error
	errSubstr  string
	verify     func(t *testing.T, got []osv.Vulnerability)
}

func TestQuery(t *testing.T) {
	t.Parallel()

	const cobraModule = "github.com/spf13/cobra"
	emptyBody := `{"vulns":[]}`

	const flaggedModule = "example.com/totally-fine"
	maliciousBody := `{
		"vulns": [
			{
				"id": "MAL-2025-0001",
				"summary": "Malicious code in v1.2.3",
				"aliases": ["GHSA-aaaa-bbbb-cccc"],
				"modified": "2025-01-15T00:00:00Z",
				"published": "2025-01-14T00:00:00Z"
			}
		]
	}`

	const mixedModule = "example.com/has-cve-too"
	mixedBody := `{
		"vulns": [
			{"id": "GO-2025-0042", "summary": "Generic vuln"},
			{"id": "MAL-2025-0007", "summary": "Backdoor introduced upstream"}
		]
	}`

	const customUA = "malscan-test/0"

	cases := []queryCase{
		{
			name:    "empty vulns decodes to a nil-or-empty slice",
			pkg:     osv.Package{Name: cobraModule, Ecosystem: "Go"},
			version: "v1.10.2",
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/query", r.URL.Path)
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
				assert.Equal(t, osv.DefaultUserAgent, r.Header.Get("User-Agent"))
				var sent struct {
					Version string `json:"version"`
					Package struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					} `json:"package"`
				}
				if decErr := json.NewDecoder(r.Body).Decode(&sent); decErr != nil {
					t.Errorf("decode request body: %v", decErr)
				}
				assert.Equal(t, "v1.10.2", sent.Version)
				assert.Equal(t, cobraModule, sent.Package.Name)
				assert.Equal(t, "Go", sent.Package.Ecosystem)
				w.Header().Set("Content-Type", "application/json")
				mustWrite(t, w, emptyBody)
			},
			verify: func(t *testing.T, got []osv.Vulnerability) {
				t.Helper()
				assert.Empty(t, got)
			},
		},
		{
			name:    "MAL-prefixed advisory decodes verbatim",
			pkg:     osv.Package{Name: flaggedModule, Ecosystem: "Go"},
			version: "v1.2.3",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				mustWrite(t, w, maliciousBody)
			},
			verify: func(t *testing.T, got []osv.Vulnerability) {
				t.Helper()
				require.Len(t, got, 1)
				assert.Equal(t, "MAL-2025-0001", got[0].ID)
				assert.Equal(t, "Malicious code in v1.2.3", got[0].Summary)
				assert.Equal(t, []string{"GHSA-aaaa-bbbb-cccc"}, got[0].Aliases)
			},
		},
		{
			name:    "mixed advisory list preserves order",
			pkg:     osv.Package{Name: mixedModule, Ecosystem: "Go"},
			version: "v0.5.0",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				mustWrite(t, w, mixedBody)
			},
			verify: func(t *testing.T, got []osv.Vulnerability) {
				t.Helper()
				require.Len(t, got, 2)
				assert.Equal(t,
					[]string{"GO-2025-0042", "MAL-2025-0007"},
					[]string{got[0].ID, got[1].ID},
				)
			},
		},
		{
			name:    "non-200 wraps ErrUnexpectedStatus",
			pkg:     osv.Package{Name: "example.com/whatever", Ecosystem: "Go"},
			version: "v0.0.1",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "boom", http.StatusInternalServerError)
			},
			// The default client retries 5xx; inject a plain client so this
			// case exercises the status-to-error mapping in a single shot. The
			// TestQuery_Retries* tests below cover the retry behavior itself.
			clientOpts: func(c *osv.Client) { c.HTTPClient = &http.Client{} },
			wantErr:    []error{osv.ErrUnexpectedStatus},
		},
		{
			name:    "malformed JSON surfaces as a decode error",
			pkg:     osv.Package{Name: "example.com/garbage", Ecosystem: "Go"},
			version: "v0.0.1",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				mustWrite(t, w, "not json at all")
			},
			notWantErr: []error{osv.ErrUnexpectedStatus},
			errSubstr:  "decode",
		},
		{
			name:    "custom User-Agent reaches the server unchanged",
			pkg:     osv.Package{Name: "example.com/whatever", Ecosystem: "Go"},
			version: "v0.0.1",
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, customUA, r.Header.Get("User-Agent"))
				w.Header().Set("Content-Type", "application/json")
				mustWrite(t, w, emptyBody)
			},
			clientOpts: func(c *osv.Client) { c.UserAgent = customUA },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runQueryCase(t, tc)
		})
	}
}

// runQueryCase wires the case's handler into an httptest server and
// points a Client at it. The case's expectations then drive the
// Query call and the post-call assertions.
func runQueryCase(t *testing.T, tc queryCase) {
	t.Helper()
	srv := httptest.NewServer(tc.handler)
	t.Cleanup(srv.Close)

	c := &osv.Client{BaseURL: srv.URL}
	if tc.clientOpts != nil {
		tc.clientOpts(c)
	}

	got, err := c.Query(t.Context(), tc.pkg, tc.version)
	hasErrExpectations := len(tc.wantErr) > 0 || len(tc.notWantErr) > 0 || tc.errSubstr != ""
	if !hasErrExpectations {
		require.NoError(t, err)
		if tc.verify != nil {
			tc.verify(t, got)
		}
		return
	}
	require.Error(t, err)
	for _, want := range tc.wantErr {
		require.ErrorIs(t, err, want)
	}
	for _, notWant := range tc.notWantErr {
		require.NotErrorIs(t, err, notWant)
	}
	if tc.errSubstr != "" {
		assert.Contains(t, err.Error(), tc.errSubstr)
	}
}

// TestQuery_ContextCancelled lives outside the table because the
// timing dance (slow handler vs. short deadline) doesn't fit the
// synchronous case shape the table assumes.
func TestQuery_ContextCancelled(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		mustWrite(t, w, `{"vulns":[]}`)
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	t.Cleanup(cancel)

	c := &osv.Client{BaseURL: srv.URL}
	_, err := c.Query(ctx, osv.Package{Name: "example.com/slow", Ecosystem: "Go"}, "v0.0.1")
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline"),
		"expected deadline-exceeded, got %v", err,
	)
}

// The retry tests below drive the failsafe-go retry/backoff policy through the
// public Query call, inside a testing/synctest bubble with an in-memory
// transport. The bubble's fake clock advances every backoff wait instantly, so
// the tests reuse the real production timing constants yet finish in
// microseconds and stay deterministic. The retryhttp package tests cover
// the transport's own behavior (Retry-After handling, per-attempt timeout,
// jitter); these confirm Query composes with the shared transport and maps
// a persistent failure onto ErrUnexpectedStatus.

const retryVulnsBody = `{"vulns":[{"id":"MAL-2025-0001","summary":"Malicious code"}]}`

// roundTripperFunc adapts a function to an http.RoundTripper, standing in for
// the network so the retry policy runs under a fake clock with no real I/O.
// (synctest doesn't advance time across real network blocks.)
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// fakeResponse builds a minimal *http.Response for the in-memory transport.
func fakeResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

// retryClient builds a Client whose transport applies the production
// retry/backoff policy around a counting in-memory transport. It invokes
// respond once per attempt with the 1-based attempt number, and the returned
// counter records how many attempts reached the transport.
func retryClient(
	respond func(attempt int32, req *http.Request) (*http.Response, error),
) (*osv.Client, *atomic.Int32) {
	var count atomic.Int32
	inner := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return respond(count.Add(1), req)
	})
	c := &osv.Client{
		BaseURL: "http://example.test",
		HTTPClient: &http.Client{
			Transport: retryhttp.NewTransport(
				inner, retryhttp.InitialDelay, retryhttp.MaxDelay, retryhttp.AttemptTimeout,
			),
		},
	}
	return c, &count
}

func TestQuery_RetriesServerErrorThenSucceeds(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c, count := retryClient(func(attempt int32, req *http.Request) (*http.Response, error) {
			if attempt <= retryhttp.MaxRetries {
				return fakeResponse(req, http.StatusInternalServerError, "boom"), nil
			}
			return fakeResponse(req, http.StatusOK, retryVulnsBody), nil
		})

		got, err := c.Query(t.Context(), osv.Package{Name: "example.com/m", Ecosystem: "Go"}, "v1.0.0")
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "MAL-2025-0001", got[0].ID)
		assert.Equal(t, int32(retryhttp.MaxRetries+1), count.Load(), "should retry until the success response")
	})
}

func TestQuery_ExhaustsRetriesOnPersistentServerError(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c, count := retryClient(func(_ int32, req *http.Request) (*http.Response, error) {
			return fakeResponse(req, http.StatusServiceUnavailable, "still broken"), nil
		})

		_, err := c.Query(t.Context(), osv.Package{Name: "example.com/m", Ecosystem: "Go"}, "v1.0.0")
		// ReturnLastFailure lets the final 503 flow through the status switch
		// instead of a retrypolicy.ExceededError wrapper.
		require.ErrorIs(t, err, osv.ErrUnexpectedStatus)
		assert.Equal(
			t,
			int32(retryhttp.MaxRetries+1),
			count.Load(),
			"should attempt the initial request plus every retry",
		)
		var re *retryhttp.Error
		require.ErrorAs(t, err, &re)
		assert.Equal(t, retryhttp.MaxRetries+1, re.Attempts)
		assert.Equal(t, http.StatusServiceUnavailable, re.LastStatus)
	})
}

func TestQuery_DoesNotRetryTerminalStatus(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c, count := retryClient(func(_ int32, req *http.Request) (*http.Response, error) {
			return fakeResponse(req, http.StatusBadRequest, "bad request"), nil
		})

		_, err := c.Query(t.Context(), osv.Package{Name: "example.com/m", Ecosystem: "Go"}, "v1.0.0")
		require.ErrorIs(t, err, osv.ErrUnexpectedStatus)
		assert.Equal(t, int32(1), count.Load(), "a terminal 4xx must not be retried")
		var re *retryhttp.Error
		require.ErrorAs(t, err, &re)
		assert.Equal(t, 1, re.Attempts)
		assert.Equal(t, http.StatusBadRequest, re.LastStatus)
	})
}
