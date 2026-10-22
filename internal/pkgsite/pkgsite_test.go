// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

package pkgsite_test

import (
	"context"
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

	"github.com/tbhb-dev/gomodscan/internal/pkgsite"
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

// versionsCase drives one TestVersions subtest. Each case supplies a
// handler, optional client overrides, the module path under test, an
// error matcher set, and a verifier for the success path.
type versionsCase struct {
	name       string
	handler    http.HandlerFunc
	clientOpts func(c *pkgsite.Client)
	module     string
	wantErr    []error
	notWantErr []error
	errSubstr  string
	verify     func(t *testing.T, got []pkgsite.ModuleVersion)
}

func TestVersions(t *testing.T) {
	t.Parallel()

	const cobraModule = "github.com/spf13/cobra"
	singlePageBody := `{
		"items": [
			{"modulePath":"` + cobraModule + `","version":"v1.10.2","latestVersion":"v1.10.2","deprecated":false,"retracted":false,"commitTime":"2025-12-03T23:51:15Z"},
			{"modulePath":"` + cobraModule + `","version":"v1.10.1","latestVersion":"v1.10.2","deprecated":false,"retracted":false,"commitTime":"2025-09-01T16:19:51Z"}
		],
		"total": 2
	}`

	const manyVersionsModule = "example.com/many-versions"
	pageBodies := map[string]string{
		"": `{
			"items": [{"modulePath":"` + manyVersionsModule + `","version":"v0.3.0","latestVersion":"v0.3.0"}],
			"total": 3,
			"nextPageToken": "TOKEN-2"
		}`,
		"TOKEN-2": `{
			"items": [{"modulePath":"` + manyVersionsModule + `","version":"v0.2.0","latestVersion":"v0.3.0"}],
			"total": 3,
			"nextPageToken": "TOKEN-3"
		}`,
		"TOKEN-3": `{
			"items": [{"modulePath":"` + manyVersionsModule + `","version":"v0.1.0","latestVersion":"v0.3.0"}],
			"total": 3
		}`,
	}

	const oldAndBustedModule = "example.com/old-and-busted"
	deprecatedRetractedBody := `{
		"items": [
			{"modulePath":"` + oldAndBustedModule + `","version":"v2.0.0","latestVersion":"v2.0.0","deprecated":true,"deprecationReason":"use v3","retracted":false},
			{"modulePath":"` + oldAndBustedModule + `","version":"v1.0.1","latestVersion":"v2.0.0","deprecated":true,"deprecationReason":"use v3","retracted":true,"retractionReason":"breaking checksum"}
		],
		"total": 2
	}`

	const customUA = "depscan-test/0"

	cases := []versionsCase{
		{
			name:   "single page returns all items and headers match contract",
			module: cobraModule,
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/versions/"+cobraModule, r.URL.Path)
				assert.Equal(t, "200", r.URL.Query().Get("limit"))
				assert.Empty(t, r.URL.Query().Get("token"))
				assert.Equal(t, pkgsite.DefaultUserAgent, r.Header.Get("User-Agent"))
				w.Header().Set("Content-Type", "application/json")
				mustWrite(t, w, singlePageBody)
			},
			verify: func(t *testing.T, got []pkgsite.ModuleVersion) {
				t.Helper()
				require.Len(t, got, 2)
				assert.Equal(t, "v1.10.2", got[0].Version)
				assert.Equal(t, "v1.10.2", got[0].LatestVersion)
				assert.False(t, got[0].Retracted)
				assert.False(t, got[0].Deprecated)
			},
		},
		{
			name:   "pagination walks every nextPageToken until exhaustion",
			module: manyVersionsModule,
			handler: func(w http.ResponseWriter, r *http.Request) {
				token := r.URL.Query().Get("token")
				body, present := pageBodies[token]
				if !present {
					t.Errorf("unexpected token %q", token)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				mustWrite(t, w, body)
			},
			verify: func(t *testing.T, got []pkgsite.ModuleVersion) {
				t.Helper()
				require.Len(t, got, 3)
				assert.Equal(t,
					[]string{"v0.3.0", "v0.2.0", "v0.1.0"},
					[]string{got[0].Version, got[1].Version, got[2].Version},
				)
			},
		},
		{
			name:   "deprecation and retraction fields decode verbatim",
			module: oldAndBustedModule,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				mustWrite(t, w, deprecatedRetractedBody)
			},
			verify: func(t *testing.T, got []pkgsite.ModuleVersion) {
				t.Helper()
				require.Len(t, got, 2)
				assert.True(t, got[0].Deprecated)
				assert.Equal(t, "use v3", got[0].DeprecationReason)
				assert.True(t, got[1].Retracted)
				assert.Equal(t, "breaking checksum", got[1].RetractionReason)
			},
		},
		{
			name:   "404 wraps ErrNotFound",
			module: "example.com/private/repo",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "not found", http.StatusNotFound)
			},
			wantErr: []error{pkgsite.ErrNotFound},
		},
		{
			name:   "5xx wraps ErrUnexpectedStatus",
			module: "example.com/whatever",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "boom", http.StatusInternalServerError)
			},
			// The default client retries 5xx; inject a plain client so
			// this case exercises the status-to-error mapping in a single
			// shot. The TestRetryTransport_* tests below cover the retry
			// behavior itself.
			clientOpts: func(c *pkgsite.Client) { c.HTTPClient = &http.Client{} },
			wantErr:    []error{pkgsite.ErrUnexpectedStatus},
			notWantErr: []error{pkgsite.ErrNotFound},
		},
		{
			name:   "malformed JSON surfaces as a decode error",
			module: "example.com/garbage",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				mustWrite(t, w, "not json at all")
			},
			errSubstr: "decode",
		},
		{
			name:   "custom User-Agent reaches the server unchanged",
			module: "example.com/whatever",
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, customUA, r.Header.Get("User-Agent"))
				w.Header().Set("Content-Type", "application/json")
				mustWrite(t, w, `{"items":[],"total":0}`)
			},
			clientOpts: func(c *pkgsite.Client) { c.UserAgent = customUA },
		},
		{
			name:   "non-advancing nextPageToken is refused instead of looping",
			module: "example.com/stuck",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				// Hand back the same nextPageToken on every request. A
				// client that followed it would page forever; Versions must
				// bail out with ErrStalePageToken after one repeat.
				w.Header().Set("Content-Type", "application/json")
				mustWrite(t, w, `{
					"items": [{"modulePath":"example.com/stuck","version":"v1.0.0"}],
					"total": 1,
					"nextPageToken": "STUCK"
				}`)
			},
			wantErr: []error{pkgsite.ErrStalePageToken},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runVersionsCase(t, tc)
		})
	}
}

// runVersionsCase wires the case's handler into an httptest server
// and points a Client at it. The case's expectations then drive the
// Versions call and the post-call assertions.
func runVersionsCase(t *testing.T, tc versionsCase) {
	t.Helper()
	srv := httptest.NewServer(tc.handler)
	t.Cleanup(srv.Close)

	c := &pkgsite.Client{BaseURL: srv.URL}
	if tc.clientOpts != nil {
		tc.clientOpts(c)
	}

	got, err := c.Versions(t.Context(), tc.module)
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

// TestVersions_StalePageTokenReportsItsRequest checks that a repeated page
// token reports the attempt and the 200 of the request that delivered it,
// rather than the zero values that read as no HTTP response.
func TestVersions_StalePageTokenReportsItsRequest(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mustWrite(t, w, `{"items":[],"total":0,"nextPageToken":"STUCK"}`)
	}))
	t.Cleanup(srv.Close)

	c := &pkgsite.Client{BaseURL: srv.URL}
	_, err := c.Versions(t.Context(), "example.com/stuck")
	require.ErrorIs(t, err, pkgsite.ErrStalePageToken)
	var re *retryhttp.Error
	require.ErrorAs(t, err, &re)
	assert.Equal(t, 1, re.Attempts)
	assert.Equal(t, http.StatusOK, re.LastStatus)
	assert.Contains(t, err.Error(), "example.com/stuck (attempts: 1, last status: 200)")
}

// TestVersions_ContextCancelled lives outside the table because
// the timing dance (slow handler vs. short deadline) doesn't fit
// the synchronous case shape the table assumes.
func TestVersions_ContextCancelled(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		mustWrite(t, w, `{"items":[],"total":0}`)
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	t.Cleanup(cancel)

	c := &pkgsite.Client{BaseURL: srv.URL}
	_, err := c.Versions(ctx, "example.com/slow")
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline"),
		"expected deadline-exceeded, got %v", err,
	)
}

// The retry tests below drive the failsafe-go retry/backoff policy
// through the public Versions call, inside a testing/synctest bubble with
// an in-memory transport. The bubble's fake clock advances every backoff
// or Retry-After wait instantly, so the tests reuse the real production
// timing constants yet finish in microseconds and stay deterministic.
// The export_test.go shim reaches the unexported transport builder.

const retryOKBody = `{"items":[{"modulePath":"example.com/m","version":"v1.0.0","latestVersion":"v1.0.0"}],"total":1}`

// errConnRefused stands in for a transient network error the in-memory
// transport surfaces on every attempt.
var errConnRefused = errors.New("connection refused")

// roundTripperFunc adapts a function to an http.RoundTripper, standing in
// for the network so the retry policy runs under a fake clock with no
// real I/O. (synctest doesn't advance time across real network blocks.)
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
// respond once per attempt with the 1-based attempt number, and the
// returned counter records how many attempts reached the transport.
func retryClient(
	attemptTimeout time.Duration,
	respond func(attempt int32, req *http.Request) (*http.Response, error),
) (*pkgsite.Client, *atomic.Int32) {
	var count atomic.Int32
	inner := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return respond(count.Add(1), req)
	})
	c := &pkgsite.Client{
		BaseURL: "http://example.test",
		HTTPClient: &http.Client{
			Transport: retryhttp.NewTransport(
				inner, retryhttp.InitialDelay, retryhttp.MaxDelay, attemptTimeout,
			),
		},
	}
	return c, &count
}

func TestRetryTransport_RetriesServerErrorThenSucceeds(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c, count := retryClient(retryhttp.AttemptTimeout,
			func(attempt int32, req *http.Request) (*http.Response, error) {
				if attempt <= retryhttp.MaxRetries {
					return fakeResponse(req, http.StatusInternalServerError, "boom"), nil
				}
				return fakeResponse(req, http.StatusOK, retryOKBody), nil
			})

		got, err := c.Versions(t.Context(), "example.com/m")
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, int32(retryhttp.MaxRetries+1), count.Load(), "should retry until the success response")
	})
}

func TestRetryTransport_ExhaustsRetriesOnPersistentServerError(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c, count := retryClient(retryhttp.AttemptTimeout,
			func(_ int32, req *http.Request) (*http.Response, error) {
				return fakeResponse(req, http.StatusServiceUnavailable, "still broken"), nil
			})

		_, err := c.Versions(t.Context(), "example.com/m")
		// ReturnLastFailure lets the final 503 flow through the status
		// switch instead of a retrypolicy.ExceededError wrapper.
		require.ErrorIs(t, err, pkgsite.ErrUnexpectedStatus)
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

func TestRetryTransport_ReportsLastNetworkError(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c, count := retryClient(retryhttp.AttemptTimeout,
			func(_ int32, _ *http.Request) (*http.Response, error) {
				return nil, errConnRefused
			})

		_, err := c.Versions(t.Context(), "example.com/m")
		require.ErrorIs(t, err, errConnRefused)
		var re *retryhttp.Error
		require.ErrorAs(t, err, &re)
		assert.Equal(t, retryhttp.MaxRetries+1, re.Attempts)
		assert.Equal(t, int32(retryhttp.MaxRetries+1), count.Load())
		assert.Zero(t, re.LastStatus, "no attempt got an HTTP response")
		assert.Contains(t, err.Error(), "connection refused (attempts: 4, last status: 0, no HTTP response)")
	})
}

func TestRetryTransport_DoesNotRetryForbidden(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c, count := retryClient(retryhttp.AttemptTimeout,
			func(_ int32, req *http.Request) (*http.Response, error) {
				return fakeResponse(req, http.StatusForbidden, "forbidden"), nil
			})

		_, err := c.Versions(t.Context(), "example.com/m")
		require.ErrorIs(t, err, pkgsite.ErrUnexpectedStatus)
		assert.Equal(t, int32(1), count.Load(), "403 is terminal and must not be retried")
		var re *retryhttp.Error
		require.ErrorAs(t, err, &re)
		assert.Equal(t, 1, re.Attempts)
		assert.Equal(t, http.StatusForbidden, re.LastStatus)
	})
}

// TestRetryTransport_RetriesTooManyRequests covers both shapes of 429
// pkg.go.dev returns: one carrying a Retry-After header and a bare
// text/html one without it (golang/go#78590 caught the two back-to-back).
// The fake clock lets each case assert the delay that distinguishes the
// Retry-After path from the backoff fallback. The bare case also confirms
// a non-JSON 429 body doesn't break the eventual success decode.
func TestRetryTransport_RetriesTooManyRequests(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		setHeader  func(r *http.Response)
		minElapsed time.Duration // asserted when > 0
		maxElapsed time.Duration // asserted when > 0
	}{
		{
			name:       "honors Retry-After header",
			setHeader:  func(r *http.Response) { r.Header.Set("Retry-After", "30") },
			minElapsed: 20 * time.Second, // 30 s Retry-After, minus jitter
		},
		{
			name:       "falls back to backoff without Retry-After",
			setHeader:  func(r *http.Response) { r.Header.Set("Content-Type", "text/html") },
			maxElapsed: 5 * time.Second, // ~1 s initial backoff, not tens of seconds
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				c, count := retryClient(retryhttp.AttemptTimeout,
					func(attempt int32, req *http.Request) (*http.Response, error) {
						if attempt == 1 {
							r := fakeResponse(req, http.StatusTooManyRequests, "rate exceeded")
							tc.setHeader(r)
							return r, nil
						}
						return fakeResponse(req, http.StatusOK, retryOKBody), nil
					})

				start := time.Now()
				got, err := c.Versions(t.Context(), "example.com/m")
				require.NoError(t, err)
				require.Len(t, got, 1)
				assert.Equal(t, int32(2), count.Load())
				if tc.minElapsed > 0 {
					assert.GreaterOrEqual(t, time.Since(start), tc.minElapsed)
				}
				if tc.maxElapsed > 0 {
					assert.Less(t, time.Since(start), tc.maxElapsed)
				}
			})
		})
	}
}

func TestRetryTransport_DoesNotRetryNotFound(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c, count := retryClient(retryhttp.AttemptTimeout,
			func(_ int32, req *http.Request) (*http.Response, error) {
				return fakeResponse(req, http.StatusNotFound, "not found"), nil
			})

		_, err := c.Versions(t.Context(), "example.com/private")
		require.ErrorIs(t, err, pkgsite.ErrNotFound)
		assert.Equal(t, int32(1), count.Load(), "404 is terminal and must not be retried")
	})
}

func TestRetryTransport_RetriesPerAttemptTimeout(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		const attemptTimeout = time.Second
		c, count := retryClient(attemptTimeout,
			func(_ int32, req *http.Request) (*http.Response, error) {
				// Block past the per-attempt timeout on the fake clock, but
				// unblock promptly once the timeout cancels the attempt's
				// context, so no goroutine leaks out of the bubble.
				select {
				case <-time.After(2 * attemptTimeout):
					return fakeResponse(req, http.StatusOK, retryOKBody), nil
				case <-req.Context().Done():
					return nil, req.Context().Err()
				}
			})

		_, err := c.Versions(t.Context(), "example.com/slow")
		require.Error(t, err)
		assert.Equal(t, int32(retryhttp.MaxRetries+1), count.Load(), "each timed-out attempt should be retried")
	})
}
