// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

package pkgsite_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.tbhb.dev/gomodscan/internal/pkgsite"
	"go.tbhb.dev/gomodscan/internal/retryhttp"
)

// The in-memory clients never dial these. They name closed loopback ports, so
// a mutant that drops the injected client gets a refused connection at once.
// A named host would make it wait on DNS in a sandbox with no network.
const (
	unreachableURL = "http://127.0.0.1:1"
	configuredHost = "127.0.0.1:2"
	configuredURL  = "http://" + configuredHost
)

// mustWrite writes body to w and records any error against t.
// The httptest handlers run in their own goroutine. t.Errorf is
// allowed from that context: it records the failure without panicking.
func mustWrite(t *testing.T, writer http.ResponseWriter, body string) {
	t.Helper()

	_, err := writer.Write([]byte(body))
	if err != nil {
		t.Errorf("write response body: %v", err)
	}
}

// requestBudget caps the requests a test server answers.
const requestBudget = 20

// boundedHandler answers like next for the first `requestBudget` requests and
// with 410 Gone after that. Paging forever ends in an error.
func boundedHandler(next http.HandlerFunc) http.HandlerFunc {
	var served atomic.Int32

	return func(writer http.ResponseWriter, req *http.Request) {
		if served.Add(1) > requestBudget {
			http.Error(writer, "request budget spent", http.StatusGone)

			return
		}

		next(writer, req)
	}
}

// versionsCase drives one TestVersions subtest. Each case supplies a
// handler, optional client overrides, the module path under test, an
// error matcher set, and a verifier for the success path.
type versionsCase struct {
	handler    http.HandlerFunc
	clientOpts func(client *pkgsite.Client)
	verify     func(t *testing.T, got []pkgsite.ModuleVersion)
	name       string
	module     string
	errSubstr  string
	wantErr    []error
	notWantErr []error
}

//nolint:dupl,funlen // scenarios repeat steps in one function that holds the whole table
func TestVersions(t *testing.T) {
	t.Parallel()

	const cobraModule = "github.com/spf13/cobra"

	singlePageBody := `{
		"items": [
			{"modulePath":"` + cobraModule + `","version":"v1.10.2",
				"latestVersion":"v1.10.2",
				"deprecated":false,
				"retracted":false,"commitTime":"2025-12-03T23:51:15Z"},
			{"modulePath":"` + cobraModule + `","version":"v1.10.1",
				"latestVersion":"v1.10.2",
				"deprecated":false,
				"retracted":false,"commitTime":"2025-09-01T16:19:51Z"}
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
			{"modulePath":"` + oldAndBustedModule + `","version":"v2.0.0",
				"latestVersion":"v2.0.0",
				"deprecated":true,"deprecationReason":"use v3",
				"retracted":false},
			{"modulePath":"` + oldAndBustedModule + `","version":"v1.0.1",
				"latestVersion":"v2.0.0",
				"deprecated":true,"deprecationReason":"use v3",
				"retracted":true,"retractionReason":"breaking checksum"}
		],
		"total": 2
	}`

	const customUA = "depscan-test/0"

	cases := []versionsCase{
		{
			name:   "single page returns all items and headers match contract",
			module: cobraModule,
			handler: func(writer http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/versions/"+cobraModule, r.URL.Path)
				assert.Equal(t, "200", r.URL.Query().Get("limit"))
				assert.Empty(t, r.URL.Query().Get("token"))
				assert.Equal(t, pkgsite.DefaultUserAgent, r.Header.Get("User-Agent"))
				writer.Header().Set("Content-Type", "application/json")
				mustWrite(t, writer, singlePageBody)
			},
			verify: func(t *testing.T, got []pkgsite.ModuleVersion) {
				t.Helper()
				require.Len(t, got, 2)
				assert.Equal(t, "v1.10.2", got[0].Version)
				assert.Equal(t, "v1.10.2", got[0].LatestVersion)
				assert.False(t, got[0].Retracted)
				assert.False(t, got[0].Deprecated)
			},
			clientOpts: nil,
			errSubstr:  "",
			wantErr:    nil,
			notWantErr: nil,
		},
		{
			name:   "pagination walks every nextPageToken until exhaustion",
			module: manyVersionsModule,
			handler: func(writer http.ResponseWriter, r *http.Request) {
				token := r.URL.Query().Get("token")

				body, present := pageBodies[token]
				if !present {
					t.Errorf("unexpected token %q", token)

					return
				}

				writer.Header().Set("Content-Type", "application/json")
				mustWrite(t, writer, body)
			},
			verify: func(t *testing.T, got []pkgsite.ModuleVersion) {
				t.Helper()
				require.Len(t, got, 3)
				assert.Equal(t,
					[]string{"v0.3.0", "v0.2.0", "v0.1.0"},
					[]string{got[0].Version, got[1].Version, got[2].Version},
				)
			},
			clientOpts: nil,
			errSubstr:  "",
			wantErr:    nil,
			notWantErr: nil,
		},
		{
			name:   "deprecation and retraction fields decode verbatim",
			module: oldAndBustedModule,
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				mustWrite(t, writer, deprecatedRetractedBody)
			},
			verify: func(t *testing.T, got []pkgsite.ModuleVersion) {
				t.Helper()
				require.Len(t, got, 2)
				assert.True(t, got[0].Deprecated)
				assert.Equal(t, "use v3", got[0].DeprecationReason)
				assert.True(t, got[1].Retracted)
				assert.Equal(t, "breaking checksum", got[1].RetractionReason)
			},
			clientOpts: nil,
			errSubstr:  "",
			wantErr:    nil,
			notWantErr: nil,
		},
		{
			name:   "404 wraps ErrNotFound",
			module: "example.com/private/repo",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				http.Error(writer, "not found", http.StatusNotFound)
			},
			wantErr:    []error{pkgsite.ErrNotFound},
			clientOpts: nil,
			verify:     nil,
			errSubstr:  "",
			notWantErr: nil,
		},
		{
			name:   "5xx wraps ErrUnexpectedStatus",
			module: "example.com/whatever",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				http.Error(writer, "boom", http.StatusInternalServerError)
			},
			// The test client makes one plain attempt, so this case exercises the
			// status-to-error mapping. The retry tests below cover retrying.
			clientOpts: nil,
			wantErr:    []error{pkgsite.ErrUnexpectedStatus},
			notWantErr: []error{pkgsite.ErrNotFound},
			verify:     nil,
			errSubstr:  "",
		},
		{
			name:   "malformed JSON surfaces as a decode error",
			module: "example.com/garbage",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				mustWrite(t, writer, "not json at all")
			},
			errSubstr:  "decode",
			clientOpts: nil,
			verify:     nil,
			wantErr:    nil,
			notWantErr: nil,
		},
		{
			name:   "custom User-Agent reaches the server unchanged",
			module: "example.com/whatever",
			handler: func(writer http.ResponseWriter, r *http.Request) {
				assert.Equal(t, customUA, r.Header.Get("User-Agent"))
				writer.Header().Set("Content-Type", "application/json")
				mustWrite(t, writer, `{"items":[],"total":0}`)
			},
			clientOpts: func(client *pkgsite.Client) { client.UserAgent = customUA },
			verify:     nil,
			errSubstr:  "",
			wantErr:    nil,
			notWantErr: nil,
		},
		{
			name:   "non-advancing nextPageToken is refused instead of looping",
			module: "example.com/stuck",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				// Hand back the same nextPageToken on every request. A
				// client that followed it would page forever; Versions must
				// bail out with ErrStalePageToken after one repeat.
				writer.Header().Set("Content-Type", "application/json")
				mustWrite(t, writer, `{
					"items": [{"modulePath":"example.com/stuck","version":"v1.0.0"}],
					"total": 1,
					"nextPageToken": "STUCK"
				}`)
			},
			wantErr:    []error{pkgsite.ErrStalePageToken},
			clientOpts: nil,
			verify:     nil,
			errSubstr:  "",
			notWantErr: nil,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			runVersionsCase(t, testCase)
		})
	}
}

// runVersionsCase wires the case's handler into an httptest server
// and points a Client at it. The Versions call and the post-call
// assertions then use the case's expectations.
func runVersionsCase(t *testing.T, testCase versionsCase) {
	t.Helper()

	srv := httptest.NewServer(boundedHandler(testCase.handler))
	t.Cleanup(srv.Close)

	client := &pkgsite.Client{
		BaseURL:    srv.URL,
		HTTPClient: &http.Client{Transport: serverOnlyTransport(srv), CheckRedirect: nil, Jar: nil, Timeout: 0},
		UserAgent:  "",
	}
	if testCase.clientOpts != nil {
		testCase.clientOpts(client)
	}

	got, err := client.Versions(t.Context(), testCase.module)

	hasErrExpectations := len(testCase.wantErr) > 0 || len(testCase.notWantErr) > 0 || testCase.errSubstr != ""
	if !hasErrExpectations {
		require.NoError(t, err)

		if testCase.verify != nil {
			testCase.verify(t, got)
		}

		return
	}

	require.Error(t, err)

	for _, want := range testCase.wantErr {
		require.ErrorIs(t, err, want)
	}

	for _, notWant := range testCase.notWantErr {
		require.NotErrorIs(t, err, notWant)
	}

	if testCase.errSubstr != "" {
		assert.Contains(t, err.Error(), testCase.errSubstr)
	}
}

// TestVersions_StalePageTokenReportsItsRequest checks that a repeated page
// token reports the attempt and the 200 of the request that delivered it.
// Zero values would read as no HTTP response.
//
//nolint:dupl // test scenarios repeat the same arrange and assert steps
func TestVersions_StalePageTokenReportsItsRequest(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(boundedHandler(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		mustWrite(t, writer, `{"items":[],"total":0,"nextPageToken":"STUCK"}`)
	}))
	t.Cleanup(srv.Close)

	transport := retryhttp.NewTransport(
		serverOnlyTransport(srv), retryhttp.InitialDelay, retryhttp.MaxDelay, retryhttp.AttemptTimeout,
	)
	client := newCachedClient(srv.URL, transport)
	_, err := client.Versions(t.Context(), "example.com/stuck")
	require.ErrorIs(t, err, pkgsite.ErrStalePageToken)

	var re *retryhttp.Error
	require.ErrorAs(t, err, &re)
	assert.Equal(t, 1, re.Attempts)
	assert.Equal(t, http.StatusOK, re.LastStatus)
	assert.Contains(t, err.Error(), "example.com/stuck (attempts: 1, last status: 200)")
}

// TestVersions_ContextCancelled lives outside the table because
// the timing dance (slow handler vs. short deadline) doesn't fit
// the synchronous case structure the table assumes.
func TestVersions_ContextCancelled(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		writer.Header().Set("Content-Type", "application/json")
		mustWrite(t, writer, `{"items":[],"total":0}`)
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	t.Cleanup(cancel)

	client := &pkgsite.Client{BaseURL: srv.URL, HTTPClient: nil, UserAgent: ""}
	_, err := client.Versions(ctx, "example.com/slow")
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline"),
		"expected deadline-exceeded, got %v", err,
	)
}

// The retry tests below drive the failsafe-go retry/backoff policy
// through the public Versions call, inside a testing/synctest bubble with
// an in-memory transport. The bubble's fake clock advances every backoff
// or Retry-After wait instantly. The tests reuse the real production timing
// constants yet finish in microseconds with deterministic results.
// The export_test.go shim reaches the unexported transport builder.

const retryOKBody = `{"items":[{"modulePath":"example.com/m","version":"v1.0.0","latestVersion":"v1.0.0"}],"total":1}`

// errConnRefused represents a transient network error the in-memory
// transport surfaces on every attempt.
var errConnRefused = errors.New("connection refused")

// roundTripperFunc adapts a function to an http.RoundTripper. It replaces
// the network so the retry policy runs under a fake clock with no
// real I/O. (synctest doesn't advance time across real network blocks.)
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// fakeResponse builds a minimal *http.Response for the in-memory transport.
func fakeResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode:       status,
		Status:           http.StatusText(status),
		Header:           make(http.Header),
		Body:             io.NopCloser(strings.NewReader(body)),
		Request:          req,
		Proto:            "",
		ProtoMajor:       0,
		ProtoMinor:       0,
		ContentLength:    0,
		TransferEncoding: nil,
		Close:            false,
		Uncompressed:     false,
		Trailer:          nil,
		TLS:              nil,
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
	client := &pkgsite.Client{
		BaseURL: unreachableURL,
		HTTPClient: &http.Client{
			Transport: retryhttp.NewTransport(
				inner, retryhttp.InitialDelay, retryhttp.MaxDelay, attemptTimeout,
			),
			CheckRedirect: nil,
			Jar:           nil,
			Timeout:       0,
		},
		UserAgent: "",
	}

	return client, &count
}

func TestRetryTransport_RetriesServerErrorThenSucceeds(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		client, count := retryClient(retryhttp.AttemptTimeout,
			func(attempt int32, req *http.Request) (*http.Response, error) {
				if attempt <= retryhttp.MaxRetries {
					return fakeResponse(req, http.StatusInternalServerError, "boom"), nil
				}

				return fakeResponse(req, http.StatusOK, retryOKBody), nil
			})

		got, err := client.Versions(t.Context(), "example.com/m")
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, int32(retryhttp.MaxRetries+1), count.Load(), "should retry until the success response")
	})
}

//nolint:dupl // test scenarios repeat the same arrange and assert steps
func TestRetryTransport_ExhaustsRetriesOnPersistentServerError(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		client, count := retryClient(retryhttp.AttemptTimeout,
			func(_ int32, req *http.Request) (*http.Response, error) {
				return fakeResponse(req, http.StatusServiceUnavailable, "still broken"), nil
			})

		_, err := client.Versions(t.Context(), "example.com/m")
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
		client, count := retryClient(retryhttp.AttemptTimeout,
			func(_ int32, _ *http.Request) (*http.Response, error) {
				return nil, errConnRefused
			})

		_, err := client.Versions(t.Context(), "example.com/m")
		require.ErrorIs(t, err, errConnRefused)

		var re *retryhttp.Error
		require.ErrorAs(t, err, &re)
		assert.Equal(t, retryhttp.MaxRetries+1, re.Attempts)
		assert.Equal(t, int32(retryhttp.MaxRetries+1), count.Load())
		assert.Zero(t, re.LastStatus, "no attempt got an HTTP response")
		assert.Contains(t, err.Error(), "connection refused (attempts: 4, last status: 0, no HTTP response)")
	})
}

//nolint:dupl // test scenarios repeat the same arrange and assert steps
func TestRetryTransport_DoesNotRetryForbidden(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		client, count := retryClient(retryhttp.AttemptTimeout,
			func(_ int32, req *http.Request) (*http.Response, error) {
				return fakeResponse(req, http.StatusForbidden, "forbidden"), nil
			})

		_, err := client.Versions(t.Context(), "example.com/m")
		require.ErrorIs(t, err, pkgsite.ErrUnexpectedStatus)
		assert.Equal(t, int32(1), count.Load(), "403 is terminal and must not be retried")

		var re *retryhttp.Error
		require.ErrorAs(t, err, &re)
		assert.Equal(t, 1, re.Attempts)
		assert.Equal(t, http.StatusForbidden, re.LastStatus)
	})
}

// TestRetryTransport_RetriesTooManyRequests covers both shapes of 429
// pkg.go.dev returns: one with a Retry-After header and a bare
// text/html one without it (golang/go#78590 caught the two back-to-back).
// The fake clock lets each case assert the delay that distinguishes the
// Retry-After path from the backoff fallback. The bare case also confirms
// a non-JSON 429 body doesn't break the eventual success decode.
func TestRetryTransport_RetriesTooManyRequests(t *testing.T) {
	t.Parallel()

	cases := []struct {
		setHeader  func(r *http.Response)
		name       string
		minElapsed time.Duration
		maxElapsed time.Duration
	}{
		{
			name:       "honors Retry-After header",
			setHeader:  func(r *http.Response) { r.Header.Set("Retry-After", "30") },
			minElapsed: 20 * time.Second, // 30 s Retry-After, minus jitter
			maxElapsed: 0,
		},
		{
			name:       "falls back to backoff without Retry-After",
			setHeader:  func(r *http.Response) { r.Header.Set("Content-Type", "text/html") },
			minElapsed: 0,
			maxElapsed: 5 * time.Second, // ~1 s initial backoff, not tens of seconds
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				client, count := retryClient(retryhttp.AttemptTimeout,
					func(attempt int32, req *http.Request) (*http.Response, error) {
						if attempt == 1 {
							r := fakeResponse(req, http.StatusTooManyRequests, "rate exceeded")
							testCase.setHeader(r)

							return r, nil
						}

						return fakeResponse(req, http.StatusOK, retryOKBody), nil
					})

				start := time.Now()
				got, err := client.Versions(t.Context(), "example.com/m")
				require.NoError(t, err)
				require.Len(t, got, 1)
				assert.Equal(t, int32(2), count.Load())

				if testCase.minElapsed > 0 {
					assert.GreaterOrEqual(t, time.Since(start), testCase.minElapsed)
				}

				if testCase.maxElapsed > 0 {
					assert.Less(t, time.Since(start), testCase.maxElapsed)
				}
			})
		})
	}
}

//nolint:dupl // test scenarios repeat the same arrange and assert steps
func TestRetryTransport_DoesNotRetryNotFound(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		client, count := retryClient(retryhttp.AttemptTimeout,
			func(_ int32, req *http.Request) (*http.Response, error) {
				return fakeResponse(req, http.StatusNotFound, "not found"), nil
			})

		_, err := client.Versions(t.Context(), "example.com/private")
		require.ErrorIs(t, err, pkgsite.ErrNotFound)
		assert.Equal(t, int32(1), count.Load(), "404 is terminal and must not be retried")
	})
}

func TestRetryTransport_RetriesPerAttemptTimeout(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		const attemptTimeout = time.Second

		client, count := retryClient(attemptTimeout,
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

		_, err := client.Versions(t.Context(), "example.com/slow")
		require.Error(t, err)
		assert.Equal(t, int32(retryhttp.MaxRetries+1), count.Load(), "each timed-out attempt should be retried")
	})
}

// unusableBaseURL parses as a path. A module path with an invalid escape makes
// the join keep that path, and the result reads back as a host with an escape
// the URL parser rejects.
const unusableBaseURL = "/%2fa "

func TestVersions_RejectsAnUnparsableBaseURL(t *testing.T) {
	t.Parallel()

	client := newCachedClient("://missing-scheme", roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errConnRefused
	}))
	_, err := client.Versions(t.Context(), "example.com/m")
	require.ErrorContains(t, err, "parse base URL")

	var urlErr *url.Error
	require.ErrorAs(t, err, &urlErr)
}

func TestVersions_RejectsABaseURLThatYieldsNoRequest(t *testing.T) {
	t.Parallel()

	client := newCachedClient(unusableBaseURL, roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errConnRefused
	}))
	_, err := client.Versions(t.Context(), "example.com/m%zz")
	require.ErrorContains(t, err, "build request for example.com/m%zz")

	var urlErr *url.Error
	require.ErrorAs(t, err, &urlErr)
}

func TestVersions_UsesTheDefaultBaseURL(t *testing.T) {
	t.Parallel()

	var gotHost string

	client := &pkgsite.Client{
		BaseURL: "",
		HTTPClient: &http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				gotHost = req.URL.Scheme + "://" + req.URL.Host

				return fakeResponse(req, http.StatusOK, `{"items":[],"total":0,"nextPageToken":""}`), nil
			}),
			CheckRedirect: nil,
			Jar:           nil,
			Timeout:       0,
		},
		UserAgent: "",
	}

	got, err := client.Versions(t.Context(), "example.com/m")
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Equal(t, pkgsite.DefaultBaseURL, gotHost)
}

func TestVersions_SendsTheJSONHeaders(t *testing.T) {
	t.Parallel()

	var gotAccept string

	client := newCachedClient(unreachableURL, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		gotAccept = req.Header.Get("Accept")

		return fakeResponse(req, http.StatusOK, retryOKBody), nil
	}))

	_, err := client.Versions(t.Context(), "example.com/m")
	require.NoError(t, err)
	assert.Equal(t, "application/json", gotAccept)
}

func TestVersions_UsesTheConfiguredClientAndBaseURL(t *testing.T) {
	t.Parallel()

	var gotHost string

	client := newCachedClient(
		configuredURL,
		roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			gotHost = req.URL.Host

			return fakeResponse(req, http.StatusOK, retryOKBody), nil
		}),
	)

	_, err := client.Versions(t.Context(), "example.com/m")
	require.NoError(t, err)
	assert.Equal(t, configuredHost, gotHost)
}

func TestVersions_WrapsTheTransportError(t *testing.T) {
	t.Parallel()

	client := newCachedClient(unreachableURL, roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errConnRefused
	}))

	_, err := client.Versions(t.Context(), "example.com/m")
	require.ErrorIs(t, err, errConnRefused)

	var re *retryhttp.Error
	require.ErrorAs(t, err, &re)
	assert.Zero(t, re.LastStatus)
}

func TestVersions_WrapsTheDecodeError(t *testing.T) {
	t.Parallel()

	client := newCachedClient(unreachableURL, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return fakeResponse(req, http.StatusOK, "not json"), nil
	}))

	_, err := client.Versions(t.Context(), "example.com/m")

	var syntaxErr *json.SyntaxError
	require.ErrorAs(t, err, &syntaxErr)
}

// serverOnlyTransport answers a request for any host but the test server's
// with a 400, which no retry policy repeats. A fault in the base URL then fails
// a test at once, on a response that arrives immediately.
func serverOnlyTransport(srv *httptest.Server) http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != srv.Listener.Addr().String() {
			return fakeResponse(req, http.StatusBadRequest, "not the test server"), nil
		}

		return srv.Client().Transport.RoundTrip(req)
	})
}
