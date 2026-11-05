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
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.tbhb.dev/gomodscan/internal/osv"
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

// queryCase drives one TestQuery subtest. Each case supplies a
// handler, optional client overrides, the package and version under
// query, an error matcher set, and a verifier for the success path.
type queryCase struct {
	handler    http.HandlerFunc
	clientOpts func(client *osv.Client)
	verify     func(t *testing.T, got []osv.Vulnerability)
	pkg        osv.Package
	name       string
	version    string
	errSubstr  string
	wantErr    []error
	notWantErr []error
}

//nolint:dupl,funlen // scenarios repeat steps in one function that holds the whole table
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
			handler: func(writer http.ResponseWriter, req *http.Request) {
				assert.Equal(t, "/v1/query", req.URL.Path)
				assert.Equal(t, http.MethodPost, req.Method)
				assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
				assert.Equal(t, osv.DefaultUserAgent, req.Header.Get("User-Agent"))

				var sent struct {
					Version string `json:"version"`
					Package struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					} `json:"package"`
				}

				decErr := json.NewDecoder(req.Body).Decode(&sent)
				if decErr != nil {
					t.Errorf("decode request body: %v", decErr)
				}

				assert.Equal(t, "v1.10.2", sent.Version)
				assert.Equal(t, cobraModule, sent.Package.Name)
				assert.Equal(t, "Go", sent.Package.Ecosystem)
				writer.Header().Set("Content-Type", "application/json")
				mustWrite(t, writer, emptyBody)
			},
			verify: func(t *testing.T, got []osv.Vulnerability) {
				t.Helper()
				assert.Empty(t, got)
			},
			clientOpts: nil,
			errSubstr:  "",
			wantErr:    nil,
			notWantErr: nil,
		},
		{
			name:    "MAL-prefixed advisory decodes verbatim",
			pkg:     osv.Package{Name: flaggedModule, Ecosystem: "Go"},
			version: "v1.2.3",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				mustWrite(t, writer, maliciousBody)
			},
			verify: func(t *testing.T, got []osv.Vulnerability) {
				t.Helper()
				require.Len(t, got, 1)
				assert.Equal(t, "MAL-2025-0001", got[0].ID)
				assert.Equal(t, "Malicious code in v1.2.3", got[0].Summary)
				assert.Equal(t, []string{"GHSA-aaaa-bbbb-cccc"}, got[0].Aliases)
			},
			clientOpts: nil,
			errSubstr:  "",
			wantErr:    nil,
			notWantErr: nil,
		},
		{
			name:    "mixed advisory list preserves order",
			pkg:     osv.Package{Name: mixedModule, Ecosystem: "Go"},
			version: "v0.5.0",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				mustWrite(t, writer, mixedBody)
			},
			verify: func(t *testing.T, got []osv.Vulnerability) {
				t.Helper()
				require.Len(t, got, 2)
				assert.Equal(t,
					[]string{"GO-2025-0042", "MAL-2025-0007"},
					[]string{got[0].ID, got[1].ID},
				)
			},
			clientOpts: nil,
			errSubstr:  "",
			wantErr:    nil,
			notWantErr: nil,
		},
		{
			name:    "non-200 wraps ErrUnexpectedStatus",
			pkg:     osv.Package{Name: "example.com/whatever", Ecosystem: "Go"},
			version: versionV001,
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				http.Error(writer, "boom", http.StatusInternalServerError)
			},
			// The test client makes one plain attempt, so this case exercises the
			// status-to-error mapping. The retry tests below cover retrying.
			clientOpts: nil,
			wantErr:    []error{osv.ErrUnexpectedStatus},
			verify:     nil,
			errSubstr:  "",
			notWantErr: nil,
		},
		{
			name:    "malformed JSON surfaces as a decode error",
			pkg:     osv.Package{Name: "example.com/garbage", Ecosystem: "Go"},
			version: versionV001,
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				mustWrite(t, writer, "not json at all")
			},
			notWantErr: []error{osv.ErrUnexpectedStatus},
			errSubstr:  "decode",
			clientOpts: nil,
			verify:     nil,
			wantErr:    nil,
		},
		{
			name:    "custom User-Agent reaches the server unchanged",
			pkg:     osv.Package{Name: "example.com/whatever", Ecosystem: "Go"},
			version: versionV001,
			handler: func(writer http.ResponseWriter, req *http.Request) {
				assert.Equal(t, customUA, req.Header.Get("User-Agent"))
				writer.Header().Set("Content-Type", "application/json")
				mustWrite(t, writer, emptyBody)
			},
			clientOpts: func(client *osv.Client) { client.UserAgent = customUA },
			verify:     nil,
			errSubstr:  "",
			wantErr:    nil,
			notWantErr: nil,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			runQueryCase(t, testCase)
		})
	}
}

// runQueryCase wires the case's handler into an httptest server and
// points a Client at it. The Query call and the post-call assertions
// then use the case's expectations.
func runQueryCase(t *testing.T, testCase queryCase) {
	t.Helper()

	srv := httptest.NewServer(testCase.handler)
	t.Cleanup(srv.Close)

	client := &osv.Client{
		BaseURL:    srv.URL,
		HTTPClient: &http.Client{Transport: serverOnlyTransport(srv), CheckRedirect: nil, Jar: nil, Timeout: 0},
		UserAgent:  "",
	}
	if testCase.clientOpts != nil {
		testCase.clientOpts(client)
	}

	got, err := client.Query(t.Context(), testCase.pkg, testCase.version)

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

// TestQuery_ContextCancelled lives outside the table because the
// timing dance (slow handler vs. short deadline) doesn't fit the
// synchronous cases the table assumes.
func TestQuery_ContextCancelled(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		writer.Header().Set("Content-Type", "application/json")
		mustWrite(t, writer, `{"vulns":[]}`)
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	t.Cleanup(cancel)

	client := &osv.Client{BaseURL: srv.URL, HTTPClient: nil, UserAgent: ""}
	_, err := client.Query(ctx, osv.Package{Name: "example.com/slow", Ecosystem: "Go"}, versionV001)
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline"),
		"expected deadline-exceeded, got %v", err,
	)
}

// The retry tests below drive the failsafe-go retry/backoff policy through the
// public Query call, inside a testing/synctest bubble with an in-memory
// transport. The bubble's fake clock advances every backoff wait instantly.
// The tests reuse the real production timing constants yet finish in
// microseconds with deterministic results. The retryhttp package tests cover
// the transport's own behavior (Retry-After handling, per-attempt timeout,
// jitter); these confirm Query composes with the shared transport and maps
// a persistent failure onto ErrUnexpectedStatus.

const retryVulnsBody = `{"vulns":[{"id":"MAL-2025-0001","summary":"Malicious code"}]}`

// roundTripperFunc adapts a function to an http.RoundTripper. It replaces the
// network and lets the retry policy run under a fake clock without real I/O.
// (synctest doesn't advance time across real network blocks.)
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

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
// respond once per attempt with the 1-based attempt number, and the returned
// counter records how many attempts reached the transport.
func retryClient(
	respond func(attempt int32, req *http.Request) (*http.Response, error),
) (*osv.Client, *atomic.Int32) {
	var count atomic.Int32

	inner := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return respond(count.Add(1), req)
	})
	client := &osv.Client{
		BaseURL: unreachableURL,
		HTTPClient: &http.Client{
			Transport: retryhttp.NewTransport(
				inner, retryhttp.InitialDelay, retryhttp.MaxDelay, retryhttp.AttemptTimeout,
			),
			CheckRedirect: nil,
			Jar:           nil,
			Timeout:       0,
		},
		UserAgent: "",
	}

	return client, &count
}

func TestQuery_RetriesServerErrorThenSucceeds(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		client, count := retryClient(func(attempt int32, req *http.Request) (*http.Response, error) {
			if attempt <= retryhttp.MaxRetries {
				return fakeResponse(req, http.StatusInternalServerError, "boom"), nil
			}

			return fakeResponse(req, http.StatusOK, retryVulnsBody), nil
		})

		got, err := client.Query(t.Context(), osv.Package{Name: modM, Ecosystem: "Go"}, "v1.0.0")
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "MAL-2025-0001", got[0].ID)
		assert.Equal(t, int32(retryhttp.MaxRetries+1), count.Load(), "should retry until the success response")
	})
}

//nolint:dupl // test scenarios repeat the same arrange and assert steps
func TestQuery_ExhaustsRetriesOnPersistentServerError(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		client, count := retryClient(func(_ int32, req *http.Request) (*http.Response, error) {
			return fakeResponse(req, http.StatusServiceUnavailable, "still broken"), nil
		})

		_, err := client.Query(t.Context(), osv.Package{Name: modM, Ecosystem: "Go"}, "v1.0.0")
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

//nolint:dupl // test scenarios repeat the same arrange and assert steps
func TestQuery_DoesNotRetryTerminalStatus(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		client, count := retryClient(func(_ int32, req *http.Request) (*http.Response, error) {
			return fakeResponse(req, http.StatusBadRequest, "bad request"), nil
		})

		_, err := client.Query(t.Context(), osv.Package{Name: modM, Ecosystem: "Go"}, "v1.0.0")
		require.ErrorIs(t, err, osv.ErrUnexpectedStatus)
		assert.Equal(t, int32(1), count.Load(), "a terminal 4xx must not be retried")

		var re *retryhttp.Error
		require.ErrorAs(t, err, &re)
		assert.Equal(t, 1, re.Attempts)
		assert.Equal(t, http.StatusBadRequest, re.LastStatus)
	})
}

const (
	versionV001 = "v0.0.1"
	modM        = "example.com/m"
)

func TestQuery_RejectsAnUnparsableBaseURL(t *testing.T) {
	t.Parallel()

	client := inMemoryClient("://missing-scheme", func(*http.Request) (*http.Response, error) {
		return nil, errConnRefused
	})
	_, err := client.Query(t.Context(), osv.Package{Name: "example.com/m", Ecosystem: "Go"}, "v1.0.0")
	require.ErrorContains(t, err, "parse base URL")

	var urlErr *url.Error
	require.ErrorAs(t, err, &urlErr)
}

func TestQuery_UsesTheDefaultBaseURL(t *testing.T) {
	t.Parallel()

	var gotURL string

	client := &osv.Client{
		BaseURL: "",
		HTTPClient: &http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				gotURL = req.URL.String()

				return fakeResponse(req, http.StatusOK, `{"vulns":[]}`), nil
			}),
			CheckRedirect: nil,
			Jar:           nil,
			Timeout:       0,
		},
		UserAgent: "",
	}

	got, err := client.Query(t.Context(), osv.Package{Name: "example.com/m", Ecosystem: "Go"}, "v1.0.0")
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Equal(t, osv.DefaultBaseURL+"/v1/query", gotURL)
}

var errConnRefused = errors.New("connection refused")

func TestQuery_SendsTheJSONHeaders(t *testing.T) {
	t.Parallel()

	var gotAccept, gotContentType string

	client := inMemoryClient(unreachableURL, func(req *http.Request) (*http.Response, error) {
		gotAccept, gotContentType = req.Header.Get("Accept"), req.Header.Get("Content-Type")

		return fakeResponse(req, http.StatusOK, `{"vulns":[]}`), nil
	})

	_, err := client.Query(t.Context(), osv.Package{Name: modM, Ecosystem: "Go"}, versionV001)
	require.NoError(t, err)
	assert.Equal(t, "application/json", gotAccept)
	assert.Equal(t, "application/json", gotContentType)
}

func TestQuery_UsesTheConfiguredClientAndBaseURL(t *testing.T) {
	t.Parallel()

	var gotHost string

	client := inMemoryClient(configuredURL, func(req *http.Request) (*http.Response, error) {
		gotHost = req.URL.Host

		return fakeResponse(req, http.StatusOK, `{"vulns":[]}`), nil
	})

	_, err := client.Query(t.Context(), osv.Package{Name: modM, Ecosystem: "Go"}, versionV001)
	require.NoError(t, err)
	assert.Equal(t, configuredHost, gotHost)
}

func TestQuery_WrapsTheTransportError(t *testing.T) {
	t.Parallel()

	client := inMemoryClient(unreachableURL, func(*http.Request) (*http.Response, error) {
		return nil, errConnRefused
	})

	_, err := client.Query(t.Context(), osv.Package{Name: modM, Ecosystem: "Go"}, versionV001)
	require.ErrorIs(t, err, errConnRefused)

	var re *retryhttp.Error
	require.ErrorAs(t, err, &re)
	assert.Zero(t, re.LastStatus)
}

func TestQuery_WrapsTheDecodeError(t *testing.T) {
	t.Parallel()

	client := inMemoryClient(unreachableURL, func(req *http.Request) (*http.Response, error) {
		return fakeResponse(req, http.StatusOK, "not json"), nil
	})

	_, err := client.Query(t.Context(), osv.Package{Name: modM, Ecosystem: "Go"}, versionV001)

	var syntaxErr *json.SyntaxError
	require.ErrorAs(t, err, &syntaxErr)
}

// inMemoryClient builds a Client over a plain http.Client that hands each
// request to respond. It retries nothing and reaches no network.
func inMemoryClient(baseURL string, respond roundTripperFunc) *osv.Client {
	return &osv.Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Transport:     respond,
			CheckRedirect: nil,
			Jar:           nil,
			Timeout:       0,
		},
		UserAgent: "",
	}
}

// serverOnlyTransport answers a request for any host but the test server's
// with a 400, which no retry policy repeats. A fault in the base URL then fails
// a test at once, on a response that arrives immediately.
func serverOnlyTransport(srv *httptest.Server) roundTripperFunc {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != srv.Listener.Addr().String() {
			return fakeResponse(req, http.StatusBadRequest, "not the test server"), nil
		}

		return srv.Client().Transport.RoundTrip(req)
	})
}
