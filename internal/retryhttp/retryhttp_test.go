// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

package retryhttp_test

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbhb-dev/gomodscan/internal/retryhttp"
)

// The tests below drive failsafe-go's retry/backoff policy through a real
// http.Client whose transport wraps retryhttp.NewTransport around an in-memory
// RoundTripper, inside a testing/synctest bubble. The bubble's fake clock
// advances every backoff or Retry-After wait instantly, so the tests reuse the
// real production timing constants yet finish in microseconds and stay
// deterministic. (synctest doesn't advance time across real network blocks, so
// the in-memory transport stands in for the network.)

const okBody = `{"ok":true}`

// errConnReset stands in for a transient network error the inner transport
// surfaces.
var errConnReset = errors.New("connection reset")

// roundTripperFunc adapts a function to an http.RoundTripper, standing in for
// the network so the retry policy runs under a fake clock with no real I/O.
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

// retryClient builds an http.Client whose transport applies the production
// retry/backoff policy around a counting in-memory transport. It invokes
// respond once per attempt with the 1-based attempt number, and the returned
// counter records how many attempts reached the transport.
func retryClient(
	attemptTimeout time.Duration,
	respond func(attempt int32, req *http.Request) (*http.Response, error),
) (*http.Client, *atomic.Int32) {
	var count atomic.Int32
	inner := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return respond(count.Add(1), req)
	})
	return &http.Client{
		Transport: retryhttp.NewTransport(
			inner, retryhttp.InitialDelay, retryhttp.MaxDelay, attemptTimeout,
		),
	}, &count
}

// get issues a GET through c to a dummy host and returns the response.
func get(t *testing.T, c *http.Client) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.test", nil)
	require.NoError(t, err)
	//nolint:wrapcheck // test helper surfaces the transport's raw error for assertions.
	return c.Do(req)
}

func TestNewTransport_RetriesServerErrorThenSucceeds(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c, count := retryClient(retryhttp.AttemptTimeout,
			func(attempt int32, req *http.Request) (*http.Response, error) {
				if attempt <= retryhttp.MaxRetries {
					return fakeResponse(req, http.StatusInternalServerError, "boom"), nil
				}
				return fakeResponse(req, http.StatusOK, okBody), nil
			})

		resp, err := get(t, c)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, int32(retryhttp.MaxRetries+1), count.Load(), "should retry until the success response")
	})
}

// TestNewTransport_ExhaustsRetriesReturnsFinalResponse pins the
// ReturnLastFailure behavior: once the policy runs out of attempts on a
// persistent retryable status, the transport hands back the final response
// with a nil error rather than a retrypolicy.ExceededError wrapper. The client
// status switches downstream rely on this to map the status onto their own
// errors.
func TestNewTransport_ExhaustsRetriesReturnsFinalResponse(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c, count := retryClient(retryhttp.AttemptTimeout,
			func(_ int32, req *http.Request) (*http.Response, error) {
				return fakeResponse(req, http.StatusServiceUnavailable, "still broken"), nil
			})

		resp, err := get(t, c)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })
		assert.Equal(
			t,
			http.StatusServiceUnavailable,
			resp.StatusCode,
			"the final response should flow through unwrapped",
		)
		assert.Equal(
			t,
			int32(retryhttp.MaxRetries+1),
			count.Load(),
			"should attempt the initial request plus every retry",
		)
	})
}

// TestNewTransport_RetriesTooManyRequests covers both shapes of 429 the
// upstreams return: one carrying a Retry-After header and a bare one without
// it. The fake clock lets each case assert the delay that distinguishes the
// Retry-After path from the backoff fallback.
func TestNewTransport_RetriesTooManyRequests(t *testing.T) {
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
						return fakeResponse(req, http.StatusOK, okBody), nil
					})

				start := time.Now()
				resp, err := get(t, c)
				require.NoError(t, err)
				t.Cleanup(func() { _ = resp.Body.Close() })
				assert.Equal(t, http.StatusOK, resp.StatusCode)
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

func TestNewTransport_DoesNotRetryTerminalStatus(t *testing.T) {
	t.Parallel()
	for _, status := range []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusUnprocessableEntity,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				c, count := retryClient(retryhttp.AttemptTimeout,
					func(_ int32, req *http.Request) (*http.Response, error) {
						return fakeResponse(req, status, "terminal"), nil
					})

				resp, err := get(t, c)
				require.NoError(t, err)
				t.Cleanup(func() { _ = resp.Body.Close() })
				assert.Equal(t, status, resp.StatusCode)
				assert.Equal(t, int32(1), count.Load(), "a terminal 4xx must not be retried")
			})
		})
	}
}

// TestNewTransport_BacksOffExponentially pins the backoff schedule on a
// persistent 5xx without Retry-After. The wait doubles from about 1 s to 4 s
// between the four attempts, 7 s in all, give or take the 25% jitter on each
// step.
func TestNewTransport_BacksOffExponentially(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c, count := retryClient(retryhttp.AttemptTimeout,
			func(_ int32, req *http.Request) (*http.Response, error) {
				return fakeResponse(req, http.StatusBadGateway, "upstream down"), nil
			})

		start := time.Now()
		resp, err := get(t, c)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })
		elapsed := time.Since(start)
		assert.Equal(t, int32(4), count.Load(), "four attempts in all: the initial request plus three retries")
		assert.GreaterOrEqual(t, elapsed, 5250*time.Millisecond, "7 s of backoff, minus jitter")
		assert.LessOrEqual(t, elapsed, 8750*time.Millisecond, "7 s of backoff, plus jitter")
	})
}

func TestWithAttempts_CountsEveryAttempt(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		respond func(attempt int32, req *http.Request) (*http.Response, error)
		want    int
	}{
		{
			name: "persistent 5xx exhausts every attempt",
			respond: func(_ int32, req *http.Request) (*http.Response, error) {
				return fakeResponse(req, http.StatusServiceUnavailable, "still broken"), nil
			},
			want: retryhttp.MaxRetries + 1,
		},
		{
			name: "persistent network error exhausts every attempt",
			respond: func(_ int32, _ *http.Request) (*http.Response, error) {
				return nil, errConnReset
			},
			want: retryhttp.MaxRetries + 1,
		},
		{
			name: "terminal 4xx stops after one attempt",
			respond: func(_ int32, req *http.Request) (*http.Response, error) {
				return fakeResponse(req, http.StatusForbidden, "forbidden"), nil
			},
			want: 1,
		},
		{
			name: "success after one retry counts both attempts",
			respond: func(attempt int32, req *http.Request) (*http.Response, error) {
				if attempt == 1 {
					return fakeResponse(req, http.StatusInternalServerError, "boom"), nil
				}
				return fakeResponse(req, http.StatusOK, okBody), nil
			},
			want: 2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				c, _ := retryClient(retryhttp.AttemptTimeout, tc.respond)
				ctx, attempts := retryhttp.WithAttempts(t.Context())
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.test", nil)
				require.NoError(t, err)

				resp, err := c.Do(req)
				if err == nil {
					t.Cleanup(func() { _ = resp.Body.Close() })
				}
				assert.Equal(t, tc.want, attempts())
			})
		})
	}
}

func TestError(t *testing.T) {
	t.Parallel()

	t.Run("reports the last HTTP status", func(t *testing.T) {
		t.Parallel()
		err := &retryhttp.Error{Err: errConnReset, Attempts: 4, LastStatus: http.StatusServiceUnavailable}
		assert.Equal(t, "connection reset (attempts: 4, last status: 503)", err.Error())
	})

	t.Run("reports a missing HTTP response", func(t *testing.T) {
		t.Parallel()
		err := &retryhttp.Error{Err: errConnReset, Attempts: 4}
		assert.Equal(t, "connection reset (attempts: 4, no HTTP response)", err.Error())
	})

	t.Run("unwraps to the client error", func(t *testing.T) {
		t.Parallel()
		err := fmt.Errorf("lookup: %w", &retryhttp.Error{Err: errConnReset, Attempts: 1})
		require.ErrorIs(t, err, errConnReset)
		var re *retryhttp.Error
		require.ErrorAs(t, err, &re)
		assert.Equal(t, 1, re.Attempts)
	})
}

func TestNewTransport_RetriesPerAttemptTimeout(t *testing.T) {
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
					return fakeResponse(req, http.StatusOK, okBody), nil
				case <-req.Context().Done():
					return nil, req.Context().Err()
				}
			})

		resp, err := get(t, c)
		if resp != nil {
			t.Cleanup(func() { _ = resp.Body.Close() })
		}
		require.Error(t, err)
		assert.Equal(t, int32(retryhttp.MaxRetries+1), count.Load(), "each timed-out attempt should be retried")
	})
}
