// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

// Package retryhttp builds the retry/backoff [http.RoundTripper] that the
// OSV and pkg.go.dev clients share. Both upstreams answer an occasional
// request with a 429, a transient 5xx, or a dropped connection, and a scan
// walks hundreds of modules, so one transient failure shouldn't end the run.
// [NewTransport] re-issues those attempts with exponential backoff and honors
// a Retry-After header when the upstream sends one. It leaves terminal
// responses alone. Each client's own status switch still maps a 404 or a 400
// onto its own error. [WithAttempts] and [Error] let a client report how
// many attempts a request that still failed made, and what it got last.
package retryhttp

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/failsafe-go/failsafe-go/failsafehttp"
	"github.com/failsafe-go/failsafe-go/timeout"
)

const (
	// MaxRetries bounds how many times the transport re-issues a request
	// after a retryable response (429 or most 5xx) or a transient network
	// error. A request gets MaxRetries+1 attempts in all. Three retries
	// back off about 1 s, 2 s, then 4 s, which rides out a short upstream
	// blip while holding the worst-case per-request wait down when an
	// upstream throttles the whole host.
	MaxRetries = 3

	// InitialDelay sets the first exponential-backoff step the transport
	// waits after a 429 that arrives without a Retry-After header, which the
	// upstreams send inconsistently. With the header present, the transport
	// honors it instead.
	InitialDelay = 1 * time.Second

	// MaxDelay caps the exponential backoff. The ceiling matches the
	// Retry-After value pkg.go.dev returns when it does send one.
	MaxDelay = 30 * time.Second

	// AttemptTimeout caps each HTTP attempt. The transport composes this
	// timeout inside the retry policy. Each attempt gets its own deadline, and
	// the timeout doesn't cut short a long Retry-After wait between attempts.
	AttemptTimeout = 30 * time.Second

	// jitterFactor randomizes each backoff delay so a batch of lookups
	// doesn't retry at the same moment.
	jitterFactor = 0.25
)

// NewTransport wraps inner with a per-attempt timeout plus retry/backoff.
// failsafehttp.NewRetryPolicyBuilder already retries the transient
// responses (a 429 or most 5xx) along with transient network errors, and
// honors a Retry-After header. On top, this adds exponential backoff for the
// no-header case plus a jitter factor, under a ceiling of MaxRetries
// retries. Composing the
// timeout policy inside the retry policy bounds each attempt rather than the
// whole sequence. Callers pass the durations, so tests drive the policy with
// their own timing.
//
// ReturnLastFailure keeps retries transparent. Once the policy exhausts its
// attempts and gives up, the transport returns the final response (or error)
// directly rather than a retrypolicy.ExceededError wrapper. A caller's status
// switch still maps a persistent 429 or 5xx onto its own unexpected-status
// error.
func NewTransport(
	inner http.RoundTripper,
	initialDelay, maxDelay, attemptTimeout time.Duration,
) http.RoundTripper {
	//nolint:bodyclose // failsafe policies use *http.Response generics that confuse bodyclose, with nothing to close.
	retryPolicy := failsafehttp.NewRetryPolicyBuilder().
		WithBackoff(initialDelay, maxDelay).
		WithJitterFactor(jitterFactor).
		WithMaxRetries(MaxRetries).
		ReturnLastFailure().
		Build()
	//nolint:bodyclose // same generics issue as the retry policy, with nothing to close.
	attemptDeadline := timeout.New[*http.Response](attemptTimeout)
	return failsafehttp.NewRoundTripper(countingTransport{inner: inner}, retryPolicy, attemptDeadline)
}

// attemptsKey keys the attempt counter [WithAttempts] stores in a request
// context.
type attemptsKey struct{}

// WithAttempts returns a copy of the context that the transport reports each
// attempt to, plus a function that reads how many attempts a request built on
// that context has made so far. A client reads it once the transport hands
// back a failure, so the error it returns can say how hard the run tried.
func WithAttempts(ctx context.Context) (context.Context, func() int) {
	var n atomic.Int32
	return context.WithValue(ctx, attemptsKey{}, &n), func() int { return int(n.Load()) }
}

// countingTransport sits inside the retry policy and bumps the counter
// [WithAttempts] installs once per attempt, before delegating to inner.
type countingTransport struct {
	inner http.RoundTripper
}

func (t countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if n, ok := req.Context().Value(attemptsKey{}).(*atomic.Int32); ok {
		n.Add(1)
	}
	//nolint:wrapcheck // a transparent pass-through, so the retry policy sees the raw error.
	return t.inner.RoundTrip(req)
}

// Error reports a request that still failed once the transport stopped
// retrying. Attempts counts every try the transport made, and LastStatus
// holds the final HTTP status, or 0 when the last try ended without a
// response (a network error or a per-attempt timeout). Err carries the
// client's own error, so errors.Is still matches its sentinels.
type Error struct {
	Err        error
	Attempts   int
	LastStatus int
}

func (e *Error) Error() string {
	if e.LastStatus == 0 {
		return fmt.Sprintf("%v (attempts: %d, last status: 0, no HTTP response)", e.Err, e.Attempts)
	}
	return fmt.Sprintf("%v (attempts: %d, last status: %d)", e.Err, e.Attempts, e.LastStatus)
}

func (e *Error) Unwrap() error { return e.Err }
