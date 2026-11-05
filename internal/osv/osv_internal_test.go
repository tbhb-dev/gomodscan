// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

package osv

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// This test runs before the parallel ones. When a change drops the injected
// client, it fails here at once, while the other tests would send every
// request through the real retry transport and wait out its backoff.
//
//nolint:paralleltest // it has to finish before the slower parallel tests start
func TestHTTPClient_PrefersTheInjectedClient(t *testing.T) {
	injected := &http.Client{Transport: nil, CheckRedirect: nil, Jar: nil, Timeout: 0}

	assert.Same(t, injected, (&Client{BaseURL: "", HTTPClient: injected, UserAgent: ""}).httpClient())
	assert.Same(t, defaultHTTPClient, (&Client{BaseURL: "", HTTPClient: nil, UserAgent: ""}).httpClient())
}
