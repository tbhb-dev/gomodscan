// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

package cachehttp

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// A cached entry with no stored header still yields a usable response, and a
// freshly made header has the from-cache marker.
func TestEntryResponseNilHeader(t *testing.T) {
	t.Parallel()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.test", nil)
	require.NoError(t, err)
	resp := entry{StatusCode: http.StatusOK}.response(req)
	t.Cleanup(func() { _ = resp.Body.Close() })
	require.Equal(t, "1", resp.Header.Get(FromCacheHeader))
}
