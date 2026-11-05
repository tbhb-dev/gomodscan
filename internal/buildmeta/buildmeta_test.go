// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

package buildmeta_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.tbhb.dev/gomodscan/internal/buildmeta"
)

func TestGetReturnsPackageVars(t *testing.T) {
	t.Parallel()

	got := buildmeta.Get()
	assert.Equal(t, buildmeta.Version, got.Version)
	assert.Equal(t, buildmeta.Commit, got.Commit)
	assert.Equal(t, buildmeta.Date, got.Date)
}

// FuzzGetIsSafe sets the project's fuzz pattern. Get() takes no input, the
// target calls it with each seed corpus entry and checks that Version is
// never empty. A plain go test run replays the seeds.
func FuzzGetIsSafe(f *testing.F) {
	f.Add("seed")
	f.Fuzz(func(t *testing.T, _ string) {
		got := buildmeta.Get()
		require.NotEmpty(t, got.Version, "Get().Version must never be empty; init() guarantees DEV fallback")
	})
}
