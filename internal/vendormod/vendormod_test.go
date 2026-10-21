// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

package vendormod_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbhb-dev/gomodscan/internal/vendormod"
)

func TestParse(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want []vendormod.Module
	}{
		{
			name: "plain module declarations",
			in: `# github.com/spf13/cobra v1.10.2
## explicit; go 1.23
github.com/spf13/cobra
# github.com/stretchr/testify v1.11.1
## explicit; go 1.17
github.com/stretchr/testify/assert
github.com/stretchr/testify/require
`,
			want: []vendormod.Module{
				{Path: "github.com/spf13/cobra", Version: "v1.10.2", Line: 1},
				{Path: "github.com/stretchr/testify", Version: "v1.11.1", Line: 4},
			},
		},
		{
			name: "replaced to another module",
			in: `# example.com/old v0.0.0 => example.com/new v1.2.3
## explicit
example.com/old
`,
			want: []vendormod.Module{
				{Path: "example.com/new", Version: "v1.2.3", Line: 1},
			},
		},
		{
			name: "replaced to local path is dropped",
			in: `# example.com/local v0.0.0 => ../local
## explicit
example.com/local
# github.com/keep/me v1.0.0
github.com/keep/me
`,
			want: []vendormod.Module{
				{Path: "github.com/keep/me", Version: "v1.0.0", Line: 4},
			},
		},
		{
			name: "blank input yields no modules",
			in:   "",
			want: nil,
		},
		{
			name: "package paths and sub-metadata are ignored",
			in: `# github.com/a/b v0.1.0
## explicit; go 1.21
github.com/a/b
github.com/a/b/sub
random non-header line
`,
			want: []vendormod.Module{{Path: "github.com/a/b", Version: "v0.1.0", Line: 1}},
		},
		{
			name: "three-field replace without version drops the entry",
			in: `# example.com/old => example.com/new
## explicit
example.com/old
`,
			want: nil,
		},
		{
			name: "four fields without arrow at either anchor position drops",
			in: `# example.com/strange one two three
## explicit
example.com/strange
`,
			want: nil,
		},
		{
			name: "single-field header drops via the default branch",
			in: `# loner
## explicit
loner
`,
			want: nil,
		},
		{
			name: "five fields with arrow at len-3 picks the replacement pair",
			in: `# example.com/old v0.1.0 => example.com/new v9.9.9
## explicit
example.com/old
`,
			want: []vendormod.Module{
				{Path: "example.com/new", Version: "v9.9.9", Line: 1},
			},
		},
		{
			name: "four fields with arrow at len-3 picks the replacement pair",
			in: `# example.com/old => example.com/new v9.9.9
## explicit
example.com/old
`,
			want: []vendormod.Module{
				{Path: "example.com/new", Version: "v9.9.9", Line: 1},
			},
		},
		{
			name: "exactly two fields hit the plain-module case",
			in: `# example.com/exact v0.0.1
## explicit
example.com/exact
`,
			want: []vendormod.Module{
				{Path: "example.com/exact", Version: "v0.0.1", Line: 1},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := vendormod.Parse(strings.NewReader(tc.in))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseReportsScannerError(t *testing.T) {
	t.Parallel()
	// One header line longer than the 1 MiB scanner cap forces
	// bufio.Scanner to surface bufio.ErrTooLong, which Parse wraps
	// and returns. Exercising the wrap closes the only otherwise
	// unreachable error path in Parse.
	huge := "# example.com/big " + strings.Repeat("v", (1<<20)+1) + "\n"
	_, err := vendormod.Parse(strings.NewReader(huge))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scan:")
}

func TestRead(t *testing.T) {
	t.Parallel()

	t.Run("returns parsed modules from vendor/modules.txt", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		vendorDir := filepath.Join(dir, "vendor")
		require.NoError(t, os.MkdirAll(vendorDir, 0o755))
		require.NoError(t, os.WriteFile(
			filepath.Join(vendorDir, "modules.txt"),
			[]byte("# github.com/keep/me v1.2.3\n## explicit\ngithub.com/keep/me\n"),
			0o644,
		))
		got, err := vendormod.Read(dir)
		require.NoError(t, err)
		assert.Equal(t, []vendormod.Module{
			{Path: "github.com/keep/me", Version: "v1.2.3", Line: 1},
		}, got)
	})

	t.Run("wraps open errors for a missing modules.txt", func(t *testing.T) {
		t.Parallel()
		got, err := vendormod.Read(filepath.Join(t.TempDir(), "absent"))
		require.Error(t, err)
		assert.Nil(t, got)
		assert.Contains(t, err.Error(), "open ")
		assert.Contains(t, err.Error(), "modules.txt")
	})

	t.Run("wraps parse errors when a line overflows the scanner cap", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		vendorDir := filepath.Join(dir, "vendor")
		require.NoError(t, os.MkdirAll(vendorDir, 0o755))
		huge := "# example.com/big " + strings.Repeat("v", (1<<20)+1) + "\n"
		require.NoError(t, os.WriteFile(
			filepath.Join(vendorDir, "modules.txt"),
			[]byte(huge),
			0o644,
		))
		got, err := vendormod.Read(dir)
		require.Error(t, err)
		assert.Nil(t, got)
		assert.Contains(t, err.Error(), "parse ")
		assert.Contains(t, err.Error(), "scan:")
	})
}
