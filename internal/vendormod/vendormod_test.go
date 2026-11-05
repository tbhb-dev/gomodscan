// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

package vendormod_test

import (
	"bufio"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.tbhb.dev/gomodscan/internal/vendormod"
)

//nolint:funlen // one function holds the whole scenario table
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
				{Path: modNew, Version: "v1.2.3", Line: 1},
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
			name: "three fields that start with the arrow drop the entry",
			in: `# => example.com/new v9.9.9
## explicit
example.com/old
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
				{Path: modNew, Version: "v9.9.9", Line: 1},
			},
		},
		{
			name: "four fields with arrow at len-3 picks the replacement pair",
			in: `# example.com/old => example.com/new v9.9.9
## explicit
example.com/old
`,
			want: []vendormod.Module{
				{Path: modNew, Version: "v9.9.9", Line: 1},
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

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := vendormod.Parse(strings.NewReader(testCase.in))
			require.NoError(t, err)
			assert.Equal(t, testCase.want, got)
		})
	}
}

func TestParseReportsScannerError(t *testing.T) {
	t.Parallel()
	// One header line longer than the 1 MiB scanner cap forces
	// bufio.Scanner to report bufio.ErrTooLong, which Parse wraps
	// and returns. Exercising the wrap closes the only otherwise
	// unreachable error path in Parse.
	huge := "# example.com/big " + strings.Repeat("v", (1<<20)+1) + "\n"
	_, err := vendormod.Parse(strings.NewReader(huge))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scan:")
	require.ErrorIs(t, err, bufio.ErrTooLong)
}

// firstReadSize records the length of the buffer the scanner hands to its
// reader on the first read, which is the scanner's initial buffer size.
type firstReadSize struct {
	r    io.Reader
	size int
	read bool
}

func (f *firstReadSize) Read(buf []byte) (int, error) {
	if !f.read {
		f.read = true
		f.size = len(buf)
	}

	return f.r.Read(buf) //nolint:wrapcheck // a transparent wrapper, so the scanner sees the reader's own error
}

// The scanner starts with a 64 KiB buffer, so a typical vendor/modules.txt
// is read in one pass.
func TestParseStartsWithA64KiBBuffer(t *testing.T) {
	t.Parallel()

	reader := &firstReadSize{r: strings.NewReader("# example.com/m v1.0.0\n"), size: 0, read: false}

	got, err := vendormod.Parse(reader)
	require.NoError(t, err)
	assert.Len(t, got, 1)
	assert.Equal(t, 1<<16, reader.size)
}

// The scanner takes a line of nearly 1 MiB, well past the 64 KiB default
// token limit, and the module on it keeps its line number.
func TestParseAcceptsLongLines(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		version string
	}{
		{name: "past the default scanner cap", version: strings.Repeat("v", 100_000)},
		{name: "just under the 1 MiB cap", version: strings.Repeat("v", (1<<20)-100)},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			in := "## explicit\n# example.com/big " + testCase.version + "\n"

			got, err := vendormod.Parse(strings.NewReader(in))
			require.NoError(t, err)
			assert.Equal(t, []vendormod.Module{
				{Path: "example.com/big", Version: testCase.version, Line: 2},
			}, got)
		})
	}
}

func TestRead(t *testing.T) {
	t.Parallel()

	t.Run("returns parsed modules from vendor/modules.txt", func(t *testing.T) {
		t.Parallel()

		got, err := vendormod.Read(filepath.Join("testdata", "basic"))
		require.NoError(t, err)
		assert.Equal(t, []vendormod.Module{
			{Path: "github.com/keep/me", Version: "v1.2.3", Line: 1},
		}, got)
	})

	t.Run("names the missing modules.txt path once", func(t *testing.T) {
		t.Parallel()

		modroot := filepath.Join("testdata", "absent")
		path := filepath.Join(modroot, "vendor", "modules.txt")
		_, openErr := os.Open(path)
		require.Error(t, openErr)

		got, err := vendormod.Read(modroot)
		require.Error(t, err)
		assert.Nil(t, got)
		require.ErrorIs(t, err, fs.ErrNotExist)
		assert.Equal(t, "vendor manifest: "+openErr.Error(), err.Error())
		assert.Equal(t, 1, strings.Count(err.Error(), path))
	})

	t.Run("wraps parse errors when a line overflows the scanner cap", func(t *testing.T) {
		t.Parallel()

		// The over-long line is generated because a 1 MiB fixture would
		// bloat the repository for one assertion.
		dir := t.TempDir()
		vendorDir := filepath.Join(dir, "vendor")
		require.NoError(t, os.MkdirAll(vendorDir, 0o750))

		huge := "# example.com/big " + strings.Repeat("v", (1<<20)+1) + "\n"
		require.NoError(t, os.WriteFile(filepath.Join(vendorDir, "modules.txt"), []byte(huge), 0o600))

		got, err := vendormod.Read(dir)
		require.Error(t, err)
		assert.Nil(t, got)
		assert.Contains(t, err.Error(), "parse ")
		assert.Contains(t, err.Error(), "scan:")
		require.ErrorIs(t, err, bufio.ErrTooLong)
	})
}

// TestSelfFixtureMatchesGoMod keeps testdata/self/vendor/modules.txt, a
// copy of what go mod vendor writes for this module, consistent with the
// requirements in the repository's go.mod. A dependency bump that skips the
// fixture fails here.
func TestSelfFixtureMatchesGoMod(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	require.NoError(t, err)

	want := map[string]string{}
	inRequire := false

	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(line)

		switch {
		case line == "require (":
			inRequire = true
		case line == ")":
			inRequire = false
		case inRequire:
			fields := strings.Fields(line)
			require.GreaterOrEqual(t, len(fields), 2, line)

			want[fields[0]] = fields[1]
		}
	}

	require.NotEmpty(t, want)

	modules, err := vendormod.Read(filepath.Join("testdata", "self"))
	require.NoError(t, err)

	got := make(map[string]string, len(modules))
	for _, module := range modules {
		got[module.Path] = module.Version
	}

	assert.Equal(t, want, got)
}

const (
	modNew = "example.com/new"
)
