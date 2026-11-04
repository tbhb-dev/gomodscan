// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.tbhb.dev/gomodscan/internal/exitcode"
)

// TestRealMain_ReportFileMode checks the -o and -summary-json files take mode
// 0644 less the bits the file creation mask clears, as a file from os.Create
// would. A plain os.CreateTemp leaves mode 0600.
//
//nolint:paralleltest // the file creation mask belongs to the whole process
func TestRealMain_ReportFileMode(t *testing.T) {
	for _, testCase := range []struct {
		umask int
		want  os.FileMode
	}{
		{umask: 0o022, want: 0o644},
		{umask: 0o077, want: 0o600},
	} {
		old := syscall.Umask(testCase.umask)
		dir := fixtureRoot("empty")
		outPath := filepath.Join(t.TempDir(), "out.sarif")
		sumPath := filepath.Join(t.TempDir(), "summary.json")

		var out, errOut bytes.Buffer

		code := realMain([]string{
			"-no-cache", flagModroot, dir, "-format", formatSARIF, "-o", outPath, "-summary-json", sumPath,
		}, &out, &errOut)

		syscall.Umask(old)

		require.Equal(t, exitcode.OK, code, errOut.String())

		for _, path := range []string{outPath, sumPath} {
			info, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(
				t,
				testCase.want,
				info.Mode().Perm(),
				"%s under umask %#o",
				filepath.Base(path),
				testCase.umask,
			)
		}
	}
}
