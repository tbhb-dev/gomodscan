// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

//go:build unix

package cachehttp_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"go.tbhb.dev/gomodscan/internal/cachehttp"
)

// The test changes the process file creation mask, so it must not run in
// parallel. A parallel test only resumes after every serial test in the
// package ends.
//
//nolint:paralleltest // the file creation mask is process-wide
func TestDiskStore_CreatesTheCacheDirectoryPrivateToItsGroup(t *testing.T) {
	old := syscall.Umask(0)

	t.Cleanup(func() { syscall.Umask(old) })

	dir := filepath.Join(t.TempDir(), "cache")
	cachehttp.NewDiskStore(dir).Put("k", []byte("v"))

	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o750), info.Mode().Perm(), "no access for others, and no write for the group")
}
