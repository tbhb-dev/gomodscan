// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

package cachehttp

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A cached entry with no stored header still yields a usable response, and a
// freshly made header has the from-cache marker.
func TestEntryResponseNilHeader(t *testing.T) {
	t.Parallel()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.test", nil)
	require.NoError(t, err)

	resp := entry{StatusCode: http.StatusOK, Expires: time.Time{}, Header: nil, Body: nil}.response(req)

	t.Cleanup(func() { _ = resp.Body.Close() })
	require.Equal(t, "1", resp.Header.Get(FromCacheHeader))
}

var errDisk = errors.New("disk failure")

// fakeTemp is a temporary file whose write and close results the test sets.
// A real file backs it so the test can see whether Put removes it.
type fakeTemp struct {
	writeErr error
	closeErr error
	name     string
}

func (f *fakeTemp) Write(p []byte) (int, error) { return len(p), f.writeErr }
func (f *fakeTemp) Close() error                { return f.closeErr }
func (f *fakeTemp) Name() string                { return f.name }

func TestDiskStorePut_DropsTheWriteOnATempFileFailure(t *testing.T) {
	t.Parallel()

	cases := []struct {
		writeErr error
		closeErr error
		name     string
	}{
		{name: "write fails", writeErr: errDisk, closeErr: nil},
		{name: "close fails", writeErr: nil, closeErr: errDisk},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			tmpName := filepath.Join(dir, "k.tmp-1")
			require.NoError(t, os.WriteFile(tmpName, []byte("partial"), 0o600))

			store := NewDiskStore(dir)
			store.createTemp = func(string, string) (tempFile, error) {
				return &fakeTemp{name: tmpName, writeErr: testCase.writeErr, closeErr: testCase.closeErr}, nil
			}

			store.Put("k", []byte("v"))

			_, ok := store.Get("k")
			require.False(t, ok, "a failed temp file write leaves no entry")
			require.NoFileExists(t, tmpName, "Put removes the temp file it couldn't finish")
		})
	}
}

func TestDiskStorePut_DropsTheWriteWhenTheTempFileCannotBeCreated(t *testing.T) {
	t.Parallel()

	store := NewDiskStore(t.TempDir())
	store.createTemp = func(string, string) (tempFile, error) { return nil, errDisk }

	store.Put("k", []byte("v"))

	_, ok := store.Get("k")
	require.False(t, ok)
}
