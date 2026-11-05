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

//nolint:dupl // table-driven cases repeat setup and assertions by design
func TestParseCacheControl(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header string
		want   cacheControl
	}{
		{"empty header", "", cacheControl{maxAge: 0, noStore: false, present: false}},
		{"only empty directives", " , ,", cacheControl{maxAge: 0, noStore: false, present: false}},
		{
			"skips a leading empty directive",
			", max-age=60",
			cacheControl{maxAge: time.Minute, noStore: false, present: true},
		},
		{
			"an empty directive does not end the parse",
			"max-age=60,,no-store",
			cacheControl{maxAge: time.Minute, noStore: true, present: true},
		},
		{"one second", "max-age=1", cacheControl{maxAge: time.Second, noStore: false, present: true}},
		{"zero grants nothing", "max-age=0", cacheControl{maxAge: 0, noStore: false, present: true}},
		{"negative grants nothing", "max-age=-5", cacheControl{maxAge: 0, noStore: false, present: true}},
		{
			"a later max-age overrides an earlier one",
			"max-age=60, max-age=0",
			cacheControl{maxAge: 0, noStore: false, present: true},
		},
		{
			"out of range grants nothing",
			"max-age=99999999999999999999",
			cacheControl{maxAge: 0, noStore: false, present: true},
		},
		{"not a number grants nothing", "max-age=soon", cacheControl{maxAge: 0, noStore: false, present: true}},
		{
			"ignores case and spacing",
			" Max-Age=30 , NO-STORE",
			cacheControl{maxAge: 30 * time.Second, noStore: true, present: true},
		},
		{
			"an unrecognized directive still counts as present",
			"public",
			cacheControl{maxAge: 0, noStore: false, present: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, parseCacheControl(tt.header))
		})
	}
}

//nolint:dupl // table-driven cases repeat setup and assertions by design
func TestAge(t *testing.T) {
	t.Parallel()

	tests := []struct {
		header string
		want   time.Duration
	}{
		{"", 0},
		{"abc", 0},
		{"0", 0},
		{"-1", 0},
		{"-30", 0},
		{"99999999999999999999", 0},
		{"90", 90 * time.Second},
		{" 7 ", 7 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, age(tt.header))
		})
	}
}

func TestDecode_RoundTripsAndWrapsFailures(t *testing.T) {
	t.Parallel()

	want := entry{
		Expires:    time.Unix(1_700_000_000, 0).UTC(),
		Header:     http.Header{"K": {"v"}},
		Body:       []byte("body"),
		StatusCode: http.StatusOK,
	}

	got, err := decode(encode(want))
	require.NoError(t, err)
	require.True(t, want.Expires.Equal(got.Expires))
	require.Equal(t, want.Header, got.Header)
	require.Equal(t, want.Body, got.Body)
	require.Equal(t, want.StatusCode, got.StatusCode)

	_, err = decode([]byte("not a gob stream"))
	require.Error(t, err)
	require.ErrorContains(t, err, "decode cache entry")
	require.Error(t, errors.Unwrap(err), "the gob failure stays in the error chain")
}

func TestDiskStorePut_CreatesNoTempFileWhenTheDirectoryIsBlocked(t *testing.T) {
	t.Parallel()

	// A regular file where the cache directory should sit blocks creation.
	file := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))

	store := NewDiskStore(filepath.Join(file, "sub"))
	calls := 0
	store.createTemp = func(string, string) (tempFile, error) {
		calls++

		return nil, errDisk
	}

	store.Put("k", []byte("v"))

	require.Zero(t, calls, "Put gives up before it opens a temp file when it can't make the directory")
}
