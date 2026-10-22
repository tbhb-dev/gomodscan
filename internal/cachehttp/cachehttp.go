// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

// Package cachehttp builds an on-disk caching [http.RoundTripper] for the
// pkg.go.dev client. pkg.go.dev answers GET /v1/versions/{module} with
// Cache-Control: public, max-age=3600 and sends no revalidation header and no
// Vary, so a private cache may reuse a module's version list for the freshness
// window the server grants and re-fetches in full once that window lapses. A
// repeated pre-commit run inside the window then skips the network. The 404
// for a private module or one pkg.go.dev never indexed carries no-store, so
// this cache never records a negative lookup.
//
// The transport honors only the directives pkg.go.dev sends. It keeps a 200
// for its max-age and refuses no-store. The full request URL forms the whole
// key. The server ignores If-Modified-Since and never returns 304, so no
// revalidation path exists and a stale entry triggers a fresh fetch. Freshness
// stays strict, so the transport never serves a stale entry and a failed
// origin surfaces as an error rather than a silently outdated answer.
//
// A cache miss covers the only failure mode the transport allows. A store
// error or a corrupt entry turns into a miss, and a failed write drops
// silently. The request then reaches the origin anyway, so the cache speeds
// a scan up yet never fails one.
//
// Layer the cache outside the retry transport
// (github.com/tbhb-dev/gomodscan/internal/retryhttp) so a fresh hit
// short-circuits before any backoff or socket. NewTransport takes that retry
// transport as its inner RoundTripper.
package cachehttp

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// FromCacheHeader marks a response the transport served from the on-disk
// store rather than the origin. The pkg.go.dev client reads it to report a
// cached response as one that made no network attempt, and tests and curious
// operators read it to tell a hit from a miss.
const FromCacheHeader = "X-From-Cache"

// Store persists opaque cache blobs under a key. Neither method returns an
// error: the cache must never fail a scan, so the disk-backed store swallows
// its IO errors and reports a miss from Get or drops the write from Put rather
// than propagating them.
type Store interface {
	Get(key string) ([]byte, bool)
	Put(key string, blob []byte)
}

// entry holds the cached form of a response and the instant that copy goes
// stale.
type entry struct {
	Expires    time.Time
	StatusCode int
	Header     http.Header
	Body       []byte
}

// transport carries the caching RoundTripper that NewTransport returns.
type transport struct {
	inner http.RoundTripper
	store Store
}

// NewTransport wraps inner with the on-disk response cache backed by store. A
// GET whose cached copy stays fresh returns from store and never reaches
// inner. Every other request delegates to inner, and a 200 that carries
// max-age without no-store goes into store before it returns.
func NewTransport(inner http.RoundTripper, store Store) http.RoundTripper {
	return &transport{inner: inner, store: store}
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Only a GET reaches the cache, and the client only ever sends pkg.go.dev
	// a GET. Any other method passes straight through.
	if req.Method != http.MethodGet {
		return t.inner.RoundTrip(req) //nolint:wrapcheck // transparent pass-through, and inner owns the error.
	}

	key := cacheKey(req)
	if resp, ok := t.fresh(req, key); ok {
		return resp, nil
	}

	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		return resp, err //nolint:wrapcheck // transparent, so the client wraps it.
	}
	return t.cache(key, resp), nil
}

// fresh returns a response rebuilt from a still-fresh entry, or false
// otherwise. A decode error or a lapsed entry degrades to a miss rather than a
// failure.
func (t *transport) fresh(req *http.Request, key string) (*http.Response, bool) {
	blob, ok := t.store.Get(key)
	if !ok {
		return nil, false
	}
	e, err := decode(blob)
	if err != nil || !time.Now().Before(e.Expires) {
		return nil, false
	}
	return e.response(req), true
}

// cache stores resp under key when the response qualifies, then returns a
// response whose body the caller can read. A 200 that carries max-age
// without no-store goes into store. Anything else, the no-store 404 or
// a directive-free response, flows straight back. A failed body read or
// encode skips the write yet still returns the buffered body.
func (t *transport) cache(key string, resp *http.Response) *http.Response {
	cc := parseCacheControl(resp.Header.Get("Cache-Control"))
	if resp.StatusCode != http.StatusOK || !cc.present || cc.noStore || cc.maxAge <= 0 {
		return resp
	}

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		// The body arrived partly consumed and now unreadable. Skip the cache
		// write, yet still return what arrived so the client meets the same
		// failure it would without a cache in the path.
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))

	e := entry{
		Expires:    time.Now().Add(cc.maxAge - age(resp.Header.Get("Age"))),
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       body,
	}
	if blob, encErr := encode(e); encErr == nil {
		t.store.Put(key, blob)
	}
	return resp
}

// response rebuilds an *http.Response from a cache entry for req. It clones
// the stored header and adds FromCacheHeader. The body then comes from an
// in-memory reader.
func (e entry) response(req *http.Request) *http.Response {
	header := e.Header.Clone()
	if header == nil {
		header = make(http.Header)
	}
	header.Set(FromCacheHeader, "1")
	return &http.Response{
		StatusCode:    e.StatusCode,
		Status:        strconv.Itoa(e.StatusCode) + " " + http.StatusText(e.StatusCode),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(e.Body)),
		ContentLength: int64(len(e.Body)),
		Request:       req,
	}
}

// cacheKey derives the store key from the request. The method and full URL
// together form the whole key. pkg.go.dev sends no Vary, and the limit and
// token query parameters that page the results already ride in the URL.
func cacheKey(req *http.Request) string {
	sum := sha256.Sum256([]byte(req.Method + " " + req.URL.String()))
	return hex.EncodeToString(sum[:])
}

// cacheControl holds the Cache-Control directives the cache acts on. present
// reports whether the header carried any directive at all, so a caller can
// tell "no caching guidance" (don't store) apart from "max-age=0" (store
// nothing fresh).
type cacheControl struct {
	maxAge  time.Duration
	noStore bool
	present bool
}

// parseCacheControl pulls the directives the cache acts on out of a
// Cache-Control header, skipping any directive it doesn't recognize.
func parseCacheControl(header string) cacheControl {
	var cc cacheControl
	for raw := range strings.SplitSeq(header, ",") {
		directive := strings.ToLower(strings.TrimSpace(raw))
		if directive == "" {
			continue
		}
		cc.present = true
		if directive == "no-store" {
			cc.noStore = true
		} else if value, ok := strings.CutPrefix(directive, "max-age="); ok {
			if secs, err := strconv.Atoi(value); err == nil && secs > 0 {
				cc.maxAge = time.Duration(secs) * time.Second
			}
		}
	}
	return cc
}

// age parses an Age header into a duration, returning zero for an absent or
// malformed header. Subtracting it from max-age keeps a response that already
// aged in pkg.go.dev's fronting cache from over-staying its freshness window.
func age(header string) time.Duration {
	secs, err := strconv.Atoi(strings.TrimSpace(header))
	if err != nil || secs < 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

func encode(e entry) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(e); err != nil {
		return nil, fmt.Errorf("encode cache entry: %w", err)
	}
	return buf.Bytes(), nil
}

func decode(blob []byte) (entry, error) {
	var e entry
	if err := gob.NewDecoder(bytes.NewReader(blob)).Decode(&e); err != nil {
		return entry{}, fmt.Errorf("decode cache entry: %w", err)
	}
	return e, nil
}

// DiskStore backs [Store] with one file per key under a directory. It creates
// the directory lazily on the first write and swallows every IO error, so a
// read-only or missing cache directory turns the cache into a no-op rather
// than a scan failure.
type DiskStore struct {
	dir string
}

// NewDiskStore returns a DiskStore rooted at dir. The directory need not
// exist yet. The first Put creates it.
func NewDiskStore(dir string) *DiskStore {
	return &DiskStore{dir: dir}
}

// DefaultDir returns the per-user cache directory for the pkg.go.dev response
// cache, $os.UserCacheDir/gomodscan/pkgsite. The error from os.UserCacheDir
// flows up so a caller can fall back to disabling the cache.
func DefaultDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate user cache dir: %w", err)
	}
	return filepath.Join(base, "gomodscan", "pkgsite"), nil
}

// Get reads the blob stored under key. A missing or unreadable file reports a
// miss.
func (s *DiskStore) Get(key string) ([]byte, bool) {
	blob, err := os.ReadFile(s.path(key))
	if err != nil {
		return nil, false
	}
	return blob, true
}

// Put writes blob under key through a temp file and an atomic rename, so a
// concurrent reader never observes a half-written entry and a re-fetch
// overwrites the stale copy in place. Any IO error drops the write silently.
func (s *DiskStore) Put(key string, blob []byte) {
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return
	}
	tmp, err := os.CreateTemp(s.dir, key+".tmp-*")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	_, writeErr := tmp.Write(blob)
	if closeErr := tmp.Close(); writeErr != nil || closeErr != nil {
		_ = os.Remove(tmpName)
		return
	}
	if err = os.Rename(tmpName, s.path(key)); err != nil {
		_ = os.Remove(tmpName)
	}
}

func (s *DiskStore) path(key string) string {
	return filepath.Join(s.dir, key)
}
