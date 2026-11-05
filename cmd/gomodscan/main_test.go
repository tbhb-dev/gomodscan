// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.tbhb.dev/gomodscan/internal/buildmeta"
	"go.tbhb.dev/gomodscan/internal/cachehttp"
	"go.tbhb.dev/gomodscan/internal/exitcode"
	"go.tbhb.dev/gomodscan/internal/findings"
	"go.tbhb.dev/gomodscan/internal/osv"
	"go.tbhb.dev/gomodscan/internal/pkgsite"
	"go.tbhb.dev/gomodscan/internal/retryhttp"
	"go.tbhb.dev/gomodscan/internal/vendormod"
)

// errLookupFailure represents any non-not-found pkg.go.dev lookup
// error the fake client surfaces. Declared once so err113 never fires.
var errLookupFailure = errors.New("network failure")

// errQueryFailure represents any OSV-side error the stub returns
// to the scanner.
var errQueryFailure = errors.New("network failure")

// fakeVersionsClient drives the deprecated scanner from tests by
// returning a canned response (or error) per module path. The interface
// keeps run injectable so the table-driven cases below don't need to
// start an httptest server for every branch.
type fakeVersionsClient struct {
	responses map[string][]pkgsite.ModuleVersion
	errors    map[string]error
}

func (f *fakeVersionsClient) Versions(_ context.Context, module string) ([]pkgsite.ModuleVersion, error) {
	if err, ok := f.errors[module]; ok {
		return nil, err
	}

	if vs, ok := f.responses[module]; ok {
		return vs, nil
	}

	return nil, fmt.Errorf("%w: %s", pkgsite.ErrNotFound, module)
}

// fakeVulnsClient drives the malicious scanner from tests. Each entry
// maps "module@version" to a canned response or error.
type fakeVulnsClient struct {
	responses map[string][]osv.Vulnerability
	errors    map[string]error
}

func (f *fakeVulnsClient) Query(_ context.Context, pkg osv.Package, version string) ([]osv.Vulnerability, error) {
	key := pkg.Name + "@" + version
	if err, ok := f.errors[key]; ok {
		return nil, err
	}

	return f.responses[key], nil
}

//nolint:dupl // test scenarios repeat the same arrange and assert steps
func TestFindingLevel(t *testing.T) {
	t.Parallel()
	assert.Equal(
		t,
		findings.LevelError,
		finding{
			kind:    kindMalicious,
			module:  "",
			version: "",
			latest:  "",
			reason:  "",
			id:      "",
			summary: "",
			line:    0,
		}.level(),
	)
	assert.Equal(
		t,
		findings.LevelWarning,
		finding{
			kind:    kindRetracted,
			module:  "",
			version: "",
			latest:  "",
			reason:  "",
			id:      "",
			summary: "",
			line:    0,
		}.level(),
	)
	assert.Equal(
		t,
		findings.LevelWarning,
		finding{
			kind:    kindDeprecated,
			module:  "",
			version: "",
			latest:  "",
			reason:  "",
			id:      "",
			summary: "",
			line:    0,
		}.level(),
	)
}

//nolint:dupl // table-driven cases repeat setup and assertions by design
func TestFindingProps(t *testing.T) {
	t.Parallel()

	cases := []struct {
		want map[string]string
		name string
		f    finding
	}{
		{
			name: "retracted with reason",
			f: finding{
				kind: kindRetracted, module: modA, version: v100, reason: checksumReason,
				latest: "", id: "", summary: "", line: 0,
			},
			want: map[string]string{reasonKey: checksumReason},
		},
		{
			name: "retracted without reason",
			f: finding{
				kind:    kindRetracted,
				module:  modA,
				version: v100,
				latest:  "",
				reason:  "",
				id:      "",
				summary: "",
				line:    0,
			},
			want: map[string]string{},
		},
		{
			name: "reason whitespace trimmed",
			f: finding{
				kind:    kindRetracted,
				module:  modA,
				version: v100,
				reason:  "  checksum  \n",
				latest:  "",
				id:      "",
				summary: "",
				line:    0,
			},
			want: map[string]string{reasonKey: checksumReason},
		},
		{
			name: "retracted ignores a stray latest version",
			f: finding{
				kind: kindRetracted, module: modA, version: v100, latest: v020,
				reason: "", id: "", summary: "", line: 0,
			},
			want: map[string]string{},
		},
		{
			name: "deprecated emits latest and reason",
			f: finding{
				kind: kindDeprecated, module: modB, version: v010,
				latest: v020, reason: useV020,
				id:      "",
				summary: "",
				line:    0,
			},
			want: map[string]string{"latest": v020, reasonKey: useV020},
		},
		{
			name: "deprecated without a latest version omits it",
			f: finding{
				kind: kindDeprecated, module: modB, version: v010, reason: useV020,
				latest: "", id: "", summary: "", line: 0,
			},
			want: map[string]string{reasonKey: useV020},
		},
		{
			name: "malicious id only when summary missing",
			f: finding{
				kind: kindMalicious, module: modA, version: v100, id: malID,
				summary: "", latest: "", reason: "", line: 0,
			},
			want: map[string]string{"id": malID},
		},
		{
			name: "malicious id plus trimmed summary",
			f: finding{
				kind: kindMalicious, module: modA, version: v100, id: malID,
				summary: "  Backdoor introduced  ",
				latest:  "",
				reason:  "",
				line:    0,
			},
			want: map[string]string{"id": malID, "summary": backdoorIntroduced},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, testCase.want, testCase.f.props())
		})
	}
}

//nolint:dupl // table-driven cases repeat setup and assertions by design
func TestFindingMessage(t *testing.T) {
	t.Parallel()

	assert.Equal(
		t,
		"Module retracted at v1.0.0. Reason: checksum.",
		finding{
			kind:    kindRetracted,
			module:  modA,
			version: v100,
			reason:  checksumReason,
			latest:  "",
			id:      "",
			summary: "",
			line:    0,
		}.message(),
	)
	assert.Equal(
		t,
		"Module retracted at v1.0.0. No reason recorded.",
		finding{
			kind:    kindRetracted,
			module:  modA,
			version: v100,
			latest:  "",
			reason:  "",
			id:      "",
			summary: "",
			line:    0,
		}.message(),
	)
	assert.Equal(t,
		"Module deprecated at latest version v0.2.0. Reason: use v0.2.0.",
		finding{
			kind: kindDeprecated, module: modB, version: v010,
			latest: v020, reason: useV020,
			id:      "",
			summary: "",
			line:    0,
		}.message(),
	)
	assert.Equal(
		t,
		"OSV malicious-package advisory MAL-2025-0001.",
		finding{
			kind:    kindMalicious,
			id:      malID,
			module:  "",
			version: "",
			latest:  "",
			reason:  "",
			summary: "",
			line:    0,
		}.message(),
	)
	assert.Equal(
		t,
		"OSV malicious-package advisory MAL-2025-0001: Backdoor introduced.",
		finding{
			kind:    kindMalicious,
			id:      malID,
			summary: backdoorIntroduced,
			module:  "",
			version: "",
			latest:  "",
			reason:  "",
			line:    0,
		}.message(),
	)
	assert.Equal(
		t,
		"Unknown finding.",
		finding{
			kind:    findingKind("other"),
			module:  "",
			version: "",
			latest:  "",
			reason:  "",
			id:      "",
			summary: "",
			line:    0,
		}.message(),
	)
}

func TestEmitText_UnifiedFormat(t *testing.T) {
	t.Parallel()

	hits := []finding{
		{
			kind:    kindRetracted,
			module:  modA,
			version: v100,
			reason:  checksumReason,
			latest:  "",
			id:      "",
			summary: "",
			line:    0,
		},
		{
			kind: kindDeprecated, module: modB, version: v010,
			latest: v020, reason: useV020,
			id:      "",
			summary: "",
			line:    0,
		},
		{
			kind:    kindMalicious,
			module:  "example.com/c",
			version: v200,
			id:      malID,
			summary: backdoorIntroduced,
			latest:  "",
			reason:  "",
			line:    0,
		},
	}

	var buf bytes.Buffer
	require.NoError(t, emitText(&buf, hits))
	assert.Equal(t,
		"warning: gomodscan/retracted: example.com/a@v1.0.0 reason=checksum\n"+
			"warning: gomodscan/deprecated: example.com/b@v0.1.0 latest=v0.2.0 reason=\"use v0.2.0\"\n"+
			"error: gomodscan/malicious-package: example.com/c@v2.0.0 id=MAL-2025-0001 summary=\"Backdoor introduced\"\n",
		buf.String(),
	)
}

func TestEmitSARIF_RegistersAllRulesAndEmitsResults(t *testing.T) {
	t.Parallel()

	hits := []finding{
		{
			kind:    kindRetracted,
			module:  modA,
			version: v100,
			line:    10,
			reason:  checksumReason,
			latest:  "",
			id:      "",
			summary: "",
		},
		{
			kind: kindDeprecated, module: modB, version: v010, line: 14,
			latest: v020, reason: useV020,
			id:      "",
			summary: "",
		},
		{
			kind:    kindMalicious,
			module:  "example.com/c",
			version: v200,
			line:    18,
			id:      malID,
			summary: backdoor,
			latest:  "",
			reason:  "",
		},
	}

	var buf bytes.Buffer
	require.NoError(t, emitSARIF(&buf, hits))
	out := buf.String()
	assert.Contains(t, out, `"name": "gomodscan"`)
	assert.Contains(t, out, `"id": "retracted"`)
	assert.Contains(t, out, `"id": "deprecated"`)
	assert.Contains(t, out, `"id": "malicious-package"`)
	assert.Contains(t, out, `"ruleId": "retracted"`)
	assert.Contains(t, out, `"ruleId": "deprecated"`)
	assert.Contains(t, out, `"ruleId": "malicious-package"`)
	assert.Contains(t, out, `"level": "error"`)
	assert.Contains(t, out, `"name": "example.com/a@v1.0.0"`)
	assert.Contains(t, out, `"name": "example.com/c@v2.0.0"`)
	assert.Contains(t, out, `"latest": "v0.2.0"`)
	assert.Contains(t, out, `"id": "MAL-2025-0001"`)
	// Each result records the vendor manifest as its physical location,
	// with the module's line threaded onto the region so Code Scanning
	// anchors each finding on the real file.
	assert.Contains(t, out, `"uri": "vendor/modules.txt"`)
	assert.Contains(t, out, `"startLine": 10`)
	assert.Contains(t, out, `"startLine": 14`)
	assert.Contains(t, out, `"startLine": 18`)
}

func TestEmitFindings_UnknownFormatErrors(t *testing.T) {
	t.Parallel()

	err := emitFindings(&bytes.Buffer{}, formatJSON, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown -format")
}

//nolint:dupl,funlen // scenarios repeat steps in one function that holds the whole table
func TestCollectDeprecated(t *testing.T) {
	t.Parallel()

	mod := vendormod.Module{Path: modM, Version: v123, Line: 5}

	t.Run("empty version list yields no hits", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, collectDeprecated(mod, nil))
	})

	t.Run("non-matching versions yield no hits", func(t *testing.T) {
		t.Parallel()

		versions := []pkgsite.ModuleVersion{
			{
				Version:           v123,
				LatestVersion:     v200,
				Retracted:         false,
				Deprecated:        false,
				CommitTime:        time.Time{},
				ModulePath:        "",
				DeprecationReason: "",
				RetractionReason:  "",
				IsRedistributable: false,
				HasGoMod:          false,
			},
			{
				Version:           v200,
				LatestVersion:     v200,
				Retracted:         false,
				Deprecated:        false,
				CommitTime:        time.Time{},
				ModulePath:        "",
				DeprecationReason: "",
				RetractionReason:  "",
				IsRedistributable: false,
				HasGoMod:          false,
			},
		}
		assert.Nil(t, collectDeprecated(mod, versions))
	})

	t.Run("matching retracted version emits a retracted finding", func(t *testing.T) {
		t.Parallel()

		versions := []pkgsite.ModuleVersion{
			{
				Version:           v200,
				LatestVersion:     v200,
				Retracted:         false,
				Deprecated:        false,
				CommitTime:        time.Time{},
				ModulePath:        "",
				DeprecationReason: "",
				RetractionReason:  "",
				IsRedistributable: false,
				HasGoMod:          false,
			},
			{
				Version:           v123,
				LatestVersion:     v200,
				Retracted:         true,
				RetractionReason:  checksumReason,
				CommitTime:        time.Time{},
				ModulePath:        "",
				DeprecationReason: "",
				IsRedistributable: false,
				HasGoMod:          false,
				Deprecated:        false,
			},
		}
		got := collectDeprecated(mod, versions)
		require.Len(t, got, 1)
		assert.Equal(t, kindRetracted, got[0].kind)
		assert.Equal(t, v123, got[0].version)
		assert.Equal(t, checksumReason, got[0].reason)
	})

	t.Run("retracted at a different version is ignored", func(t *testing.T) {
		t.Parallel()

		versions := []pkgsite.ModuleVersion{
			{
				Version:           v200,
				LatestVersion:     v200,
				Retracted:         false,
				CommitTime:        time.Time{},
				ModulePath:        "",
				DeprecationReason: "",
				RetractionReason:  "",
				IsRedistributable: false,
				HasGoMod:          false,
				Deprecated:        false,
			},
			{
				Version:           v100,
				LatestVersion:     v200,
				Retracted:         true,
				RetractionReason:  checksumReason,
				CommitTime:        time.Time{},
				ModulePath:        "",
				DeprecationReason: "",
				IsRedistributable: false,
				HasGoMod:          false,
				Deprecated:        false,
			},
		}
		assert.Nil(t, collectDeprecated(mod, versions))
	})

	t.Run("latest version deprecated emits a deprecated finding", func(t *testing.T) {
		t.Parallel()

		versions := []pkgsite.ModuleVersion{
			{
				Version: v300, LatestVersion: v300, Deprecated: true, DeprecationReason: "use v4",
				CommitTime: time.Time{}, ModulePath: "", RetractionReason: "",
				IsRedistributable: false, HasGoMod: false, Retracted: false,
			},
			{
				Version:           v123,
				LatestVersion:     v300,
				Deprecated:        false,
				CommitTime:        time.Time{},
				ModulePath:        "",
				DeprecationReason: "",
				RetractionReason:  "",
				IsRedistributable: false,
				HasGoMod:          false,
				Retracted:         false,
			},
		}
		got := collectDeprecated(mod, versions)
		require.Len(t, got, 1)
		assert.Equal(t, kindDeprecated, got[0].kind)
		assert.Equal(t, v300, got[0].latest)
		assert.Equal(t, "use v4", got[0].reason)
	})

	t.Run("deprecation on a non-latest version is ignored", func(t *testing.T) {
		t.Parallel()

		versions := []pkgsite.ModuleVersion{
			{
				Version:           v300,
				LatestVersion:     v300,
				Deprecated:        false,
				CommitTime:        time.Time{},
				ModulePath:        "",
				DeprecationReason: "",
				RetractionReason:  "",
				IsRedistributable: false,
				HasGoMod:          false,
				Retracted:         false,
			},
			{
				Version:           v123,
				LatestVersion:     v300,
				Deprecated:        true,
				DeprecationReason: "use v3",
				CommitTime:        time.Time{},
				ModulePath:        "",
				RetractionReason:  "",
				IsRedistributable: false,
				HasGoMod:          false,
				Retracted:         false,
			},
		}
		assert.Nil(t, collectDeprecated(mod, versions))
	})

	t.Run("matching retraction and latest deprecation emit both findings", func(t *testing.T) {
		t.Parallel()

		versions := []pkgsite.ModuleVersion{
			{
				Version:           v200,
				LatestVersion:     v200,
				Deprecated:        true,
				DeprecationReason: "use v3",
				CommitTime:        time.Time{},
				ModulePath:        "",
				RetractionReason:  "",
				IsRedistributable: false,
				HasGoMod:          false,
				Retracted:         false,
			},
			{
				Version:           v123,
				LatestVersion:     v200,
				Retracted:         true,
				RetractionReason:  checksumReason,
				CommitTime:        time.Time{},
				ModulePath:        "",
				DeprecationReason: "",
				IsRedistributable: false,
				HasGoMod:          false,
				Deprecated:        false,
			},
		}
		got := collectDeprecated(mod, versions)
		require.Len(t, got, 2)
		// Order tracks the version slice: deprecated entry comes first.
		assert.Equal(t, kindDeprecated, got[0].kind)
		assert.Equal(t, kindRetracted, got[1].kind)
		// Both findings record the module's manifest line.
		assert.Equal(t, mod.Line, got[0].line)
		assert.Equal(t, mod.Line, got[1].line)
	})
}

//nolint:dupl // test scenarios repeat the same arrange and assert steps
func TestCollectMalicious(t *testing.T) {
	t.Parallel()

	mod := vendormod.Module{Path: "example.com/mixed", Version: "v0.5.0", Line: 3}
	cases := []struct {
		name    string
		vulns   []osv.Vulnerability
		wantIDs []string
	}{
		{
			name:    "empty vuln list yields no findings",
			vulns:   nil,
			wantIDs: nil,
		},
		{
			name: "only non-MAL advisories yields no findings",
			vulns: []osv.Vulnerability{
				{ID: "GO-2025-0042", Summary: "Generic vuln", Details: "", Modified: "", Published: "", Aliases: nil},
				{ID: "GHSA-aaaa-bbbb-cccc", Summary: "", Details: "", Modified: "", Published: "", Aliases: nil},
				{ID: "CVE-2025-12345", Summary: "", Details: "", Modified: "", Published: "", Aliases: nil},
			},
			wantIDs: nil,
		},
		{
			name: "MAL-prefixed advisories surface; siblings drop out",
			vulns: []osv.Vulnerability{
				{ID: "GO-2025-0042", Summary: "", Details: "", Modified: "", Published: "", Aliases: nil},
				{
					ID:        "MAL-2025-0007",
					Summary:   "Backdoor introduced upstream",
					Details:   "",
					Modified:  "",
					Published: "",
					Aliases:   nil,
				},
				{ID: "MAL-2025-0008", Summary: "", Details: "", Modified: "", Published: "", Aliases: nil},
			},
			wantIDs: []string{"MAL-2025-0007", "MAL-2025-0008"},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := collectMalicious(mod, testCase.vulns)
			require.Len(t, got, len(testCase.wantIDs))

			for i, want := range testCase.wantIDs {
				assert.Equal(t, want, got[i].id)
				assert.Equal(t, kindMalicious, got[i].kind)
				assert.Equal(t, mod.Path, got[i].module)
				assert.Equal(t, mod.Version, got[i].version)
				assert.Equal(t, mod.Line, got[i].line)
			}
		})
	}
}

//nolint:dupl // table-driven cases repeat setup and assertions by design
func TestEvaluateDeprecated(t *testing.T) {
	t.Parallel()

	mod := vendormod.Module{Path: modM, Version: v100, Line: 0}

	t.Run("not-found error is swallowed as a skip", func(t *testing.T) {
		t.Parallel()

		client := &fakeVersionsClient{
			errors: map[string]error{
				mod.Path: fmt.Errorf("%w: %s", pkgsite.ErrNotFound, mod.Path),
			},
			responses: nil,
		}
		got, err := evaluateDeprecated(context.Background(), client, mod)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("other errors propagate wrapped", func(t *testing.T) {
		t.Parallel()

		client := &fakeVersionsClient{errors: map[string]error{mod.Path: errLookupFailure}, responses: nil}
		got, err := evaluateDeprecated(context.Background(), client, mod)
		require.Error(t, err)
		require.ErrorIs(t, err, errLookupFailure)
		assert.Contains(t, err.Error(), "lookup versions")
		assert.Nil(t, got)
	})

	t.Run("happy path forwards to collectDeprecated", func(t *testing.T) {
		t.Parallel()

		client := &fakeVersionsClient{
			responses: map[string][]pkgsite.ModuleVersion{
				mod.Path: {
					{
						Version:           v100,
						LatestVersion:     v100,
						Retracted:         true,
						RetractionReason:  "bad",
						CommitTime:        time.Time{},
						ModulePath:        "",
						DeprecationReason: "",
						IsRedistributable: false,
						HasGoMod:          false,
						Deprecated:        false,
					},
				},
			},
			errors: nil,
		}
		got, err := evaluateDeprecated(context.Background(), client, mod)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, kindRetracted, got[0].kind)
	})
}

func TestEvaluateMalicious(t *testing.T) {
	t.Parallel()

	mod := vendormod.Module{Path: modM, Version: v100, Line: 0}
	key := mod.Path + "@" + mod.Version

	t.Run("network errors propagate wrapped", func(t *testing.T) {
		t.Parallel()

		client := &fakeVulnsClient{errors: map[string]error{key: errQueryFailure}, responses: nil}
		got, err := evaluateMalicious(context.Background(), client, mod)
		require.Error(t, err)
		require.ErrorIs(t, err, errQueryFailure)
		assert.Contains(t, err.Error(), "lookup vulns")
		assert.Nil(t, got)
	})

	t.Run("happy path forwards to collectMalicious", func(t *testing.T) {
		t.Parallel()

		client := &fakeVulnsClient{
			responses: map[string][]osv.Vulnerability{
				key: {
					{ID: malID, Summary: backdoor, Details: "", Modified: "", Published: "", Aliases: nil},
				},
			},
			errors: nil,
		}
		got, err := evaluateMalicious(context.Background(), client, mod)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, malID, got[0].id)
	})

	t.Run("empty response yields no findings", func(t *testing.T) {
		t.Parallel()

		client := &fakeVulnsClient{responses: nil, errors: nil} // any key returns nil, nil from the fake
		got, err := evaluateMalicious(context.Background(), client, mod)
		require.NoError(t, err)
		assert.Nil(t, got)
	})
}

// fixtureRoot returns the modroot under testdata that holds the
// vendor/modules.txt fixture called name. The run-level tests only read it.
func fixtureRoot(name string) string {
	return filepath.Join("testdata", name)
}

// exhaustedLookup builds the error the pkg.go.dev client returns once the
// retry transport gives up on a persistent 503.
func exhaustedLookup() error {
	return &retryhttp.Error{
		Err: fmt.Errorf("%w: GET https://pkg.go.dev/v1/versions/example.com/explode?limit=200: status 503",
			pkgsite.ErrUnexpectedStatus),
		Attempts:   retryhttp.MaxRetries + 1,
		LastStatus: http.StatusServiceUnavailable,
	}
}

// exhaustedLookupMessage spells out what [exhaustedLookup] prints.
const exhaustedLookupMessage = "unexpected status from pkg.go.dev: " +
	"GET https://pkg.go.dev/v1/versions/example.com/explode?limit=200: status 503 " +
	"(attempts: 4, last status: 503)"

// dirEntries lists the names under dir, so a test can assert that a failed
// write didn't leave a temporary file behind.
func dirEntries(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}

	return names
}

// stderrLines splits the stderr a run wrote into its lines.
func stderrLines(errOut string) []string {
	return strings.Split(strings.TrimSuffix(errOut, "\n"), "\n")
}

// readOnlyDir returns a directory the test process can't create files in.
// It skips the test where permission bits don't stop the writer: on Windows,
// and as root. The directory is empty, so t.TempDir's cleanup removes it
// without restoring write permission first.
func readOnlyDir(t *testing.T) string {
	t.Helper()

	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permission bits don't block this writer")
	}

	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o500)) //nolint:gosec // a read-only directory is the point of the helper.

	return dir
}

//nolint:dupl,funlen,maintidx // scenarios repeat steps in one function that holds the whole table
func TestRun(t *testing.T) {
	t.Parallel()

	t.Run("returns ToolFailure when modroot lacks vendor/modules.txt", func(t *testing.T) {
		t.Parallel()

		var out, errOut bytes.Buffer

		code, err := run(
			context.Background(),
			options{modroot: t.TempDir(), format: formatText, output: "", summaryJSON: ""},
			&fakeVersionsClient{responses: nil, errors: nil},
			&fakeVulnsClient{responses: nil, errors: nil},
			&out,
			&errOut,
		)
		require.Error(t, err)
		assert.Equal(t, exitcode.ToolFailure, code)
		assert.Contains(t, err.Error(), "read vendored modules")
	})

	t.Run("returns ToolFailure on an unknown -format", func(t *testing.T) {
		t.Parallel()

		dir := fixtureRoot("m")

		versions := &fakeVersionsClient{
			responses: map[string][]pkgsite.ModuleVersion{
				modM: {
					{
						Version:           v100,
						LatestVersion:     v100,
						CommitTime:        time.Time{},
						ModulePath:        "",
						DeprecationReason: "",
						RetractionReason:  "",
						IsRedistributable: false,
						HasGoMod:          false,
						Deprecated:        false,
						Retracted:         false,
					},
				},
			},
			errors: nil,
		}

		var out, errOut bytes.Buffer

		code, err := run(
			context.Background(),
			options{modroot: dir, format: formatJSON, output: "", summaryJSON: ""},
			versions,
			&fakeVulnsClient{responses: nil, errors: nil},
			&out,
			&errOut,
		)
		require.Error(t, err)
		assert.Equal(t, exitcode.ToolFailure, code)
		require.ErrorIs(t, err, errUnknownFormat)
		assert.Empty(t, out.String())
	})

	t.Run("returns OK with the no-findings banner when nothing matches", func(t *testing.T) {
		t.Parallel()

		dir := fixtureRoot("clean")

		versions := &fakeVersionsClient{
			responses: map[string][]pkgsite.ModuleVersion{
				"example.com/clean": {
					{
						Version:           v100,
						LatestVersion:     v100,
						CommitTime:        time.Time{},
						ModulePath:        "",
						DeprecationReason: "",
						RetractionReason:  "",
						IsRedistributable: false,
						HasGoMod:          false,
						Deprecated:        false,
						Retracted:         false,
					},
				},
			},
			errors: nil,
		}
		vulns := &fakeVulnsClient{
			responses: map[string][]osv.Vulnerability{
				"example.com/clean@v1.0.0": {
					{ID: "GO-2025-0001", Summary: "", Details: "", Modified: "", Published: "", Aliases: nil},
				},
			},
			errors: nil,
		}

		var out, errOut bytes.Buffer

		code, err := run(
			context.Background(),
			options{modroot: dir, format: formatText, output: "", summaryJSON: ""},
			versions,
			vulns,
			&out,
			&errOut,
		)
		require.NoError(t, err)
		assert.Equal(t, exitcode.OK, code)
		assert.Empty(t, out.String())
		assert.Equal(t, "gomodscan: scanned 1 module(s), no findings\n", errOut.String())
	})

	t.Run("returns Findings with both scanners contributing for one module", func(t *testing.T) {
		t.Parallel()

		dir := fixtureRoot("bad")

		versions := &fakeVersionsClient{
			responses: map[string][]pkgsite.ModuleVersion{
				modBad: {
					{
						Version:           v100,
						LatestVersion:     v100,
						Retracted:         true,
						RetractionReason:  checksumReason,
						CommitTime:        time.Time{},
						ModulePath:        "",
						DeprecationReason: "",
						IsRedistributable: false,
						HasGoMod:          false,
						Deprecated:        false,
					},
				},
			},
			errors: nil,
		}
		vulns := &fakeVulnsClient{
			responses: map[string][]osv.Vulnerability{
				"example.com/bad@v1.0.0": {
					{ID: malID, Summary: backdoor, Details: "", Modified: "", Published: "", Aliases: nil},
				},
			},
			errors: nil,
		}

		var out, errOut bytes.Buffer

		code, err := run(
			context.Background(),
			options{modroot: dir, format: formatText, output: "", summaryJSON: ""},
			versions,
			vulns,
			&out,
			&errOut,
		)
		require.NoError(t, err)
		assert.Equal(t, exitcode.Findings, code)
		assert.Contains(t, out.String(), "warning: gomodscan/retracted: example.com/bad@v1.0.0")
		assert.Contains(t, out.String(), "error: gomodscan/malicious-package: example.com/bad@v1.0.0")
		assert.Equal(t, "gomodscan: 2 finding(s) across 1 module(s)\n", errOut.String())
	})

	t.Run("returns ToolFailure when a module can't be evaluated", func(t *testing.T) {
		t.Parallel()

		dir := fixtureRoot("ok-explode")

		versions := &fakeVersionsClient{
			responses: map[string][]pkgsite.ModuleVersion{
				"example.com/ok": {
					{
						Version:           v100,
						LatestVersion:     v100,
						CommitTime:        time.Time{},
						ModulePath:        "",
						DeprecationReason: "",
						RetractionReason:  "",
						IsRedistributable: false,
						HasGoMod:          false,
						Deprecated:        false,
						Retracted:         false,
					},
				},
			},
			errors: map[string]error{modExplode: exhaustedLookup()},
		}
		vulns := &fakeVulnsClient{
			errors:    map[string]error{modExplodeAt: errQueryFailure},
			responses: nil,
		}

		var out, errOut bytes.Buffer

		code, err := run(
			context.Background(),
			options{modroot: dir, format: formatText, output: "", summaryJSON: ""},
			versions,
			vulns,
			&out,
			&errOut,
		)
		require.NoError(t, err)
		assert.Equal(t, exitcode.ToolFailure, code)
		assert.Empty(t, out.String())
		assert.Equal(t,
			"gomodscan: example.com/explode: lookup versions: "+exhaustedLookupMessage+"\n"+
				"gomodscan: example.com/explode: lookup vulns: network failure\n"+
				"gomodscan: 1 module(s) could not be evaluated\n",
			errOut.String(),
		)
	})

	t.Run("an unevaluated module outranks findings", func(t *testing.T) {
		t.Parallel()

		dir := fixtureRoot("bad-explode")

		versions := &fakeVersionsClient{
			responses: map[string][]pkgsite.ModuleVersion{
				modBad: {
					{
						Version:           v100,
						LatestVersion:     v100,
						Retracted:         true,
						RetractionReason:  checksumReason,
						CommitTime:        time.Time{},
						ModulePath:        "",
						DeprecationReason: "",
						IsRedistributable: false,
						HasGoMod:          false,
						Deprecated:        false,
					},
				},
			},
			errors: map[string]error{modExplode: exhaustedLookup()},
		}

		var out, errOut bytes.Buffer

		code, err := run(
			context.Background(),
			options{modroot: dir, format: formatText, output: "", summaryJSON: ""},
			versions,
			&fakeVulnsClient{responses: nil, errors: nil},
			&out,
			&errOut,
		)
		require.NoError(t, err)
		assert.Equal(t, exitcode.ToolFailure, code)
		assert.Equal(t, "warning: gomodscan/retracted: example.com/bad@v1.0.0 reason=checksum\n", out.String())
		assert.Equal(t,
			"gomodscan: example.com/explode: lookup versions: "+exhaustedLookupMessage+"\n"+
				"gomodscan: 1 finding(s) across 2 module(s)\n"+
				"gomodscan: 1 module(s) could not be evaluated\n",
			errOut.String(),
		)
	})

	t.Run("not-found deprecated lookups stay silent in errOut", func(t *testing.T) {
		t.Parallel()

		dir := fixtureRoot("private")
		// The fakes return ErrNotFound (versions) and an empty result
		// (vulns) for any module path they don't recognize.
		var out, errOut bytes.Buffer

		code, err := run(
			context.Background(),
			options{modroot: dir, format: formatText, output: "", summaryJSON: ""},
			&fakeVersionsClient{responses: nil, errors: nil},
			&fakeVulnsClient{responses: nil, errors: nil},
			&out,
			&errOut,
		)
		require.NoError(t, err)
		assert.Equal(t, exitcode.OK, code)
		assert.NotContains(t, errOut.String(), "lookup versions")
		assert.Contains(t, errOut.String(), "scanned 1 module(s), no findings")
	})
}

//nolint:dupl,funlen // scenarios repeat steps in one function that holds the whole table
func TestRun_Output(t *testing.T) {
	t.Parallel()

	retractedVersions := func() *fakeVersionsClient {
		return &fakeVersionsClient{
			responses: map[string][]pkgsite.ModuleVersion{
				modBad: {
					{
						Version:           v100,
						LatestVersion:     v100,
						Retracted:         true,
						RetractionReason:  checksumReason,
						CommitTime:        time.Time{},
						ModulePath:        "",
						DeprecationReason: "",
						IsRedistributable: false,
						HasGoMod:          false,
						Deprecated:        false,
					},
				},
			},
			errors: nil,
		}
	}

	t.Run("writes the findings to the file instead of stdout", func(t *testing.T) {
		t.Parallel()

		dir := fixtureRoot("bad")
		outDir := t.TempDir()
		path := filepath.Join(outDir, "findings.txt")
		require.NoError(t, os.WriteFile(path, []byte("stale\n"), 0o600))

		var out, errOut bytes.Buffer

		opts := options{modroot: dir, format: formatText, output: path, summaryJSON: ""}
		code, err := run(
			context.Background(),
			opts,
			retractedVersions(),
			&fakeVulnsClient{responses: nil, errors: nil},
			&out,
			&errOut,
		)
		require.NoError(t, err)
		assert.Equal(t, exitcode.Findings, code)
		assert.Empty(t, out.String())

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, "warning: gomodscan/retracted: example.com/bad@v1.0.0 reason=checksum\n", string(got))
		assert.Equal(t, []string{"findings.txt"}, dirEntries(t, outDir), "no temporary file should remain")
		assert.Equal(t, "gomodscan: 1 finding(s) across 1 module(s)\n", errOut.String())
	})

	t.Run("a read-only directory fails the run and leaves no file", func(t *testing.T) {
		t.Parallel()

		dir := fixtureRoot("bad")
		outDir := readOnlyDir(t)

		var out, errOut bytes.Buffer

		opts := options{
			modroot:     dir,
			format:      formatSARIF,
			output:      filepath.Join(outDir, "findings.sarif"),
			summaryJSON: "",
		}
		code, err := run(
			context.Background(),
			opts,
			retractedVersions(),
			&fakeVulnsClient{responses: nil, errors: nil},
			&out,
			&errOut,
		)
		require.NoError(t, err)
		assert.Equal(t, exitcode.ToolFailure, code)
		// The write error prints ahead of the stderr summary, which stays last.
		lines := stderrLines(errOut.String())
		require.Len(t, lines, 2)
		assert.True(t, strings.HasPrefix(lines[0], "gomodscan: emit findings: create temp file"), lines[0])
		assert.Equal(t, "gomodscan: 1 finding(s) across 1 module(s)", lines[1])
		assert.Empty(t, out.String())
		assert.Empty(t, dirEntries(t, outDir))
	})

	t.Run("a failed rename removes the temporary file", func(t *testing.T) {
		t.Parallel()

		dir := fixtureRoot("bad")
		outDir := t.TempDir()
		// A non-empty directory at the target path makes the final rename
		// fail after the temporary file has been written and synced.
		target := filepath.Join(outDir, "findings.txt")
		require.NoError(t, os.MkdirAll(filepath.Join(target, "occupied"), 0o750))

		var out, errOut bytes.Buffer

		opts := options{modroot: dir, format: formatText, output: target, summaryJSON: ""}
		code, err := run(
			context.Background(),
			opts,
			retractedVersions(),
			&fakeVulnsClient{responses: nil, errors: nil},
			&out,
			&errOut,
		)
		require.NoError(t, err)
		assert.Equal(t, exitcode.ToolFailure, code)
		assert.Contains(t, errOut.String(), "gomodscan: emit findings: replace "+target)
		assert.Equal(t, []string{"findings.txt"}, dirEntries(t, outDir), "the temporary file should be gone")
	})

	t.Run("an unknown format leaves the output file untouched", func(t *testing.T) {
		t.Parallel()

		dir := fixtureRoot("bad")
		outDir := t.TempDir()

		var out, errOut bytes.Buffer

		opts := options{
			modroot:     dir,
			format:      formatJSON,
			output:      filepath.Join(outDir, "findings.json"),
			summaryJSON: "",
		}
		code, err := run(
			context.Background(),
			opts,
			retractedVersions(),
			&fakeVulnsClient{responses: nil, errors: nil},
			&out,
			&errOut,
		)
		require.Error(t, err)
		assert.Equal(t, exitcode.ToolFailure, code)
		assert.Empty(t, dirEntries(t, outDir))
	})
}

//nolint:dupl // table-driven cases repeat setup and assertions by design
func TestRun_EmptySARIF(t *testing.T) {
	t.Parallel()

	// assertEmptySARIF checks for a valid v2.1.0 document containing one run
	// with the gomodscan driver and an empty, non-null results array.
	assertEmptySARIF := func(t *testing.T, data []byte) {
		t.Helper()

		var doc struct {
			Version string `json:"version"`
			Runs    []struct {
				Tool struct {
					Driver struct {
						Name string `json:"name"`
					} `json:"driver"`
				} `json:"tool"`
				Results []json.RawMessage `json:"results"`
			} `json:"runs"`
		}
		require.NoError(t, json.Unmarshal(data, &doc))
		assert.Equal(t, "2.1.0", doc.Version)
		require.Len(t, doc.Runs, 1)
		assert.Equal(t, toolName, doc.Runs[0].Tool.Driver.Name)
		assert.NotNil(t, doc.Runs[0].Results, "results must be an empty array, not null")
		assert.Empty(t, doc.Runs[0].Results)
	}

	t.Run("to stdout", func(t *testing.T) {
		t.Parallel()

		dir := fixtureRoot("empty")

		var out, errOut bytes.Buffer

		code, err := run(
			context.Background(),
			options{modroot: dir, format: formatSARIF, output: "", summaryJSON: ""},
			&fakeVersionsClient{
				responses: nil,
				errors:    nil,
			},
			&fakeVulnsClient{responses: nil, errors: nil},
			&out,
			&errOut,
		)
		require.NoError(t, err)
		assert.Equal(t, exitcode.OK, code)
		assertEmptySARIF(t, out.Bytes())
		assert.Equal(t, "gomodscan: scanned 0 module(s), no findings\n", errOut.String())
	})

	t.Run("to a file", func(t *testing.T) {
		t.Parallel()

		dir := fixtureRoot("empty")
		path := filepath.Join(t.TempDir(), "gomodscan.sarif")

		var out, errOut bytes.Buffer

		code, err := run(
			context.Background(),
			options{modroot: dir, format: formatSARIF, output: path, summaryJSON: ""},
			&fakeVersionsClient{
				responses: nil,
				errors:    nil,
			},
			&fakeVulnsClient{responses: nil, errors: nil},
			&out,
			&errOut,
		)
		require.NoError(t, err)
		assert.Equal(t, exitcode.OK, code)
		assert.Empty(t, out.String())

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assertEmptySARIF(t, data)
	})
}

//nolint:dupl,funlen,maintidx // scenarios repeat steps in one function that holds the whole table
func TestRun_SummaryJSON(t *testing.T) {
	t.Parallel()

	t.Run("a clean run records an empty errors array", func(t *testing.T) {
		t.Parallel()

		dir := fixtureRoot("clean")

		versions := &fakeVersionsClient{
			responses: map[string][]pkgsite.ModuleVersion{
				"example.com/clean": {
					{
						Version:           v100,
						LatestVersion:     v100,
						CommitTime:        time.Time{},
						ModulePath:        "",
						DeprecationReason: "",
						RetractionReason:  "",
						IsRedistributable: false,
						HasGoMod:          false,
						Deprecated:        false,
						Retracted:         false,
					},
				},
			},
			errors: nil,
		}
		path := filepath.Join(t.TempDir(), "summary.json")

		var out, errOut bytes.Buffer

		opts := options{modroot: dir, format: formatText, summaryJSON: path, output: ""}
		code, err := run(
			context.Background(),
			opts,
			versions,
			&fakeVulnsClient{responses: nil, errors: nil},
			&out,
			&errOut,
		)
		require.NoError(t, err)
		assert.Equal(t, exitcode.OK, code)

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.JSONEq(t,
			`{"schema":1,"version":"`+buildmeta.Get().Version+
				`","modules":1,"findings":0,"unevaluated":0,"errors":[],"error":null}`,
			string(got),
		)
		assert.Contains(t, string(got), `"errors":[]`, "errors must be an empty array, not null")
		assert.Contains(t, string(got), `"error":null`, "a run whose scan ran records a null error")
	})

	t.Run("an exit-2 run still writes the summary with every failed lookup", func(t *testing.T) {
		t.Parallel()

		dir := fixtureRoot("bad-explode")

		versions := &fakeVersionsClient{
			responses: map[string][]pkgsite.ModuleVersion{
				modBad: {
					{
						Version:           v100,
						LatestVersion:     v100,
						Retracted:         true,
						RetractionReason:  checksumReason,
						CommitTime:        time.Time{},
						ModulePath:        "",
						DeprecationReason: "",
						IsRedistributable: false,
						HasGoMod:          false,
						Deprecated:        false,
					},
				},
			},
			errors: map[string]error{modExplode: exhaustedLookup()},
		}
		vulns := &fakeVulnsClient{
			errors: map[string]error{
				modExplodeAt: &retryhttp.Error{
					Err:        errQueryFailure,
					Attempts:   retryhttp.MaxRetries + 1,
					LastStatus: 0,
				},
			},
			responses: nil,
		}
		path := filepath.Join(t.TempDir(), "summary.json")

		var out, errOut bytes.Buffer

		opts := options{modroot: dir, format: formatText, summaryJSON: path, output: ""}
		code, err := run(context.Background(), opts, versions, vulns, &out, &errOut)
		require.NoError(t, err)
		assert.Equal(t, exitcode.ToolFailure, code)

		got, err := os.ReadFile(path)
		require.NoError(t, err)

		var sum summary
		require.NoError(t, json.Unmarshal(got, &sum))
		assert.Equal(t, summary{
			Schema:      1,
			Version:     buildmeta.Get().Version,
			Modules:     2,
			Findings:    1,
			Unevaluated: 1,
			Errors: []lookupError{
				{
					Module:     modExplodeAt,
					Lookup:     "versions",
					Error:      "lookup versions: " + exhaustedLookupMessage,
					Attempts:   4,
					LastStatus: http.StatusServiceUnavailable,
				},
				{
					Module:     modExplodeAt,
					Lookup:     "vulns",
					Error:      "lookup vulns: network failure (attempts: 4, last status: 0, no HTTP response)",
					Attempts:   4,
					LastStatus: 0,
				},
			},
			Error: nil,
		}, sum)
		assert.Contains(t, string(got), `"last_status":0`, "a missing HTTP response records last_status 0")
		assert.Contains(t, string(got), `"error":null`, "an exit-2 run whose scan ran records a null error")
	})

	t.Run("each failed lookup names its registry call", func(t *testing.T) {
		t.Parallel()

		dir := fixtureRoot("a-b")

		versions := &fakeVersionsClient{errors: map[string]error{modA: errLookupFailure}, responses: nil}
		vulns := &fakeVulnsClient{errors: map[string]error{"example.com/b@v1.0.0": errQueryFailure}, responses: nil}
		path := filepath.Join(t.TempDir(), "summary.json")

		var out, errOut bytes.Buffer

		opts := options{modroot: dir, format: formatText, summaryJSON: path, output: ""}
		code, err := run(context.Background(), opts, versions, vulns, &out, &errOut)
		require.NoError(t, err)
		assert.Equal(t, exitcode.ToolFailure, code)

		got, err := os.ReadFile(path)
		require.NoError(t, err)

		var sum summary
		require.NoError(t, json.Unmarshal(got, &sum))
		require.Len(t, sum.Errors, 2)
		assert.Equal(t, "example.com/a@v1.0.0", sum.Errors[0].Module)
		assert.Equal(t, lookupVersions, sum.Errors[0].Lookup)
		assert.Equal(t, "example.com/b@v1.0.0", sum.Errors[1].Module)
		assert.Equal(t, lookupVulns, sum.Errors[1].Lookup)
		assert.Equal(t, 2, sum.Unevaluated)
		assert.Contains(t, string(got), `"lookup":"versions"`)
		assert.Contains(t, string(got), `"lookup":"vulns"`)
	})

	t.Run("a failed output write still writes the summary", func(t *testing.T) {
		t.Parallel()

		dir := fixtureRoot("empty")
		path := filepath.Join(t.TempDir(), "summary.json")

		var out, errOut bytes.Buffer

		opts := options{
			modroot:     dir,
			format:      formatText,
			output:      filepath.Join(t.TempDir(), "missing", "findings.txt"),
			summaryJSON: path,
		}
		code, err := run(
			context.Background(),
			opts,
			&fakeVersionsClient{responses: nil, errors: nil},
			&fakeVulnsClient{responses: nil, errors: nil},
			&out,
			&errOut,
		)
		require.NoError(t, err)
		assert.Equal(t, exitcode.ToolFailure, code)
		assert.FileExists(t, path)
	})

	t.Run("a failed summary write exits 2", func(t *testing.T) {
		t.Parallel()

		dir := fixtureRoot("empty")
		outDir := readOnlyDir(t)

		var out, errOut bytes.Buffer

		opts := options{
			modroot:     dir,
			format:      formatText,
			summaryJSON: filepath.Join(outDir, "summary.json"),
			output:      "",
		}
		code, err := run(
			context.Background(),
			opts,
			&fakeVersionsClient{responses: nil, errors: nil},
			&fakeVulnsClient{responses: nil, errors: nil},
			&out,
			&errOut,
		)
		require.NoError(t, err)
		assert.Equal(t, exitcode.ToolFailure, code)
		// The write error prints ahead of the stderr summary, which stays last.
		lines := stderrLines(errOut.String())
		require.Len(t, lines, 2)
		assert.True(t, strings.HasPrefix(lines[0], "gomodscan: write summary: create temp file for"), lines[0])
		assert.Equal(t, "gomodscan: scanned 0 module(s), no findings", lines[1])
		assert.Empty(t, dirEntries(t, outDir))
	})

	t.Run("both failed writes print ahead of the stderr summary", func(t *testing.T) {
		t.Parallel()

		dir := fixtureRoot("explode")

		versions := &fakeVersionsClient{
			errors:    map[string]error{modExplode: exhaustedLookup()},
			responses: nil,
		}
		outDir := readOnlyDir(t)

		var out, errOut bytes.Buffer

		opts := options{
			modroot:     dir,
			format:      formatText,
			output:      filepath.Join(outDir, "findings.txt"),
			summaryJSON: filepath.Join(outDir, "summary.json"),
		}
		code, err := run(
			context.Background(),
			opts,
			versions,
			&fakeVulnsClient{responses: nil, errors: nil},
			&out,
			&errOut,
		)
		require.NoError(t, err)
		assert.Equal(t, exitcode.ToolFailure, code)

		lines := stderrLines(errOut.String())
		require.Len(t, lines, 4)
		assert.Equal(t, "gomodscan: example.com/explode: lookup versions: "+exhaustedLookupMessage, lines[0])
		assert.True(t, strings.HasPrefix(lines[1], "gomodscan: emit findings: create temp file for"), lines[1])
		assert.True(t, strings.HasPrefix(lines[2], "gomodscan: write summary: create temp file for"), lines[2])
		assert.Equal(t, "gomodscan: 1 module(s) could not be evaluated", lines[3])
	})

	t.Run("a scan that never starts records its error", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			name string
			opts func(t *testing.T) options
			want string
		}{
			{
				name: "unreadable module set",
				opts: func(t *testing.T) options {
					t.Helper()

					return options{modroot: t.TempDir(), format: formatText, output: "", summaryJSON: ""}
				},
				want: "read vendored modules: ",
			},
			{
				name: "unknown format",
				opts: func(t *testing.T) options {
					t.Helper()

					dir := fixtureRoot("m")

					return options{modroot: dir, format: formatJSON, output: "", summaryJSON: ""}
				},
				want: `unknown -format (want text or sarif): "json"`,
			},
		}
		for _, testCase := range cases {
			t.Run(testCase.name, func(t *testing.T) {
				t.Parallel()
				opts := testCase.opts(t)
				opts.summaryJSON = filepath.Join(t.TempDir(), "summary.json")

				var out, errOut bytes.Buffer

				code, err := run(
					context.Background(),
					opts,
					&fakeVersionsClient{responses: nil, errors: nil},
					&fakeVulnsClient{responses: nil, errors: nil},
					&out,
					&errOut,
				)
				require.Error(t, err)
				assert.Equal(t, exitcode.ToolFailure, code)

				got, readErr := os.ReadFile(opts.summaryJSON)
				require.NoError(t, readErr)

				var sum summary
				require.NoError(t, json.Unmarshal(got, &sum))
				require.NotNil(t, sum.Error, "a scan that never started must record its error")
				assert.Equal(t, err.Error(), *sum.Error)
				assert.Contains(t, *sum.Error, testCase.want)
				assert.Equal(t, summarySchema, sum.Schema)
				assert.Zero(t, sum.Modules)
				assert.Zero(t, sum.Findings)
				assert.Zero(t, sum.Unevaluated)
				assert.Contains(t, string(got), `"errors":[]`, "errors must be an empty array, not null")
			})
		}
	})

	t.Run("a failed summary write before the scan still exits 2", func(t *testing.T) {
		t.Parallel()
		outDir := readOnlyDir(t)

		var out, errOut bytes.Buffer

		opts := options{
			modroot:     t.TempDir(),
			format:      formatText,
			summaryJSON: filepath.Join(outDir, "summary.json"),
			output:      "",
		}
		code, err := run(
			context.Background(),
			opts,
			&fakeVersionsClient{responses: nil, errors: nil},
			&fakeVulnsClient{responses: nil, errors: nil},
			&out,
			&errOut,
		)
		require.Error(t, err)
		assert.Equal(t, exitcode.ToolFailure, code)
		// The cause prints first, then the write error, and neither path prints
		// the stderr summary lines.
		lines := stderrLines(errOut.String())
		require.Len(t, lines, 2)
		assert.Equal(t, "gomodscan: "+err.Error(), lines[0])
		assert.True(t, strings.HasPrefix(lines[1], "gomodscan: write summary: create temp file for"), lines[1])
		assert.Empty(t, dirEntries(t, outDir))
	})
}

//nolint:funlen // one function holds the whole scenario table
func TestRealMain(t *testing.T) {
	t.Parallel()

	t.Run("unknown flag returns ToolFailure", func(t *testing.T) {
		t.Parallel()

		var out, errOut bytes.Buffer

		code := realMain([]string{flagNonsense}, &out, &errOut)
		assert.Equal(t, exitcode.ToolFailure, code)
	})

	t.Run("a bad flag after -summary-json records the parse error", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "summary.json")

		var out, errOut bytes.Buffer

		code := realMain([]string{flagSummaryJSON, path, flagNonsense}, &out, &errOut)
		assert.Equal(t, exitcode.ToolFailure, code)

		got, err := os.ReadFile(path)
		require.NoError(t, err)

		var sum summary
		require.NoError(t, json.Unmarshal(got, &sum))
		require.NotNil(t, sum.Error)
		assert.Equal(t, "flag provided but not defined: -nonsense", *sum.Error)
	})

	t.Run("a bad flag followed by a failed summary write prints the cause first", func(t *testing.T) {
		t.Parallel()
		outDir := readOnlyDir(t)

		var out, errOut bytes.Buffer

		code := realMain([]string{flagSummaryJSON, filepath.Join(outDir, "summary.json"), flagNonsense}, &out, &errOut)
		assert.Equal(t, exitcode.ToolFailure, code)

		got := errOut.String()
		cause := strings.Index(got, "flag provided but not defined: -nonsense")
		write := strings.Index(got, "gomodscan: write summary: create temp file for")
		require.GreaterOrEqual(t, cause, 0, got)
		require.GreaterOrEqual(t, write, 0, got)
		assert.Less(t, cause, write, "the flag error must print before the write error")
		assert.NotContains(t, got, "module(s)")
		assert.Empty(t, dirEntries(t, outDir))
	})

	t.Run("missing vendor tree prints the error line and returns ToolFailure", func(t *testing.T) {
		t.Parallel()

		var out, errOut bytes.Buffer

		code := realMain([]string{flagModroot, t.TempDir()}, &out, &errOut)
		assert.Equal(t, exitcode.ToolFailure, code)
		// run logs the cause of a scan that never started. Asserting the
		// prefix confirms that line printed.
		assert.Contains(t, errOut.String(), "gomodscan: read vendored modules:")
	})

	t.Run("a failed findings write returns ToolFailure", func(t *testing.T) {
		t.Parallel()
		outDir := readOnlyDir(t)

		var out, errOut bytes.Buffer

		code := realMain([]string{
			flagModroot, fixtureRoot("empty"), "-o", filepath.Join(outDir, "findings.txt"),
		}, &out, &errOut)
		assert.Equal(t, exitcode.ToolFailure, code)
		assert.Contains(t, errOut.String(), "gomodscan: emit findings:")
	})

	t.Run("short and long output flags write the file", func(t *testing.T) {
		t.Parallel()

		for _, flagName := range []string{"-o", "--output"} {
			dir := fixtureRoot("empty")
			outPath := filepath.Join(t.TempDir(), "out.sarif")
			sumPath := filepath.Join(t.TempDir(), "summary.json")

			var out, errOut bytes.Buffer

			code := realMain([]string{
				flagModroot, dir, "-format", formatSARIF, flagName, outPath, flagSummaryJSON, sumPath,
			}, &out, &errOut)
			assert.Equal(t, exitcode.OK, code, flagName)
			assert.Empty(t, out.String(), flagName)
			assert.FileExists(t, outPath, flagName)
			assert.FileExists(t, sumPath, flagName)
		}
	})

	t.Run("help documents the output and summary flags", func(t *testing.T) {
		t.Parallel()

		var out, errOut bytes.Buffer
		realMain([]string{"-h"}, &out, &errOut)
		assert.Contains(t, errOut.String(), "-o file")
		assert.Contains(t, errOut.String(), "-output file")
		assert.Contains(t, errOut.String(), "-summary-json file")
		assert.Contains(t, errOut.String(), "on every exit status (schema 1)")
	})

	t.Run("version flag prints build metadata and returns OK", func(t *testing.T) {
		t.Parallel()

		var out, errOut bytes.Buffer

		code := realMain([]string{flagVersion}, &out, &errOut)
		assert.Equal(t, exitcode.OK, code)
		assert.Contains(t, out.String(), "gomodscan ")
		assert.Contains(t, out.String(), "commit:")
		assert.Contains(t, out.String(), "date:")
	})

	t.Run("version flag writes the summary", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "summary.json")

		var out, errOut bytes.Buffer

		code := realMain([]string{flagSummaryJSON, path, flagVersion}, &out, &errOut)
		assert.Equal(t, exitcode.OK, code)
		assert.Empty(t, errOut.String())

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.JSONEq(t,
			`{"schema":1,"version":"`+buildmeta.Get().Version+
				`","modules":0,"findings":0,"unevaluated":0,"errors":[],"error":null}`,
			string(got),
		)
	})

	t.Run("version flag exits 2 when the summary write fails", func(t *testing.T) {
		t.Parallel()
		outDir := readOnlyDir(t)

		var out, errOut bytes.Buffer

		code := realMain([]string{flagVersion, flagSummaryJSON, filepath.Join(outDir, "summary.json")}, &out, &errOut)
		assert.Equal(t, exitcode.ToolFailure, code)
		assert.Contains(t, out.String(), "gomodscan ")
		assert.True(t, strings.HasPrefix(errOut.String(), "gomodscan: write summary: create temp file for"))
		assert.Empty(t, dirEntries(t, outDir))
	})
}

func TestNewVersionsClient(t *testing.T) {
	t.Parallel()

	t.Run("no-cache keeps the package default transport", func(t *testing.T) {
		t.Parallel()

		c := newVersionsClient(true, "")
		assert.Nil(t, c.HTTPClient, "with caching off the client falls back to the shared retry transport")
	})

	t.Run("caching injects a dedicated client", func(t *testing.T) {
		t.Parallel()
		c := newVersionsClient(false, t.TempDir())
		assert.NotNil(t, c.HTTPClient, "with caching on the client carries its own cache+retry transport")
		assert.Zero(
			t,
			c.HTTPClient.Timeout,
			"the retry transport bounds each attempt, so the client sets no overall timeout",
		)
	})
}

func TestNewVersionsClient_FallbackWhenNoCacheDir(t *testing.T) {
	// With no cache base on any OS, the cache directory lookup errors and the
	// constructor falls back to the plain client.
	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("LocalAppData", "")

	c := newVersionsClient(false, "")
	assert.Nil(t, c.HTTPClient, "an unresolvable cache dir falls back to the default transport")
}

const (
	checksumReason     = "checksum"
	reasonKey          = "reason"
	modB               = "example.com/b"
	useV020            = "use v0.2.0"
	malID              = "MAL-2025-0001"
	backdoorIntroduced = "Backdoor introduced"
	v200               = "v2.0.0"
	backdoor           = "Backdoor"
	modM               = "example.com/m"
	v300               = "v3.0.0"
	formatJSON         = "json"
	modBad             = "example.com/bad"
	modExplode         = "example.com/explode"
	modExplodeAt       = "example.com/explode@v2.0.0"
	flagNonsense       = "--nonsense"
	flagSummaryJSON    = "--summary-json"
	flagModroot        = "-modroot"
	flagVersion        = "-version"
)

const (
	modA = "example.com/a"
	v010 = "v0.1.0"
	v020 = "v0.2.0"
	v123 = "v1.2.3"
)

const (
	v100 = "v1.0.0"
)

var errSink = errors.New("sink closed")

// failingWriter rejects every write with errSink.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errSink }

func TestEmit_ReportsWriteErrors(t *testing.T) {
	t.Parallel()

	hits := []finding{{
		kind: kindRetracted, module: modA, version: v100, line: 1,
		latest: "", reason: "", id: "", summary: "",
	}}

	t.Run("text", func(t *testing.T) {
		t.Parallel()

		err := emitText(failingWriter{}, hits)
		require.ErrorIs(t, err, errSink)
		require.ErrorContains(t, err, "emit text finding for "+modA)
	})

	t.Run("sarif", func(t *testing.T) {
		t.Parallel()

		err := emitSARIF(failingWriter{}, hits)
		require.ErrorIs(t, err, errSink)
		require.ErrorContains(t, err, "emit sarif")
	})
}

func TestWriteFindings_EmitErrorLeavesNoFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "findings.txt")

	err := writeFindings(failingWriter{}, path, "bogus", nil)
	require.ErrorIs(t, err, errUnknownFormat)
	assert.NoFileExists(t, path)
}

// fakeTemp fails the step named by its fields, and records which steps ran.
type fakeTemp struct {
	writeErr, syncErr, closeErr error
	steps                       []string
}

func (f *fakeTemp) Write(data []byte) (int, error) {
	f.steps = append(f.steps, stepWrite)

	return len(data), f.writeErr
}

func (f *fakeTemp) Sync() error {
	f.steps = append(f.steps, stepSync)

	return f.syncErr
}

func (f *fakeTemp) Close() error {
	f.steps = append(f.steps, stepClose)

	return f.closeErr
}

func (*fakeTemp) Name() string { return "fake.tmp" }

func TestCommitTemp_StopsAtTheFirstFailedStep(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		file  *fakeTemp
		want  string
		steps []string
	}{
		{
			name:  stepWrite,
			file:  &fakeTemp{writeErr: errSink, syncErr: nil, closeErr: nil, steps: nil},
			want:  "write out: ",
			steps: []string{stepWrite},
		},
		{
			name:  stepSync,
			file:  &fakeTemp{writeErr: nil, syncErr: errSink, closeErr: nil, steps: nil},
			want:  "sync out: ",
			steps: []string{stepWrite, stepSync},
		},
		{
			name:  stepClose,
			file:  &fakeTemp{writeErr: nil, syncErr: nil, closeErr: errSink, steps: nil},
			want:  "close out: ",
			steps: []string{stepWrite, stepSync, stepClose},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := commitTemp(testCase.file, "out", []byte("data"))
			require.ErrorIs(t, err, errSink)
			require.ErrorContains(t, err, testCase.want)
			assert.Equal(t, testCase.steps, testCase.file.steps)
		})
	}
}

const (
	stepWrite = "write"
	stepSync  = "sync"
	stepClose = "close"
)

func TestResolveCacheDir(t *testing.T) {
	t.Parallel()

	t.Run("an explicit directory wins", func(t *testing.T) {
		t.Parallel()

		dir, ok := resolveCacheDir("explicit")
		assert.True(t, ok)
		assert.Equal(t, "explicit", dir)
	})

	t.Run("an empty directory resolves to the per-user default", func(t *testing.T) {
		t.Parallel()

		want, err := cachehttp.DefaultDir()
		require.NoError(t, err)
		require.NotEmpty(t, want)

		dir, ok := resolveCacheDir("")
		assert.True(t, ok)
		assert.Equal(t, want, dir)
	})
}

func TestSummaryAddError_RecordsRetryDetailOnlyForRetryErrors(t *testing.T) {
	t.Parallel()

	mod := vendormod.Module{Path: modA, Version: v100, Line: 1}

	t.Run("a plain error records no attempts or status", func(t *testing.T) {
		t.Parallel()

		sum := newSummary(1)
		sum.addError(io.Discard, mod, lookupVulns, errQueryFailure)

		require.Len(t, sum.Errors, 1)
		assert.Equal(t, lookupError{
			Module: modA + "@" + v100, Lookup: lookupVulns, Error: errQueryFailure.Error(),
			Attempts: 0, LastStatus: 0,
		}, sum.Errors[0])
	})

	t.Run("a retry error records its attempts and last status", func(t *testing.T) {
		t.Parallel()

		sum := newSummary(1)
		sum.addError(io.Discard, mod, lookupVersions, exhaustedLookup())

		require.Len(t, sum.Errors, 1)
		assert.Equal(t, retryhttp.MaxRetries+1, sum.Errors[0].Attempts)
		assert.Equal(t, http.StatusServiceUnavailable, sum.Errors[0].LastStatus)
	})
}

func TestCollectMalicious_KeepsTheAdvisorySummary(t *testing.T) {
	t.Parallel()

	mod := vendormod.Module{Path: modA, Version: v100, Line: 1}
	vulns := []osv.Vulnerability{
		{ID: malID, Summary: backdoor, Details: "", Modified: "", Published: "", Aliases: nil},
	}

	got := collectMalicious(mod, vulns)
	require.Len(t, got, 1)
	assert.Equal(t, backdoor, got[0].summary)
}

func TestRun_WrapsTheVendorReadError(t *testing.T) {
	t.Parallel()

	opts := options{modroot: t.TempDir(), format: formatText, output: "", summaryJSON: ""}

	_, err := run(
		t.Context(),
		opts,
		&fakeVersionsClient{responses: nil, errors: nil},
		&fakeVulnsClient{responses: nil, errors: nil},
		io.Discard,
		io.Discard,
	)
	require.Error(t, err)
	require.ErrorIs(t, err, fs.ErrNotExist, "the cause of the missing vendor tree stays in the error chain")
}

func TestWriteFileAtomic_WrapsTheTempFileError(t *testing.T) {
	t.Parallel()

	err := writeFileAtomic(filepath.Join(t.TempDir(), "missing", "out"), []byte("data"))
	require.ErrorIs(t, err, fs.ErrNotExist, "the cause of the failed create stays in the error chain")
}

func TestCommitTemp_WrapsTheRenameError(t *testing.T) {
	t.Parallel()

	// The fake file has no counterpart on disk, so renaming it fails.
	err := commitTemp(&fakeTemp{writeErr: nil, syncErr: nil, closeErr: nil, steps: nil}, "out", []byte("data"))
	require.ErrorIs(t, err, fs.ErrNotExist)
	require.ErrorContains(t, err, "replace out: ")
}

// swapProcessState points os.Args and os.Stdout at the given values, replaces
// the exit function, and restores all three when the test ends.
//
//nolint:reassign // main reads these process-wide variables, so the test has to swap them
func swapProcessState(t *testing.T, args []string, stdout *os.File, exitFn func(int)) {
	t.Helper()

	oldArgs, oldStdout, oldExit := os.Args, os.Stdout, exit

	t.Cleanup(func() { os.Args, os.Stdout, exit = oldArgs, oldStdout, oldExit })

	os.Args, os.Stdout, exit = args, stdout, exitFn
}

// A test can't let main call os.Exit, so it swaps the exit function and the
// process-wide arguments and stdout, which rules out running it in parallel.
//
//nolint:paralleltest // main reads os.Args and os.Stdout, which are process-wide
func TestMainPassesRealMainsStatusToExit(t *testing.T) {
	stdout, err := os.CreateTemp(t.TempDir(), "stdout")
	require.NoError(t, err)

	t.Cleanup(func() { _ = stdout.Close() })

	status := -1

	swapProcessState(t, []string{"gomodscan", flagVersion}, stdout, func(code int) { status = code })

	main()

	assert.Equal(t, exitcode.OK, status)

	printed, err := os.ReadFile(stdout.Name())
	require.NoError(t, err)
	assert.Contains(t, string(printed), "gomodscan ")
}
