// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbhb-dev/gomodscan/internal/buildmeta"
	"github.com/tbhb-dev/gomodscan/internal/exitcode"
	"github.com/tbhb-dev/gomodscan/internal/findings"
	"github.com/tbhb-dev/gomodscan/internal/osv"
	"github.com/tbhb-dev/gomodscan/internal/pkgsite"
	"github.com/tbhb-dev/gomodscan/internal/retryhttp"
	"github.com/tbhb-dev/gomodscan/internal/vendormod"
)

// errLookupFailure stands in for any non-not-found pkg.go.dev lookup
// error the fake client surfaces. Declared once so err113 never fires.
var errLookupFailure = errors.New("network failure")

// errQueryFailure stands in for any OSV-side error the stub surfaces
// back to the scanner.
var errQueryFailure = errors.New("network failure")

// fakeVersionsClient drives the deprecated scanner from tests by
// returning a canned response (or error) per module path. The interface
// keeps run injectable so the table-driven cases below don't need to
// stand up an httptest server for every branch.
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

func TestFindingLevel(t *testing.T) {
	t.Parallel()
	assert.Equal(t, findings.LevelError, finding{kind: kindMalicious}.level())
	assert.Equal(t, findings.LevelWarning, finding{kind: kindRetracted}.level())
	assert.Equal(t, findings.LevelWarning, finding{kind: kindDeprecated}.level())
}

func TestFindingProps(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		f    finding
		want map[string]string
	}{
		{
			name: "retracted with reason",
			f:    finding{kind: kindRetracted, module: "example.com/a", version: "v1.0.0", reason: "checksum"},
			want: map[string]string{"reason": "checksum"},
		},
		{
			name: "retracted without reason",
			f:    finding{kind: kindRetracted, module: "example.com/a", version: "v1.0.0"},
			want: map[string]string{},
		},
		{
			name: "reason whitespace trimmed",
			f:    finding{kind: kindRetracted, module: "example.com/a", version: "v1.0.0", reason: "  checksum  \n"},
			want: map[string]string{"reason": "checksum"},
		},
		{
			name: "deprecated emits latest and reason",
			f: finding{
				kind: kindDeprecated, module: "example.com/b", version: "v0.1.0",
				latest: "v0.2.0", reason: "use v0.2.0",
			},
			want: map[string]string{"latest": "v0.2.0", "reason": "use v0.2.0"},
		},
		{
			name: "malicious id only when summary missing",
			f:    finding{kind: kindMalicious, module: "example.com/a", version: "v1.0.0", id: "MAL-2025-0001"},
			want: map[string]string{"id": "MAL-2025-0001"},
		},
		{
			name: "malicious id plus trimmed summary",
			f: finding{
				kind: kindMalicious, module: "example.com/a", version: "v1.0.0", id: "MAL-2025-0001",
				summary: "  Backdoor introduced  ",
			},
			want: map[string]string{"id": "MAL-2025-0001", "summary": "Backdoor introduced"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.f.props())
		})
	}
}

func TestFindingMessage(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"Module retracted at v1.0.0. Reason: checksum.",
		finding{kind: kindRetracted, module: "example.com/a", version: "v1.0.0", reason: "checksum"}.message(),
	)
	assert.Equal(t,
		"Module retracted at v1.0.0. No reason recorded.",
		finding{kind: kindRetracted, module: "example.com/a", version: "v1.0.0"}.message(),
	)
	assert.Equal(t,
		"Module deprecated at latest version v0.2.0. Reason: use v0.2.0.",
		finding{
			kind: kindDeprecated, module: "example.com/b", version: "v0.1.0",
			latest: "v0.2.0", reason: "use v0.2.0",
		}.message(),
	)
	assert.Equal(t,
		"OSV malicious-package advisory MAL-2025-0001.",
		finding{kind: kindMalicious, id: "MAL-2025-0001"}.message(),
	)
	assert.Equal(t,
		"OSV malicious-package advisory MAL-2025-0001: Backdoor introduced.",
		finding{kind: kindMalicious, id: "MAL-2025-0001", summary: "Backdoor introduced"}.message(),
	)
	assert.Equal(t, "Unknown finding.", finding{kind: findingKind("other")}.message())
}

func TestEmitText_UnifiedFormat(t *testing.T) {
	t.Parallel()

	hits := []finding{
		{kind: kindRetracted, module: "example.com/a", version: "v1.0.0", reason: "checksum"},
		{
			kind: kindDeprecated, module: "example.com/b", version: "v0.1.0",
			latest: "v0.2.0", reason: "use v0.2.0",
		},
		{
			kind:    kindMalicious,
			module:  "example.com/c",
			version: "v2.0.0",
			id:      "MAL-2025-0001",
			summary: "Backdoor introduced",
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
		{kind: kindRetracted, module: "example.com/a", version: "v1.0.0", line: 10, reason: "checksum"},
		{
			kind: kindDeprecated, module: "example.com/b", version: "v0.1.0", line: 14,
			latest: "v0.2.0", reason: "use v0.2.0",
		},
		{
			kind:    kindMalicious,
			module:  "example.com/c",
			version: "v2.0.0",
			line:    18,
			id:      "MAL-2025-0001",
			summary: "Backdoor",
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
	// Every result carries the vendor manifest as its physical
	// location, with the module's line threaded onto the region so
	// Code Scanning anchors each finding on the real file.
	assert.Contains(t, out, `"uri": "vendor/modules.txt"`)
	assert.Contains(t, out, `"startLine": 10`)
	assert.Contains(t, out, `"startLine": 14`)
	assert.Contains(t, out, `"startLine": 18`)
}

func TestEmitFindings_UnknownFormatErrors(t *testing.T) {
	t.Parallel()
	err := emitFindings(&bytes.Buffer{}, "json", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown -format")
}

func TestCollectDeprecated(t *testing.T) {
	t.Parallel()

	mod := vendormod.Module{Path: "example.com/m", Version: "v1.2.3", Line: 5}

	t.Run("empty version list yields no hits", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, collectDeprecated(mod, nil))
	})

	t.Run("non-matching versions yield no hits", func(t *testing.T) {
		t.Parallel()
		versions := []pkgsite.ModuleVersion{
			{Version: "v1.2.3", LatestVersion: "v2.0.0", Retracted: false, Deprecated: false},
			{Version: "v2.0.0", LatestVersion: "v2.0.0", Retracted: false, Deprecated: false},
		}
		assert.Nil(t, collectDeprecated(mod, versions))
	})

	t.Run("matching retracted version emits a retracted finding", func(t *testing.T) {
		t.Parallel()
		versions := []pkgsite.ModuleVersion{
			{Version: "v2.0.0", LatestVersion: "v2.0.0", Retracted: false, Deprecated: false},
			{Version: "v1.2.3", LatestVersion: "v2.0.0", Retracted: true, RetractionReason: "checksum"},
		}
		got := collectDeprecated(mod, versions)
		require.Len(t, got, 1)
		assert.Equal(t, kindRetracted, got[0].kind)
		assert.Equal(t, "v1.2.3", got[0].version)
		assert.Equal(t, "checksum", got[0].reason)
	})

	t.Run("retracted at a different version is ignored", func(t *testing.T) {
		t.Parallel()
		versions := []pkgsite.ModuleVersion{
			{Version: "v2.0.0", LatestVersion: "v2.0.0", Retracted: false},
			{Version: "v1.0.0", LatestVersion: "v2.0.0", Retracted: true, RetractionReason: "checksum"},
		}
		assert.Nil(t, collectDeprecated(mod, versions))
	})

	t.Run("latest version deprecated emits a deprecated finding", func(t *testing.T) {
		t.Parallel()
		versions := []pkgsite.ModuleVersion{
			{Version: "v3.0.0", LatestVersion: "v3.0.0", Deprecated: true, DeprecationReason: "use v4"},
			{Version: "v1.2.3", LatestVersion: "v3.0.0", Deprecated: false},
		}
		got := collectDeprecated(mod, versions)
		require.Len(t, got, 1)
		assert.Equal(t, kindDeprecated, got[0].kind)
		assert.Equal(t, "v3.0.0", got[0].latest)
		assert.Equal(t, "use v4", got[0].reason)
	})

	t.Run("deprecation on a non-latest version is ignored", func(t *testing.T) {
		t.Parallel()
		versions := []pkgsite.ModuleVersion{
			{Version: "v3.0.0", LatestVersion: "v3.0.0", Deprecated: false},
			{Version: "v1.2.3", LatestVersion: "v3.0.0", Deprecated: true, DeprecationReason: "use v3"},
		}
		assert.Nil(t, collectDeprecated(mod, versions))
	})

	t.Run("matching retraction and latest deprecation emit both findings", func(t *testing.T) {
		t.Parallel()
		versions := []pkgsite.ModuleVersion{
			{Version: "v2.0.0", LatestVersion: "v2.0.0", Deprecated: true, DeprecationReason: "use v3"},
			{Version: "v1.2.3", LatestVersion: "v2.0.0", Retracted: true, RetractionReason: "checksum"},
		}
		got := collectDeprecated(mod, versions)
		require.Len(t, got, 2)
		// Order tracks the version slice: deprecated entry comes first.
		assert.Equal(t, kindDeprecated, got[0].kind)
		assert.Equal(t, kindRetracted, got[1].kind)
		// Both findings carry the module's manifest line.
		assert.Equal(t, mod.Line, got[0].line)
		assert.Equal(t, mod.Line, got[1].line)
	})
}

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
				{ID: "GO-2025-0042", Summary: "Generic vuln"},
				{ID: "GHSA-aaaa-bbbb-cccc"},
				{ID: "CVE-2025-12345"},
			},
			wantIDs: nil,
		},
		{
			name: "MAL-prefixed advisories surface; siblings drop out",
			vulns: []osv.Vulnerability{
				{ID: "GO-2025-0042"},
				{ID: "MAL-2025-0007", Summary: "Backdoor introduced upstream"},
				{ID: "MAL-2025-0008"},
			},
			wantIDs: []string{"MAL-2025-0007", "MAL-2025-0008"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := collectMalicious(mod, tc.vulns)
			require.Len(t, got, len(tc.wantIDs))
			for i, want := range tc.wantIDs {
				assert.Equal(t, want, got[i].id)
				assert.Equal(t, kindMalicious, got[i].kind)
				assert.Equal(t, mod.Path, got[i].module)
				assert.Equal(t, mod.Version, got[i].version)
				assert.Equal(t, mod.Line, got[i].line)
			}
		})
	}
}

func TestEvaluateDeprecated(t *testing.T) {
	t.Parallel()

	mod := vendormod.Module{Path: "example.com/m", Version: "v1.0.0"}

	t.Run("not-found error is swallowed as a skip", func(t *testing.T) {
		t.Parallel()
		client := &fakeVersionsClient{errors: map[string]error{
			mod.Path: fmt.Errorf("%w: %s", pkgsite.ErrNotFound, mod.Path),
		}}
		got, err := evaluateDeprecated(context.Background(), client, mod)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("other errors propagate wrapped", func(t *testing.T) {
		t.Parallel()
		client := &fakeVersionsClient{errors: map[string]error{mod.Path: errLookupFailure}}
		got, err := evaluateDeprecated(context.Background(), client, mod)
		require.Error(t, err)
		require.ErrorIs(t, err, errLookupFailure)
		assert.Contains(t, err.Error(), "lookup versions")
		assert.Nil(t, got)
	})

	t.Run("happy path forwards to collectDeprecated", func(t *testing.T) {
		t.Parallel()
		client := &fakeVersionsClient{responses: map[string][]pkgsite.ModuleVersion{
			mod.Path: {{Version: "v1.0.0", LatestVersion: "v1.0.0", Retracted: true, RetractionReason: "bad"}},
		}}
		got, err := evaluateDeprecated(context.Background(), client, mod)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, kindRetracted, got[0].kind)
	})
}

func TestEvaluateMalicious(t *testing.T) {
	t.Parallel()

	mod := vendormod.Module{Path: "example.com/m", Version: "v1.0.0"}
	key := mod.Path + "@" + mod.Version

	t.Run("network errors propagate wrapped", func(t *testing.T) {
		t.Parallel()
		client := &fakeVulnsClient{errors: map[string]error{key: errQueryFailure}}
		got, err := evaluateMalicious(context.Background(), client, mod)
		require.Error(t, err)
		require.ErrorIs(t, err, errQueryFailure)
		assert.Contains(t, err.Error(), "lookup vulns")
		assert.Nil(t, got)
	})

	t.Run("happy path forwards to collectMalicious", func(t *testing.T) {
		t.Parallel()
		client := &fakeVulnsClient{responses: map[string][]osv.Vulnerability{
			key: {{ID: "MAL-2025-0001", Summary: "Backdoor"}},
		}}
		got, err := evaluateMalicious(context.Background(), client, mod)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "MAL-2025-0001", got[0].id)
	})

	t.Run("empty response yields no findings", func(t *testing.T) {
		t.Parallel()
		client := &fakeVulnsClient{} // any key returns nil, nil from the fake
		got, err := evaluateMalicious(context.Background(), client, mod)
		require.NoError(t, err)
		assert.Nil(t, got)
	})
}

// writeVendorModulesTxt drops a minimal vendor/modules.txt under dir so
// the run-level tests can drive vendormod.Read without spinning up a
// full go module.
func writeVendorModulesTxt(t *testing.T, dir, body string) {
	t.Helper()
	vendorDir := filepath.Join(dir, "vendor")
	require.NoError(t, os.MkdirAll(vendorDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(vendorDir, "modules.txt"), []byte(body), 0o600))
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

// dirEntries lists the names under dir, so a test can assert a failed write
// left no temporary file behind.
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

// readOnlyDir returns a directory the test process can't create files in.
// It skips the test where permission bits don't stop the writer: on Windows,
// and as root. The directory stays empty, so t.TempDir's cleanup removes it
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

func TestRun(t *testing.T) {
	t.Parallel()

	t.Run("returns ToolFailure when modroot lacks vendor/modules.txt", func(t *testing.T) {
		t.Parallel()
		var out, errOut bytes.Buffer
		rc, err := run(
			context.Background(),
			options{modroot: t.TempDir(), format: formatText},
			&fakeVersionsClient{},
			&fakeVulnsClient{},
			&out,
			&errOut,
		)
		require.Error(t, err)
		assert.Equal(t, exitcode.ToolFailure, rc)
		assert.Contains(t, err.Error(), "read vendored modules")
	})

	t.Run("returns ToolFailure on an unknown -format", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir, "# example.com/m v1.0.0\n## explicit\nexample.com/m\n")
		versions := &fakeVersionsClient{responses: map[string][]pkgsite.ModuleVersion{
			"example.com/m": {{Version: "v1.0.0", LatestVersion: "v1.0.0"}},
		}}
		var out, errOut bytes.Buffer
		rc, err := run(
			context.Background(),
			options{modroot: dir, format: "json"},
			versions,
			&fakeVulnsClient{},
			&out,
			&errOut,
		)
		require.Error(t, err)
		assert.Equal(t, exitcode.ToolFailure, rc)
		require.ErrorIs(t, err, errUnknownFormat)
		assert.Empty(t, out.String())
	})

	t.Run("returns OK with the no-findings banner when nothing matches", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir, "# example.com/clean v1.0.0\n## explicit\nexample.com/clean\n")
		versions := &fakeVersionsClient{responses: map[string][]pkgsite.ModuleVersion{
			"example.com/clean": {{Version: "v1.0.0", LatestVersion: "v1.0.0"}},
		}}
		vulns := &fakeVulnsClient{responses: map[string][]osv.Vulnerability{
			"example.com/clean@v1.0.0": {{ID: "GO-2025-0001"}},
		}}
		var out, errOut bytes.Buffer
		rc, err := run(context.Background(), options{modroot: dir, format: formatText}, versions, vulns, &out, &errOut)
		require.NoError(t, err)
		assert.Equal(t, exitcode.OK, rc)
		assert.Empty(t, out.String())
		assert.Equal(t, "gomodscan: scanned 1 module(s), no findings\n", errOut.String())
	})

	t.Run("returns Findings with both scanners contributing for one module", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir, "# example.com/bad v1.0.0\n## explicit\nexample.com/bad\n")
		versions := &fakeVersionsClient{responses: map[string][]pkgsite.ModuleVersion{
			"example.com/bad": {
				{Version: "v1.0.0", LatestVersion: "v1.0.0", Retracted: true, RetractionReason: "checksum"},
			},
		}}
		vulns := &fakeVulnsClient{responses: map[string][]osv.Vulnerability{
			"example.com/bad@v1.0.0": {{ID: "MAL-2025-0001", Summary: "Backdoor"}},
		}}
		var out, errOut bytes.Buffer
		rc, err := run(context.Background(), options{modroot: dir, format: formatText}, versions, vulns, &out, &errOut)
		require.NoError(t, err)
		assert.Equal(t, exitcode.Findings, rc)
		assert.Contains(t, out.String(), "warning: gomodscan/retracted: example.com/bad@v1.0.0")
		assert.Contains(t, out.String(), "error: gomodscan/malicious-package: example.com/bad@v1.0.0")
		assert.Equal(t, "gomodscan: 2 finding(s) across 1 module(s)\n", errOut.String())
	})

	t.Run("returns ToolFailure when a module can't be evaluated", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir,
			"# example.com/ok v1.0.0\n## explicit\nexample.com/ok\n"+
				"# example.com/explode v2.0.0\n## explicit\nexample.com/explode\n",
		)
		versions := &fakeVersionsClient{
			responses: map[string][]pkgsite.ModuleVersion{
				"example.com/ok": {{Version: "v1.0.0", LatestVersion: "v1.0.0"}},
			},
			errors: map[string]error{"example.com/explode": exhaustedLookup()},
		}
		vulns := &fakeVulnsClient{
			errors: map[string]error{"example.com/explode@v2.0.0": errQueryFailure},
		}
		var out, errOut bytes.Buffer
		rc, err := run(context.Background(), options{modroot: dir, format: formatText}, versions, vulns, &out, &errOut)
		require.NoError(t, err)
		assert.Equal(t, exitcode.ToolFailure, rc)
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
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir,
			"# example.com/bad v1.0.0\n## explicit\nexample.com/bad\n"+
				"# example.com/explode v2.0.0\n## explicit\nexample.com/explode\n",
		)
		versions := &fakeVersionsClient{
			responses: map[string][]pkgsite.ModuleVersion{
				"example.com/bad": {
					{Version: "v1.0.0", LatestVersion: "v1.0.0", Retracted: true, RetractionReason: "checksum"},
				},
			},
			errors: map[string]error{"example.com/explode": exhaustedLookup()},
		}
		var out, errOut bytes.Buffer
		rc, err := run(
			context.Background(),
			options{modroot: dir, format: formatText},
			versions,
			&fakeVulnsClient{},
			&out,
			&errOut,
		)
		require.NoError(t, err)
		assert.Equal(t, exitcode.ToolFailure, rc)
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
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir, "# example.com/private v1.0.0\n## explicit\nexample.com/private\n")
		// The fakes return ErrNotFound (versions) and an empty result
		// (vulns) for any module path they don't recognize.
		var out, errOut bytes.Buffer
		rc, err := run(
			context.Background(),
			options{modroot: dir, format: formatText},
			&fakeVersionsClient{},
			&fakeVulnsClient{},
			&out,
			&errOut,
		)
		require.NoError(t, err)
		assert.Equal(t, exitcode.OK, rc)
		assert.NotContains(t, errOut.String(), "lookup versions")
		assert.Contains(t, errOut.String(), "scanned 1 module(s), no findings")
	})
}

func TestRun_Output(t *testing.T) {
	t.Parallel()

	retractedVersions := func() *fakeVersionsClient {
		return &fakeVersionsClient{responses: map[string][]pkgsite.ModuleVersion{
			"example.com/bad": {
				{Version: "v1.0.0", LatestVersion: "v1.0.0", Retracted: true, RetractionReason: "checksum"},
			},
		}}
	}
	const badModule = "# example.com/bad v1.0.0\n## explicit\nexample.com/bad\n"

	t.Run("writes the findings to the file instead of stdout", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir, badModule)
		outDir := t.TempDir()
		path := filepath.Join(outDir, "findings.txt")
		require.NoError(t, os.WriteFile(path, []byte("stale\n"), 0o600))

		var out, errOut bytes.Buffer
		opts := options{modroot: dir, format: formatText, output: path}
		rc, err := run(context.Background(), opts, retractedVersions(), &fakeVulnsClient{}, &out, &errOut)
		require.NoError(t, err)
		assert.Equal(t, exitcode.Findings, rc)
		assert.Empty(t, out.String())
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, "warning: gomodscan/retracted: example.com/bad@v1.0.0 reason=checksum\n", string(got))
		assert.Equal(t, []string{"findings.txt"}, dirEntries(t, outDir), "no temporary file should remain")
		assert.Equal(t, "gomodscan: 1 finding(s) across 1 module(s)\n", errOut.String())
	})

	t.Run("a read-only directory fails the run and leaves no file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir, badModule)
		outDir := readOnlyDir(t)

		var out, errOut bytes.Buffer
		opts := options{modroot: dir, format: formatSARIF, output: filepath.Join(outDir, "findings.sarif")}
		rc, err := run(context.Background(), opts, retractedVersions(), &fakeVulnsClient{}, &out, &errOut)
		require.Error(t, err)
		assert.Equal(t, exitcode.ToolFailure, rc)
		require.ErrorIs(t, err, os.ErrPermission)
		assert.Contains(t, err.Error(), "emit findings: create temp file")
		assert.Empty(t, out.String())
		assert.Empty(t, dirEntries(t, outDir))
	})

	t.Run("a failed rename removes the temporary file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir, badModule)
		outDir := t.TempDir()
		// A non-empty directory at the target path makes the final rename
		// fail after the temporary file has been written and synced.
		target := filepath.Join(outDir, "findings.txt")
		require.NoError(t, os.MkdirAll(filepath.Join(target, "occupied"), 0o750))

		var out, errOut bytes.Buffer
		opts := options{modroot: dir, format: formatText, output: target}
		rc, err := run(context.Background(), opts, retractedVersions(), &fakeVulnsClient{}, &out, &errOut)
		require.Error(t, err)
		assert.Equal(t, exitcode.ToolFailure, rc)
		assert.Contains(t, err.Error(), "emit findings: replace "+target)
		assert.Equal(t, []string{"findings.txt"}, dirEntries(t, outDir), "the temporary file should be gone")
	})

	t.Run("an unknown format leaves the output file untouched", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir, badModule)
		outDir := t.TempDir()

		var out, errOut bytes.Buffer
		opts := options{modroot: dir, format: "json", output: filepath.Join(outDir, "findings.json")}
		rc, err := run(context.Background(), opts, retractedVersions(), &fakeVulnsClient{}, &out, &errOut)
		require.Error(t, err)
		assert.Equal(t, exitcode.ToolFailure, rc)
		assert.Empty(t, dirEntries(t, outDir))
	})
}

func TestRun_EmptySARIF(t *testing.T) {
	t.Parallel()

	// assertEmptySARIF checks for a valid v2.1.0 document holding one run
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
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir, "")
		var out, errOut bytes.Buffer
		rc, err := run(
			context.Background(), options{modroot: dir, format: formatSARIF},
			&fakeVersionsClient{}, &fakeVulnsClient{}, &out, &errOut,
		)
		require.NoError(t, err)
		assert.Equal(t, exitcode.OK, rc)
		assertEmptySARIF(t, out.Bytes())
		assert.Equal(t, "gomodscan: scanned 0 module(s), no findings\n", errOut.String())
	})

	t.Run("to a file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir, "")
		path := filepath.Join(t.TempDir(), "gomodscan.sarif")
		var out, errOut bytes.Buffer
		rc, err := run(
			context.Background(), options{modroot: dir, format: formatSARIF, output: path},
			&fakeVersionsClient{}, &fakeVulnsClient{}, &out, &errOut,
		)
		require.NoError(t, err)
		assert.Equal(t, exitcode.OK, rc)
		assert.Empty(t, out.String())
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assertEmptySARIF(t, data)
	})
}

func TestRun_SummaryJSON(t *testing.T) {
	t.Parallel()

	t.Run("a clean run records an empty errors array", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir, "# example.com/clean v1.0.0\n## explicit\nexample.com/clean\n")
		versions := &fakeVersionsClient{responses: map[string][]pkgsite.ModuleVersion{
			"example.com/clean": {{Version: "v1.0.0", LatestVersion: "v1.0.0"}},
		}}
		path := filepath.Join(t.TempDir(), "summary.json")
		var out, errOut bytes.Buffer
		opts := options{modroot: dir, format: formatText, summaryJSON: path}
		rc, err := run(context.Background(), opts, versions, &fakeVulnsClient{}, &out, &errOut)
		require.NoError(t, err)
		assert.Equal(t, exitcode.OK, rc)
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
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir,
			"# example.com/bad v1.0.0\n## explicit\nexample.com/bad\n"+
				"# example.com/explode v2.0.0\n## explicit\nexample.com/explode\n",
		)
		versions := &fakeVersionsClient{
			responses: map[string][]pkgsite.ModuleVersion{
				"example.com/bad": {
					{Version: "v1.0.0", LatestVersion: "v1.0.0", Retracted: true, RetractionReason: "checksum"},
				},
			},
			errors: map[string]error{"example.com/explode": exhaustedLookup()},
		}
		vulns := &fakeVulnsClient{errors: map[string]error{
			"example.com/explode@v2.0.0": &retryhttp.Error{Err: errQueryFailure, Attempts: retryhttp.MaxRetries + 1},
		}}
		path := filepath.Join(t.TempDir(), "summary.json")
		var out, errOut bytes.Buffer
		opts := options{modroot: dir, format: formatText, summaryJSON: path}
		rc, err := run(context.Background(), opts, versions, vulns, &out, &errOut)
		require.NoError(t, err)
		assert.Equal(t, exitcode.ToolFailure, rc)

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
					Module:     "example.com/explode@v2.0.0",
					Lookup:     "versions",
					Error:      "lookup versions: " + exhaustedLookupMessage,
					Attempts:   4,
					LastStatus: http.StatusServiceUnavailable,
				},
				{
					Module:   "example.com/explode@v2.0.0",
					Lookup:   "vulns",
					Error:    "lookup vulns: network failure (attempts: 4, last status: 0, no HTTP response)",
					Attempts: 4,
				},
			},
		}, sum)
		assert.Contains(t, string(got), `"last_status":0`, "a missing HTTP response records last_status 0")
		assert.Contains(t, string(got), `"error":null`, "an exit-2 run whose scan ran records a null error")
	})

	t.Run("each failed lookup names its registry call", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir,
			"# example.com/a v1.0.0\n## explicit\nexample.com/a\n"+
				"# example.com/b v1.0.0\n## explicit\nexample.com/b\n",
		)
		versions := &fakeVersionsClient{errors: map[string]error{"example.com/a": errLookupFailure}}
		vulns := &fakeVulnsClient{errors: map[string]error{"example.com/b@v1.0.0": errQueryFailure}}
		path := filepath.Join(t.TempDir(), "summary.json")
		var out, errOut bytes.Buffer
		opts := options{modroot: dir, format: formatText, summaryJSON: path}
		rc, err := run(context.Background(), opts, versions, vulns, &out, &errOut)
		require.NoError(t, err)
		assert.Equal(t, exitcode.ToolFailure, rc)

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
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir, "")
		path := filepath.Join(t.TempDir(), "summary.json")
		var out, errOut bytes.Buffer
		opts := options{
			modroot:     dir,
			format:      formatText,
			output:      filepath.Join(t.TempDir(), "missing", "findings.txt"),
			summaryJSON: path,
		}
		rc, err := run(context.Background(), opts, &fakeVersionsClient{}, &fakeVulnsClient{}, &out, &errOut)
		require.Error(t, err)
		assert.Equal(t, exitcode.ToolFailure, rc)
		assert.FileExists(t, path)
	})

	t.Run("a failed summary write exits 2", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeVendorModulesTxt(t, dir, "")
		outDir := readOnlyDir(t)
		var out, errOut bytes.Buffer
		opts := options{modroot: dir, format: formatText, summaryJSON: filepath.Join(outDir, "summary.json")}
		rc, err := run(context.Background(), opts, &fakeVersionsClient{}, &fakeVulnsClient{}, &out, &errOut)
		require.NoError(t, err)
		assert.Equal(t, exitcode.ToolFailure, rc)
		assert.Contains(t, errOut.String(), "gomodscan: write summary: create temp file for")
		assert.Empty(t, dirEntries(t, outDir))
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
					return options{modroot: t.TempDir(), format: formatText}
				},
				want: "read vendored modules: ",
			},
			{
				name: "unknown format",
				opts: func(t *testing.T) options {
					t.Helper()
					dir := t.TempDir()
					writeVendorModulesTxt(t, dir, "# example.com/m v1.0.0\n## explicit\nexample.com/m\n")
					return options{modroot: dir, format: "json"}
				},
				want: `unknown -format (want text or sarif): "json"`,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				opts := tc.opts(t)
				opts.summaryJSON = filepath.Join(t.TempDir(), "summary.json")
				var out, errOut bytes.Buffer
				rc, err := run(context.Background(), opts, &fakeVersionsClient{}, &fakeVulnsClient{}, &out, &errOut)
				require.Error(t, err)
				assert.Equal(t, exitcode.ToolFailure, rc)

				got, readErr := os.ReadFile(opts.summaryJSON)
				require.NoError(t, readErr)
				var sum summary
				require.NoError(t, json.Unmarshal(got, &sum))
				require.NotNil(t, sum.Error, "a scan that never started must record its error")
				assert.Equal(t, err.Error(), *sum.Error)
				assert.Contains(t, *sum.Error, tc.want)
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
		opts := options{modroot: t.TempDir(), format: formatText, summaryJSON: filepath.Join(outDir, "summary.json")}
		rc, err := run(context.Background(), opts, &fakeVersionsClient{}, &fakeVulnsClient{}, &out, &errOut)
		require.Error(t, err)
		assert.Equal(t, exitcode.ToolFailure, rc)
		assert.Contains(t, errOut.String(), "gomodscan: write summary: create temp file for")
		assert.Empty(t, dirEntries(t, outDir))
	})
}

func TestRealMain(t *testing.T) {
	t.Parallel()

	t.Run("unknown flag returns ToolFailure", func(t *testing.T) {
		t.Parallel()
		var out, errOut bytes.Buffer
		rc := realMain([]string{"--nonsense"}, &out, &errOut)
		assert.Equal(t, exitcode.ToolFailure, rc)
	})

	t.Run("a bad flag after -summary-json records the parse error", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "summary.json")
		var out, errOut bytes.Buffer
		rc := realMain([]string{"--summary-json", path, "--nonsense"}, &out, &errOut)
		assert.Equal(t, exitcode.ToolFailure, rc)
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		var sum summary
		require.NoError(t, json.Unmarshal(got, &sum))
		require.NotNil(t, sum.Error)
		assert.Equal(t, "flag provided but not defined: -nonsense", *sum.Error)
	})

	t.Run("missing vendor tree prints the error line and returns ToolFailure", func(t *testing.T) {
		t.Parallel()
		var out, errOut bytes.Buffer
		rc := realMain([]string{"-modroot", t.TempDir()}, &out, &errOut)
		assert.Equal(t, exitcode.ToolFailure, rc)
		// The error-log branch only fires when run returns a non-nil
		// error. Asserting the prefix confirms that branch executed.
		assert.Contains(t, errOut.String(), "gomodscan: read vendored modules:")
	})

	t.Run("short and long output flags write the file", func(t *testing.T) {
		t.Parallel()
		for _, flagName := range []string{"-o", "--output"} {
			dir := t.TempDir()
			writeVendorModulesTxt(t, dir, "")
			outPath := filepath.Join(t.TempDir(), "out.sarif")
			sumPath := filepath.Join(t.TempDir(), "summary.json")
			var out, errOut bytes.Buffer
			rc := realMain([]string{
				"-modroot", dir, "-format", formatSARIF, flagName, outPath, "--summary-json", sumPath,
			}, &out, &errOut)
			assert.Equal(t, exitcode.OK, rc, flagName)
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
		rc := realMain([]string{"-version"}, &out, &errOut)
		assert.Equal(t, exitcode.OK, rc)
		assert.Contains(t, out.String(), "gomodscan ")
		assert.Contains(t, out.String(), "commit:")
		assert.Contains(t, out.String(), "date:")
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
