// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

// Command gomodscan scans the modules a Go project vendors. One pass
// covers two supply chain concerns. The first is a dependency that
// pkg.go.dev marks as retracted at the pinned version or deprecated at
// its latest version (S2C2F SCA-3). The second is a dependency that the
// OSV malicious-package registry flags as malware (S2C2F ING-3).
//
// Usage:
//
//	gomodscan [-modroot dir] [-format text|sarif] [-o file]
//	          [-summary-json file] [-no-cache] [-cache-dir dir] [-version]
//
// gomodscan reads vendor/modules.txt under -modroot (defaults to the
// current working directory) to list the vendored module set.
// For each module it queries pkg.go.dev /v1/versions/{module} for
// deprecation and retraction status, plus the OSV /v1/query endpoint
// for malicious-package advisories under the MAL- ID prefix. Modules
// replaced to a local path fall outside both registries and get
// skipped.
//
// By default, gomodscan caches pkg.go.dev responses on disk, so a repeated
// run inside the server's one-hour freshness window avoids the network. Pass
// -no-cache to turn that off.
//
// The -format flag selects the finding emitter. Text output (the
// default) follows the unified shape documented in the [findings]
// package. SARIF output emits a v2.1.0 report suitable for ingestion by
// GitHub Code Scanning. The findings go to stdout unless -o (long form
// -output) names a file. gomodscan writes that file, and the -summary-json
// file, through a temporary file in the same directory that it then renames
// into place, so a reader never sees a partial file. Both files end up mode
// 0644, less any bits the process's file creation mask clears.
//
// The -summary-json flag writes a machine-readable summary of the run on
// every exit status. The JSON object, at schema 1, carries the build version,
// the modules, findings, and unevaluated counts, an errors array, and an error
// field. Each errors entry records one registry lookup that still failed after
// the retries: the module path and version, the lookup ("versions" for
// pkg.go.dev or "vulns" for OSV), the error message, the attempts, and the
// last HTTP status, which reads 0 when the final attempt got no response. The
// top-level error stays null once the scan runs. When the scan never starts,
// because of a bad argument or an unreadable vendor/modules.txt, error holds
// the reason and the counts stay 0.
//
// gomodscan exits 0 when every module came back clean and 1 when at least one
// finding surfaced. It exits 2 when any module couldn't be evaluated after the
// retries, or on any other operational failure (bad arguments, an unreadable
// vendor/modules.txt, a failed output write). An unevaluated module outranks
// findings, so a run with both exits 2.
//
// [findings]: https://pkg.go.dev/github.com/tbhb-dev/gomodscan/internal/findings
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/tbhb-dev/gomodscan/internal/buildmeta"
	"github.com/tbhb-dev/gomodscan/internal/cachehttp"
	"github.com/tbhb-dev/gomodscan/internal/exitcode"
	"github.com/tbhb-dev/gomodscan/internal/findings"
	"github.com/tbhb-dev/gomodscan/internal/osv"
	"github.com/tbhb-dev/gomodscan/internal/pkgsite"
	"github.com/tbhb-dev/gomodscan/internal/retryhttp"
	"github.com/tbhb-dev/gomodscan/internal/vendormod"
)

const (
	toolName = "gomodscan"

	// vendorModulesPath names the repo-root-relative file each SARIF
	// result points at. gomodscan reads it to list the vendored module
	// set, the physical location GitHub Code Scanning anchors every
	// finding on.
	vendorModulesPath = "vendor/modules.txt"

	// goEcosystem names the Go ecosystem in OSV requests.
	goEcosystem = "Go"

	// maliciousIDPrefix marks advisories that flag a release as
	// malware rather than as a known vulnerability. The OSSF
	// malicious-packages dataset reserves this prefix.
	maliciousIDPrefix = "MAL-"

	// formatText and formatSARIF name the -format values.
	formatText  = "text"
	formatSARIF = "sarif"

	// summarySchema versions the -summary-json document shape. Bump it on
	// any change a consumer parsing the summary would notice.
	summarySchema = 1

	// These name the registry call a summary errors entry records: the
	// pkg.go.dev versions lookup and the OSV query.
	lookupVersions = "versions"
	lookupVulns    = "vulns"

	// reportPerm is the mode the -o and -summary-json files open with, before
	// the process's file creation mask applies, so other users can read them
	// as they could a file a shell redirect created.
	reportPerm = 0o644
)

// errUnknownFormat reports that the -format flag carried a value
// outside the {text, sarif} allowlist. The sentinel form supports
// programmatic matching and keeps wrapcheck and err113 quiet.
var errUnknownFormat = errors.New("unknown -format (want text or sarif)")

// versionsClient abstracts the slice of [pkgsite.Client] the deprecated
// scanner needs. The interface keeps run injectable from tests, so the
// table-driven cases that mutation testing relies on don't have to
// stand up a real HTTP transport for every branch.
type versionsClient interface {
	Versions(ctx context.Context, module string) ([]pkgsite.ModuleVersion, error)
}

// vulnsClient abstracts the slice of [osv.Client] the malicious scanner
// needs. Keeping run injectable lets the table-driven cases drive every
// branch through a stub rather than an httptest server.
type vulnsClient interface {
	Query(ctx context.Context, pkg osv.Package, version string) ([]osv.Vulnerability, error)
}

// findingKind enumerates the issue classes gomodscan reports. The
// string value doubles as the SARIF ruleId.
type findingKind string

const (
	kindRetracted  findingKind = "retracted"
	kindDeprecated findingKind = "deprecated"
	kindMalicious  findingKind = "malicious-package"
)

// finding describes a single hit from either scanner. The kind selects
// which fields apply. Retracted findings use reason, while
// deprecated findings add latest. Malicious-package findings fill id
// and summary.
type finding struct {
	kind    findingKind
	module  string
	version string
	line    int
	latest  string
	reason  string
	id      string
	summary string
}

// level maps a finding to its SARIF severity. A malicious-package hit
// names live malware, so it reports at error. A deprecation or
// retraction warns the caller to act, so it reports at warning.
func (f finding) level() findings.Level {
	if f.kind == kindMalicious {
		return findings.LevelError
	}
	return findings.LevelWarning
}

// props returns the property bag for this finding in the shape shared
// by the text and SARIF emitters. Keys match SARIF property names so
// consumers reading either output channel see the same vocabulary.
func (f finding) props() map[string]string {
	if f.kind == kindMalicious {
		p := map[string]string{"id": f.id}
		if f.summary != "" {
			p["summary"] = strings.TrimSpace(f.summary)
		}
		return p
	}
	p := make(map[string]string)
	if f.reason != "" {
		p["reason"] = strings.TrimSpace(f.reason)
	}
	if f.kind == kindDeprecated && f.latest != "" {
		p["latest"] = f.latest
	}
	return p
}

// message returns the prose used as the SARIF result message. The text
// emitter doesn't use it; the unified text format encodes the same
// information through level/rule/properties.
func (f finding) message() string {
	switch f.kind {
	case kindRetracted:
		return fmt.Sprintf("Module retracted at %s. %s", f.version, reasonSentence(f.reason))
	case kindDeprecated:
		return fmt.Sprintf("Module deprecated at latest version %s. %s", f.latest, reasonSentence(f.reason))
	case kindMalicious:
		if f.summary == "" {
			return fmt.Sprintf("OSV malicious-package advisory %s.", f.id)
		}
		return fmt.Sprintf("OSV malicious-package advisory %s: %s.", f.id, strings.TrimSpace(f.summary))
	default:
		return "Unknown finding."
	}
}

// options carries the flags that shape a scan and where its results go.
type options struct {
	modroot     string
	format      string
	output      string
	summaryJSON string
}

// lookupError records one registry lookup that still failed for a module
// after the retries. Lookup names the registry call. Attempts and LastStatus
// come from the [retryhttp.Error] the client returns, and stay 0 for a
// failure that never reached the transport. A LastStatus of 0 also means the
// last attempt got no HTTP response.
type lookupError struct {
	Module     string `json:"module"`
	Lookup     string `json:"lookup"`
	Error      string `json:"error"`
	Attempts   int    `json:"attempts"`
	LastStatus int    `json:"last_status"`
}

// summary is the -summary-json document. Modules counts the vendored
// modules, Unevaluated the ones with at least one failed lookup, and Errors
// holds every failed lookup (up to two per module, one per registry). Error
// holds the reason a run stopped before its scan, and stays nil otherwise.
type summary struct {
	Schema      int           `json:"schema"`
	Version     string        `json:"version"`
	Modules     int           `json:"modules"`
	Findings    int           `json:"findings"`
	Unevaluated int           `json:"unevaluated"`
	Errors      []lookupError `json:"errors"`
	Error       *string       `json:"error"`
}

// newSummary starts the summary of a run over the given number of modules.
func newSummary(modules int) *summary {
	return &summary{
		Schema:  summarySchema,
		Version: buildmeta.Get().Version,
		Modules: modules,
		Errors:  []lookupError{},
	}
}

// addError logs one failed lookup for mod to errOut and records it.
func (s *summary) addError(errOut io.Writer, mod vendormod.Module, lookup string, err error) {
	fmt.Fprintf(errOut, "%s: %s: %v\n", toolName, mod.Path, err)
	le := lookupError{Module: mod.Path + "@" + mod.Version, Lookup: lookup, Error: err.Error()}
	if re, ok := errors.AsType[*retryhttp.Error](err); ok {
		le.Attempts = re.Attempts
		le.LastStatus = re.LastStatus
	}
	s.Errors = append(s.Errors, le)
}

func reasonSentence(r string) string {
	if r == "" {
		return "No reason recorded."
	}
	return "Reason: " + strings.TrimSpace(r) + "."
}

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
}

// realMain wraps the imperative flag-parsing and exit-code wiring in a
// function that the test harness can drive. The split keeps main itself
// trivial enough to verify by inspection and lets mutation testing
// exercise the error-log branch via real arguments and writers rather
// than the exit call.
func realMain(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)
	fs.SetOutput(errOut)
	var opts options
	fs.StringVar(&opts.modroot, "modroot", "", "module root to scan (defaults to cwd)")
	fs.StringVar(&opts.format, "format", formatText, "output format: text or sarif")
	fs.StringVar(&opts.output, "o", "", "write the findings to `file` instead of stdout")
	fs.StringVar(&opts.output, "output", "", "long form of -o: write the findings to `file`")
	fs.StringVar(
		&opts.summaryJSON,
		"summary-json",
		"",
		"write a JSON summary of the run to `file` on every exit status (schema 1)",
	)
	noCache := fs.Bool("no-cache", false, "disable the on-disk pkg.go.dev response cache")
	cacheDir := fs.String(
		"cache-dir",
		"",
		"directory for the pkg.go.dev response cache (defaults to the per-user cache dir)",
	)
	showVersion := fs.Bool("version", false, "print version information and exit")
	if err := fs.Parse(args); err != nil {
		// The flag set has already printed err. The summary path only counts
		// when its flag came before the bad argument.
		return abort(opts.summaryJSON, err, errOut)
	}

	if *showVersion {
		info := buildmeta.Get()
		fmt.Fprintf(out, "%s %s\ncommit: %s\ndate:   %s\n", toolName, info.Version, info.Commit, info.Date)
		return exitcode.OK
	}

	rc, err := run(
		context.Background(),
		opts,
		newVersionsClient(*noCache, *cacheDir),
		&osv.Client{},
		out,
		errOut,
	)
	if err != nil {
		fmt.Fprintf(errOut, "%s: %v\n", toolName, err)
	}
	return rc
}

// newVersionsClient builds the pkg.go.dev client the deprecated scanner uses.
// By default it layers the on-disk response cache outside the shared retry
// transport, so a fresh hit short-circuits before any backoff or socket and a
// repeated run inside pkg.go.dev's one-hour freshness window skips the network
// entirely. The -no-cache flag, or a cache directory the tool can't locate,
// falls back to the plain client, which still retries and backs off.
func newVersionsClient(noCache bool, cacheDir string) *pkgsite.Client {
	if noCache {
		return &pkgsite.Client{}
	}
	dir := cacheDir
	if dir == "" {
		def, err := cachehttp.DefaultDir()
		if err != nil {
			return &pkgsite.Client{}
		}
		dir = def
	}
	transport := cachehttp.NewTransport(
		retryhttp.NewTransport(
			http.DefaultTransport, retryhttp.InitialDelay, retryhttp.MaxDelay, retryhttp.AttemptTimeout,
		),
		cachehttp.NewDiskStore(dir),
	)
	return &pkgsite.Client{HTTPClient: &http.Client{Transport: transport}}
}

// run reads the vendored module set once, runs both scanners over it, and
// reports the result. A per-module lookup error logs to errOut and drops
// that scanner's result for that module, then marks the module unevaluated,
// which turns the run into a tool failure once the findings and the stderr
// summary are out. An unknown -format, a failure to read the module set, emit
// the findings, or write the -summary-json file also returns a tool-failure
// code.
func run(
	ctx context.Context,
	opts options,
	versions versionsClient,
	vulns vulnsClient,
	out, errOut io.Writer,
) (int, error) {
	if err := checkFormat(opts.format); err != nil {
		return abort(opts.summaryJSON, err, errOut), err
	}
	mods, err := vendormod.Read(opts.modroot)
	if err != nil {
		err = fmt.Errorf("read vendored modules: %w", err)
		return abort(opts.summaryJSON, err, errOut), err
	}

	hits, sum := scan(ctx, mods, versions, vulns, errOut)
	rc, err := report(opts, hits, sum, out, errOut)
	if opts.summaryJSON != "" {
		if sumErr := writeSummary(opts.summaryJSON, sum); sumErr != nil {
			fmt.Fprintf(errOut, "%s: write summary: %v\n", toolName, sumErr)
			return exitcode.ToolFailure, err
		}
	}
	return rc, err
}

// checkFormat rejects a -format value outside the {text, sarif} allowlist
// before the scan starts, so a bad flag costs no registry lookups.
func checkFormat(format string) error {
	if format != formatText && format != formatSARIF {
		return fmt.Errorf("%w: %q", errUnknownFormat, format)
	}
	return nil
}

// abort ends a run that stopped before its scan began. When a -summary-json
// path is set, it writes a summary that carries cause as its error. It
// returns the tool-failure code.
func abort(summaryPath string, cause error, errOut io.Writer) int {
	if summaryPath != "" {
		sum := newSummary(0)
		msg := cause.Error()
		sum.Error = &msg
		if err := writeSummary(summaryPath, sum); err != nil {
			fmt.Fprintf(errOut, "%s: write summary: %v\n", toolName, err)
		}
	}
	return exitcode.ToolFailure
}

// scan accumulates findings in module order (the deprecated check before
// the malicious check for each module) and tallies the failed lookups.
func scan(
	ctx context.Context,
	mods []vendormod.Module,
	versions versionsClient,
	vulns vulnsClient,
	errOut io.Writer,
) ([]finding, *summary) {
	sum := newSummary(len(mods))
	var hits []finding
	for _, mod := range mods {
		dep, depErr := evaluateDeprecated(ctx, versions, mod)
		if depErr != nil {
			sum.addError(errOut, mod, lookupVersions, depErr)
		} else {
			hits = append(hits, dep...)
		}

		mal, malErr := evaluateMalicious(ctx, vulns, mod)
		if malErr != nil {
			sum.addError(errOut, mod, lookupVulns, malErr)
		} else {
			hits = append(hits, mal...)
		}

		if depErr != nil || malErr != nil {
			sum.Unevaluated++
		}
	}
	sum.Findings = len(hits)
	return hits, sum
}

// report emits the findings and the stderr summary, then picks the exit code.
// The findings line still prints when some modules went unevaluated,
// but the unevaluated line comes last and the run exits 2, because the
// findings list may be missing hits from those modules. The no-findings line
// only prints when every module got evaluated.
func report(opts options, hits []finding, sum *summary, out, errOut io.Writer) (int, error) {
	if emitErr := writeFindings(out, opts.output, opts.format, hits); emitErr != nil {
		return exitcode.ToolFailure, fmt.Errorf("emit findings: %w", emitErr)
	}

	if len(hits) > 0 {
		fmt.Fprintf(errOut, "%s: %d finding(s) across %d module(s)\n", toolName, len(hits), sum.Modules)
	}
	if sum.Unevaluated > 0 {
		fmt.Fprintf(errOut, "%s: %d module(s) could not be evaluated\n", toolName, sum.Unevaluated)
		return exitcode.ToolFailure, nil
	}
	if len(hits) > 0 {
		return exitcode.Findings, nil
	}
	fmt.Fprintf(errOut, "%s: scanned %d module(s), no findings\n", toolName, sum.Modules)
	return exitcode.OK, nil
}

// writeFindings emits the findings to out, or to the output file when one
// is set. A file output renders the whole report in memory first, so an
// emit failure leaves the file untouched.
func writeFindings(out io.Writer, output, format string, hits []finding) error {
	if output == "" {
		return emitFindings(out, format, hits)
	}
	var buf bytes.Buffer
	if err := emitFindings(&buf, format, hits); err != nil {
		return err
	}
	return writeFileAtomic(output, buf.Bytes())
}

// writeSummary renders sum as one line of JSON and writes it to path.
func writeSummary(path string, sum *summary) error {
	data, err := json.Marshal(sum)
	if err != nil {
		return fmt.Errorf("marshal summary: %w", err)
	}
	return writeFileAtomic(path, append(data, '\n'))
}

// writeFileAtomic replaces path with data. It writes and syncs a temporary
// file in path's directory before renaming it over path, so a reader sees
// either the old file or the whole new one. Any failure removes the
// temporary file rather than leaving a partial one behind. The temporary
// file opens with [reportPerm], which the file creation mask then narrows as
// it would for [os.Create], where [os.CreateTemp] would leave it 0600.
func writeFileAtomic(path string, data []byte) error {
	name := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp"+rand.Text())
	tmp, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, reportPerm)
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", path, err)
	}
	if commitErr := commitTemp(tmp, path, data); commitErr != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return commitErr
	}
	return nil
}

// commitTemp writes data to the temporary file and flushes it to disk. It
// then closes the file and renames it over path.
func commitTemp(tmp *os.File, path string, data []byte) error {
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

func emitFindings(out io.Writer, format string, hits []finding) error {
	switch format {
	case formatText:
		return emitText(out, hits)
	case formatSARIF:
		return emitSARIF(out, hits)
	default:
		return fmt.Errorf("%w: %q", errUnknownFormat, format)
	}
}

func emitText(out io.Writer, hits []finding) error {
	for _, f := range hits {
		if err := findings.WriteText(
			out,
			f.level(),
			toolName,
			string(f.kind),
			f.module,
			f.version,
			f.props(),
		); err != nil {
			return fmt.Errorf("emit text finding for %s: %w", f.module, err)
		}
	}
	return nil
}

func emitSARIF(out io.Writer, hits []finding) error {
	run := findings.NewRun(toolName)
	run.AddRule(string(kindRetracted)).
		WithDescription("Module is retracted at the pinned version").
		WithHelpURI("https://go.dev/ref/mod#go-mod-file-retract")
	run.AddRule(string(kindDeprecated)).
		WithDescription("Module is deprecated at its latest version").
		WithHelpURI("https://go.dev/ref/mod#go-mod-file-module-deprecation")
	run.AddRule(string(kindMalicious)).
		WithDescription("Module appears in the OSV malicious-package registry").
		WithHelpURI("https://github.com/ossf/malicious-packages")
	for _, f := range hits {
		findings.AddResult(run, string(f.kind), f.level(), f.message(), f.module, f.version,
			findings.Location{URI: vendorModulesPath, Line: f.line}, f.props())
	}
	if err := findings.WriteSARIF(out, run); err != nil {
		return fmt.Errorf("emit sarif: %w", err)
	}
	return nil
}

// evaluateDeprecated looks up the module on pkg.go.dev and classifies
// its retraction and deprecation status. A not-found result marks the
// module as private, replaced, or not indexed, so the scan skips it.
func evaluateDeprecated(ctx context.Context, client versionsClient, mod vendormod.Module) ([]finding, error) {
	versions, err := client.Versions(ctx, mod.Path)
	if err != nil {
		if errors.Is(err, pkgsite.ErrNotFound) {
			return nil, nil // private, replaced, or not indexed: skip
		}
		return nil, fmt.Errorf("lookup versions: %w", err)
	}
	return collectDeprecated(mod, versions), nil
}

// collectDeprecated walks the version records once and emits one hit
// per concern. Retraction looks at the entry whose version matches the
// vendored pin. Deprecation looks at the entry the API names as latest.
// The Go module system stores deprecation on the most recent version's
// go.mod, so any older deprecation flags stay informational rather than
// authoritative.
func collectDeprecated(mod vendormod.Module, versions []pkgsite.ModuleVersion) []finding {
	if len(versions) == 0 {
		return nil
	}
	latest := versions[0].LatestVersion
	var hits []finding
	for _, v := range versions {
		if v.Version == mod.Version && v.Retracted {
			hits = append(hits, finding{
				kind:    kindRetracted,
				module:  mod.Path,
				version: mod.Version,
				line:    mod.Line,
				reason:  v.RetractionReason,
			})
		}
		if v.Version == latest && v.Deprecated {
			hits = append(hits, finding{
				kind:    kindDeprecated,
				module:  mod.Path,
				version: mod.Version,
				line:    mod.Line,
				latest:  latest,
				reason:  v.DeprecationReason,
			})
		}
	}
	return hits
}

// evaluateMalicious queries OSV for the module at its pinned version and
// classifies the response. OSV returns 200 with an empty list for
// unknown packages, so an empty result signals the common clean state,
// not an error.
func evaluateMalicious(ctx context.Context, client vulnsClient, mod vendormod.Module) ([]finding, error) {
	vulns, err := client.Query(ctx, osv.Package{Name: mod.Path, Ecosystem: goEcosystem}, mod.Version)
	if err != nil {
		return nil, fmt.Errorf("lookup vulns: %w", err)
	}
	return collectMalicious(mod, vulns), nil
}

// collectMalicious walks the OSV response and emits one finding per
// advisory whose ID uses the MAL- prefix. Other advisory prefixes
// (GO-, GHSA-, CVE-) describe regular vulnerabilities rather than
// malware reports and belong to the govulncheck recipe.
func collectMalicious(mod vendormod.Module, vulns []osv.Vulnerability) []finding {
	var hits []finding
	for _, v := range vulns {
		if !strings.HasPrefix(v.ID, maliciousIDPrefix) {
			continue
		}
		hits = append(hits, finding{
			kind:    kindMalicious,
			module:  mod.Path,
			version: mod.Version,
			line:    mod.Line,
			id:      v.ID,
			summary: v.Summary,
		})
	}
	return hits
}
