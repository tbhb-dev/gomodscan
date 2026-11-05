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
// default) follows the unified format documented in the [findings]
// package. SARIF output emits a v2.1.0 report suitable for ingestion by
// GitHub Code Scanning. The findings go to stdout unless -o (long form
// -output) names a file. gomodscan writes that file, and the -summary-json
// file, through a temporary file in the same directory that it then renames
// into place. A reader never sees a partial file. Both files end up mode
// 0644, less any bits the process's file creation mask clears.
//
// The -summary-json flag writes a machine-readable summary of the run on every
// exit status. The JSON object, at schema 1, carries the build version, the
// modules, findings, and unevaluated counts, an errors array, and an error
// field. Each errors entry records one registry lookup that still failed after
// the retries: the module path and version, the lookup ("versions" for
// pkg.go.dev or "vulns" for OSV), the error message, the attempts, and the
// last HTTP status, which reads 0 when the final attempt ended without a
// response. The attempts count only requests this run sent, so a lookup that
// failed on a pkg.go.dev response from the on-disk cache records 0 attempts
// and a last status of 0, and its message mentions the cache. The top-level
// error is null once the scan runs. With -version, which scans nothing, the
// counts stay 0 and the error is null. When the scan never starts, because of
// a bad argument or an unreadable vendor/modules.txt, error holds the reason
// and the counts stay 0.
//
// A failed -o or -summary-json write prints its error ahead of the stderr
// summary and exits 2. The summary is still the last line of the run.
//
// gomodscan exits 0 when every module came back clean and 1 when it reports at
// least one finding. It exits 2 when any module couldn't be evaluated after the
// retries, or on any other operational failure (bad arguments, an unreadable
// vendor/modules.txt, a failed output write). A run with both an unevaluated
// module and a finding exits 2.
//
// [findings]: https://pkg.go.dev/go.tbhb.dev/gomodscan/internal/findings
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

	"go.tbhb.dev/gomodscan/internal/buildmeta"
	"go.tbhb.dev/gomodscan/internal/cachehttp"
	"go.tbhb.dev/gomodscan/internal/exitcode"
	"go.tbhb.dev/gomodscan/internal/findings"
	"go.tbhb.dev/gomodscan/internal/osv"
	"go.tbhb.dev/gomodscan/internal/pkgsite"
	"go.tbhb.dev/gomodscan/internal/retryhttp"
	"go.tbhb.dev/gomodscan/internal/vendormod"
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
// build a real HTTP transport for every branch.
type versionsClient interface {
	Versions(ctx context.Context, module string) ([]pkgsite.ModuleVersion, error)
}

// vulnsClient abstracts the slice of [osv.Client] the malicious scanner
// needs. Keeping run injectable lets the table-driven cases exercise every
// branch through a stub rather than an httptest server.
type vulnsClient interface {
	Query(ctx context.Context, pkg osv.Package, version string) ([]osv.Vulnerability, error)
}

// findingKind enumerates the issue classes gomodscan reports. The
// string value is also the SARIF ruleId.
type findingKind string

const (
	kindRetracted  findingKind = "retracted"
	kindDeprecated findingKind = "deprecated"
	kindMalicious  findingKind = "malicious-package"
)

// finding describes one hit from either scanner. The kind selects
// which fields apply. Retracted findings use reason, while
// deprecated findings add latest. Malicious-package findings fill id
// and summary.
type finding struct {
	kind    findingKind
	module  string
	version string
	latest  string
	reason  string
	id      string
	summary string
	line    int
}

// newFinding starts a finding of the given kind at the module's pinned
// version and manifest line. The caller fills the fields the kind uses.
func newFinding(kind findingKind, mod vendormod.Module) finding {
	return finding{
		kind:    kind,
		module:  mod.Path,
		version: mod.Version,
		line:    mod.Line,
		latest:  "",
		reason:  "",
		id:      "",
		summary: "",
	}
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

// props returns the property bag for this finding in the layout shared
// by the text and SARIF emitters. Keys match SARIF property names so
// consumers reading either output channel see the same vocabulary.
func (f finding) props() map[string]string {
	if f.kind == kindMalicious {
		props := map[string]string{"id": f.id}
		if f.summary != "" {
			props["summary"] = strings.TrimSpace(f.summary)
		}

		return props
	}

	props := make(map[string]string)
	if f.reason != "" {
		props["reason"] = strings.TrimSpace(f.reason)
	}

	if f.kind == kindDeprecated && f.latest != "" {
		props["latest"] = f.latest
	}

	return props
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

// options records the flags that configure a scan and choose where its
// results go.
type options struct {
	modroot     string
	format      string
	output      string
	summaryJSON string
}

// lookupError records one registry lookup that still failed for a module
// after the retries. Lookup names the registry call. Attempts and LastStatus
// come from the [retryhttp.Error] the client returns, and stay 0 for a
// failure before the transport sent a request. A LastStatus of 0 also means
// the last attempt ended without an HTTP response, or that the response came
// from the on-disk cache rather than an attempt.
type lookupError struct {
	Module     string `json:"module"`
	Lookup     string `json:"lookup"`
	Error      string `json:"error"`
	Attempts   int    `json:"attempts"`
	LastStatus int    `json:"last_status"` //nolint:tagliatelle // summary schema 1 names this field last_status
}

// summary is the -summary-json document. Modules counts the vendored
// modules, Unevaluated the ones with at least one failed lookup, and Errors
// lists every failed lookup (up to two per module, one per registry). Error
// holds the reason a run stopped before its scan, and is nil otherwise.
type summary struct {
	Error       *string       `json:"error"`
	Version     string        `json:"version"`
	Errors      []lookupError `json:"errors"`
	Schema      int           `json:"schema"`
	Modules     int           `json:"modules"`
	Findings    int           `json:"findings"`
	Unevaluated int           `json:"unevaluated"`
}

// newSummary starts the summary of a run over the given number of modules.
func newSummary(modules int) *summary {
	return &summary{
		Error:       nil,
		Version:     buildmeta.Get().Version,
		Errors:      []lookupError{},
		Schema:      summarySchema,
		Modules:     modules,
		Findings:    0,
		Unevaluated: 0,
	}
}

// addError logs one failed lookup for mod to errOut and records it.
func (s *summary) addError(errOut io.Writer, mod vendormod.Module, lookup string, err error) {
	fmt.Fprintf(errOut, "%s: %s: %v\n", toolName, mod.Path, err)

	entry := lookupError{
		Module:     mod.Path + "@" + mod.Version,
		Lookup:     lookup,
		Error:      err.Error(),
		Attempts:   0,
		LastStatus: 0,
	}
	if retryErr, ok := errors.AsType[*retryhttp.Error](err); ok {
		entry.Attempts = retryErr.Attempts
		entry.LastStatus = retryErr.LastStatus
	}

	s.Errors = append(s.Errors, entry)
}

func reasonSentence(r string) string {
	if r == "" {
		return "No reason recorded."
	}

	return "Reason: " + strings.TrimSpace(r) + "."
}

// exit ends the process. Tests replace it to observe the status main passes.
//
//nolint:gochecknoglobals // a test can't call os.Exit and survive
var exit = os.Exit

func main() {
	exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
}

// realMain wraps the imperative flag-parsing and exit-code wiring in a
// function that the test harness can drive. The split keeps main itself
// trivial enough to verify by inspection and lets mutation testing
// exercise the error paths via real arguments and writers rather
// than the exit call.
func realMain(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet(toolName, flag.ContinueOnError)
	flags.SetOutput(errOut)

	var opts options
	flags.StringVar(&opts.modroot, "modroot", "", "module root to scan (defaults to cwd)")
	flags.StringVar(&opts.format, "format", formatText, "output format: text or sarif")
	flags.StringVar(&opts.output, "o", "", "write the findings to `file` instead of stdout")
	flags.StringVar(&opts.output, "output", "", "long form of -o: write the findings to `file`")
	flags.StringVar(
		&opts.summaryJSON,
		"summary-json",
		"",
		"write a JSON summary of the run to `file` on every exit status (schema 1)",
	)
	noCache := flags.Bool("no-cache", false, "disable the on-disk pkg.go.dev response cache")
	cacheDir := flags.String(
		"cache-dir",
		"",
		"directory for the pkg.go.dev response cache (defaults to the per-user cache dir)",
	)

	showVersion := flags.Bool("version", false, "print version information and exit")

	parseErr := flags.Parse(args)
	if parseErr != nil {
		// The flag set has already printed parseErr. The summary path only
		// counts when its flag came before the bad argument.
		return abort(opts.summaryJSON, parseErr, errOut)
	}

	if *showVersion {
		info := buildmeta.Get()
		fmt.Fprintf(out, "%s %s\ncommit: %s\ndate:   %s\n", toolName, info.Version, info.Commit, info.Date)
		// -summary-json promises a summary on every exit status, so -version
		// writes one too. It scanned nothing. Its counts are 0 and its error
		// is null.
		if opts.summaryJSON != "" {
			if !writeSummary(opts.summaryJSON, newSummary(0), errOut) {
				return exitcode.ToolFailure
			}
		}

		return exitcode.OK
	}

	code, err := run(
		context.Background(),
		opts,
		newVersionsClient(*noCache, *cacheDir),
		&osv.Client{BaseURL: "", HTTPClient: nil, UserAgent: ""},
		out,
		errOut,
	)
	if err != nil {
		// run has already logged the cause, ahead of any summary-write error,
		// and returned the tool-failure code.
		return exitcode.ToolFailure
	}

	return code
}

// newVersionsClient builds the pkg.go.dev client the deprecated scanner uses.
// By default it layers the on-disk response cache outside the shared retry
// transport, so a fresh hit short-circuits before any backoff or socket and a
// repeated run inside pkg.go.dev's one-hour freshness window skips the network
// entirely. The -no-cache flag, or a cache directory the tool can't locate,
// falls back to the plain client, which still retries and backs off.
func newVersionsClient(noCache bool, cacheDir string) *pkgsite.Client {
	if noCache {
		return plainVersionsClient()
	}

	dir, ok := resolveCacheDir(cacheDir)
	if !ok {
		return plainVersionsClient()
	}

	transport := cachehttp.NewTransport(
		retryhttp.NewTransport(
			http.DefaultTransport, retryhttp.InitialDelay, retryhttp.MaxDelay, retryhttp.AttemptTimeout,
		),
		cachehttp.NewDiskStore(dir),
	)

	return &pkgsite.Client{
		BaseURL: "",
		HTTPClient: &http.Client{
			Transport:     transport,
			CheckRedirect: nil,
			Jar:           nil,
			Timeout:       0,
		},
		UserAgent: "",
	}
}

// resolveCacheDir returns the directory the caller asked for, or the per-user
// default when the caller named none. It reports false when no default
// directory can be located.
func resolveCacheDir(cacheDir string) (string, bool) {
	if cacheDir != "" {
		return cacheDir, true
	}

	def, err := cachehttp.DefaultDir()
	if err != nil {
		return "", false
	}

	return def, true
}

// plainVersionsClient is the pkg.go.dev client with its defaults, which
// still retries and backs off but doesn't cache.
func plainVersionsClient() *pkgsite.Client {
	return &pkgsite.Client{BaseURL: "", HTTPClient: nil, UserAgent: ""}
}

// run reads the vendored module set once and runs both scanners over it. A
// per-module lookup error logs to errOut and drops that scanner's result for
// that module, then marks the module unevaluated, which turns the run into a
// tool failure once the findings and the stderr summary are out. An unknown -format, an unreadable module set, a failed
// findings emit, or a failed -summary-json write also returns a tool-failure
// code. For a scan that never starts, run logs the cause to errOut and
// returns it as the error. A failed write logs to errOut itself before the
// stderr summary that ends the output. run returns a nil error for it.
func run(
	ctx context.Context,
	opts options,
	versions versionsClient,
	vulns vulnsClient,
	out, errOut io.Writer,
) (int, error) {
	formatErr := checkFormat(opts.format)
	if formatErr != nil {
		return abortRun(opts.summaryJSON, formatErr, errOut), formatErr
	}

	mods, err := vendormod.Read(opts.modroot)
	if err != nil {
		err = fmt.Errorf("read vendored modules: %w", err)

		return abortRun(opts.summaryJSON, err, errOut), err
	}

	hits, sum := scan(ctx, mods, versions, vulns, errOut)
	wrote := true

	emitErr := writeFindings(out, opts.output, opts.format, hits)
	if emitErr != nil {
		fmt.Fprintf(errOut, "%s: emit findings: %v\n", toolName, emitErr)

		wrote = false
	}

	if opts.summaryJSON != "" {
		if !writeSummary(opts.summaryJSON, sum, errOut) {
			wrote = false
		}
	}

	code := report(sum, errOut)

	if !wrote {
		return exitcode.ToolFailure, nil
	}

	return code, nil
}

// checkFormat rejects a -format value outside the {text, sarif} allowlist
// before the scan starts. A bad flag doesn't cost any registry lookups.
func checkFormat(format string) error {
	if format != formatText && format != formatSARIF {
		return fmt.Errorf("%w: %q", errUnknownFormat, format)
	}

	return nil
}

// abortRun logs cause, then aborts, so a failed summary write prints after the
// cause, the order a flag-parse failure also gives.
func abortRun(summaryPath string, cause error, errOut io.Writer) int {
	fmt.Fprintf(errOut, "%s: %v\n", toolName, cause)

	return abort(summaryPath, cause, errOut)
}

// abort ends a run that stopped before its scan began. When a -summary-json
// path is set, it writes a summary with cause as its error, and a
// failed write logs after the cause the caller has already printed. It
// returns the tool-failure code.
func abort(summaryPath string, cause error, errOut io.Writer) int {
	if summaryPath != "" {
		sum := newSummary(0)
		msg := cause.Error()

		sum.Error = &msg

		writeSummary(summaryPath, sum, errOut)
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

// report prints the stderr summary, then picks the exit code.
// The findings line still prints when some modules went unevaluated,
// but the unevaluated line comes last and the run exits 2, because the
// findings list may be missing hits from those modules. The no-findings line
// only prints when every module got evaluated.
func report(sum *summary, errOut io.Writer) int {
	if sum.Findings > 0 {
		fmt.Fprintf(errOut, "%s: %d finding(s) across %d module(s)\n", toolName, sum.Findings, sum.Modules)
	}

	if sum.Unevaluated > 0 {
		fmt.Fprintf(errOut, "%s: %d module(s) could not be evaluated\n", toolName, sum.Unevaluated)

		return exitcode.ToolFailure
	}

	if sum.Findings > 0 {
		return exitcode.Findings
	}

	fmt.Fprintf(errOut, "%s: scanned %d module(s), no findings\n", toolName, sum.Modules)

	return exitcode.OK
}

// writeFindings emits the findings to out, or to the output file when one
// is set. A file output renders the report in memory before it
// replaces the file, and a rendering failure leaves the old file in place.
func writeFindings(out io.Writer, output, format string, hits []finding) error {
	if output == "" {
		return emitFindings(out, format, hits)
	}

	var buf bytes.Buffer

	err := emitFindings(&buf, format, hits)
	if err != nil {
		return err
	}

	return writeFileAtomic(output, buf.Bytes())
}

// writeSummary renders sum as one line of JSON and writes it to path. A
// failed write logs to errOut and reports false.
func writeSummary(path string, sum *summary, errOut io.Writer) bool {
	//nolint:errcheck,errchkjson // a summary holds only strings, integers and a slice of those, which always encode
	data, _ := json.Marshal(sum)

	err := writeFileAtomic(path, append(data, '\n'))
	if err != nil {
		fmt.Fprintf(errOut, "%s: write summary: %v\n", toolName, err)

		return false
	}

	return true
}

// writeFileAtomic replaces path with data. It writes and syncs a temporary
// file in path's directory before renaming it over path. A reader sees
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

	commitErr := commitTemp(tmp, path, data)
	if commitErr != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())

		return commitErr
	}

	return nil
}

// tempFile is the part of [os.File] that commitTemp uses. Tests supply a
// fake that fails each step.
type tempFile interface {
	io.Writer
	io.Closer
	Sync() error
	Name() string
}

// commitTemp writes data to the temporary file and flushes it to disk. It
// then closes the file and renames it over path.
func commitTemp(tmp tempFile, path string, data []byte) error {
	_, err := tmp.Write(data)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	err = tmp.Sync()
	if err != nil {
		return fmt.Errorf("sync %s: %w", path, err)
	}

	err = tmp.Close()
	if err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}

	err = os.Rename(tmp.Name(), path)
	if err != nil {
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
	for _, hit := range hits {
		err := findings.WriteText(
			out,
			hit.level(),
			toolName,
			string(hit.kind),
			hit.module,
			hit.version,
			hit.props(),
		)
		if err != nil {
			return fmt.Errorf("emit text finding for %s: %w", hit.module, err)
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

	for _, hit := range hits {
		findings.AddResult(run, string(hit.kind), hit.level(), hit.message(), hit.module, hit.version,
			findings.Location{URI: vendorModulesPath, Line: hit.line}, hit.props())
	}

	err := findings.WriteSARIF(out, run)
	if err != nil {
		return fmt.Errorf("emit sarif: %w", err)
	}

	return nil
}

// evaluateDeprecated looks up the module on pkg.go.dev and classifies
// its retraction and deprecation status. A not-found result marks the
// module as private, replaced, or not indexed, and the scan skips it.
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
// go.mod. A deprecation flag on an older version is informational rather
// than authoritative.
func collectDeprecated(mod vendormod.Module, versions []pkgsite.ModuleVersion) []finding {
	if len(versions) == 0 {
		return nil
	}

	latest := versions[0].LatestVersion

	var hits []finding

	for _, ver := range versions {
		if ver.Version == mod.Version && ver.Retracted {
			hit := newFinding(kindRetracted, mod)
			hit.reason = ver.RetractionReason
			hits = append(hits, hit)
		}

		if ver.Version == latest && ver.Deprecated {
			hit := newFinding(kindDeprecated, mod)
			hit.latest = latest
			hit.reason = ver.DeprecationReason
			hits = append(hits, hit)
		}
	}

	return hits
}

// evaluateMalicious queries OSV for the module at its pinned version and
// classifies the response. OSV returns 200 with an empty list for
// unknown packages. An empty result is the common clean state.
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

	for _, vuln := range vulns {
		if !strings.HasPrefix(vuln.ID, maliciousIDPrefix) {
			continue
		}

		hit := newFinding(kindMalicious, mod)
		hit.id = vuln.ID
		hit.summary = vuln.Summary
		hits = append(hits, hit)
	}

	return hits
}
