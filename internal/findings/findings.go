// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

// Package findings emits scanner findings in two formats: a
// human-readable, agent-parseable text shape and SARIF 2.1.0 for
// downstream ingestion by GitHub Code Scanning and other consumers.
// The text format mirrors SARIF semantics so a reader who knows one
// understands the other.
//
// Each text line follows the format:
//
//	<level>: <tool>/<rule>: <module>@<version> [<key>=<value> pairs]
//
// The level uses one of the SARIF severity words error, warning, or
// note. The tool/rule pair maps onto the SARIF ruleId on the
// corresponding result. Each trailing key=value pair maps onto an
// entry in the SARIF property bag, under alphabetically ordered keys
// for deterministic output and with double quotes around any value
// containing whitespace, an equals sign, or a literal quote.
//
// SARIF emission uses [github.com/owenrumney/go-sarif/v3] against
// the v2.1.0 schema. Each result from [AddResult] carries a logical
// location whose Kind field holds the literal string module (the
// module path) alongside a physical location pointing at the vendor
// manifest line, because GitHub Code Scanning rejects an upload
// whose results lack a physical location.
package findings

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/owenrumney/go-sarif/v3/pkg/report"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

// infoURI points consumers at the canonical gomodscan repository
// when they follow up on a finding. Every SARIF run records it as
// the tool driver's information URI.
const infoURI = "https://github.com/tbhb-dev/gomodscan"

// Level names the SARIF result severity vocabulary. The text
// emitter prints the bare string at the start of each line; the
// SARIF emitter passes it through to [sarif.Result.WithLevel].
type Level string

// The Level values are the three severities a finding takes.
const (
	LevelNote    Level = "note"
	LevelWarning Level = "warning"
	LevelError   Level = "error"
)

// NewRun returns a [sarif.Run] preloaded with the gomodscan
// information URI on the tool driver. The caller registers rules
// via [sarif.Run.AddRule] and adds results via [AddResult].
func NewRun(toolName string) *sarif.Run {
	return sarif.NewRunWithInformationURI(toolName, infoURI)
}

// Location anchors a finding on a real file in the scanned repo.
// GitHub Code Scanning rejects any result without a physical
// location, so [AddResult] turns this into one. URI holds a
// repo-root-relative path such as vendor/modules.txt, and Line gives
// the 1-based line of the finding.
type Location struct {
	URI  string
	Line int
}

// AddResult records one finding on run. The logical location uses
// the "module" kind with module@version as both the name and the
// fully qualified name. The supplied Location becomes the physical
// location Code Scanning requires, mapping URI onto
// artifactLocation.uri and Line onto region.startLine so the finding
// anchors on a real file. The partial fingerprint
// modulePathVersion/v1 contains the same identifier so downstream
// consumers can dedupe across runs. Properties pass through to the
// SARIF property bag verbatim.
func AddResult(
	run *sarif.Run,
	ruleID string,
	level Level,
	message, module, version string,
	loc Location,
	props map[string]string,
) {
	fingerprint := fmt.Sprintf("%s@%s", module, version)

	bag := sarif.NewPropertyBag()
	for _, k := range sortedKeys(props) {
		bag.Add(k, props[k])
	}

	run.CreateResultForRule(ruleID).
		WithLevel(string(level)).
		WithMessage(sarif.NewTextMessage(message)).
		AddLocation(
			sarif.NewLocation().
				AddLogicalLocation(
					sarif.NewLogicalLocation().
						WithName(fingerprint).
						WithFullyQualifiedName(fingerprint).
						WithKind("module"),
				).
				WithPhysicalLocation(
					sarif.NewPhysicalLocation().
						WithArtifactLocation(sarif.NewSimpleArtifactLocation(loc.URI)).
						WithRegion(sarif.NewRegion().WithStartLine(loc.Line)),
				),
		).
		WithProperties(bag).
		// WithPartialFingerprints initializes the underlying map;
		// AddPartialFingerprint panics on the zero value because
		// the constructor leaves PartialFingerprints nil.
		WithPartialFingerprints(map[string]string{"modulePathVersion/v1": fingerprint})
}

// WriteSARIF wraps run in a v2.1.0 [report.Report], validates it
// against the bundled schema, and pretty-prints the JSON to out.
// Validation runs before the write so a malformed report fails
// here with an error instead of at Code Scanning ingestion.
func WriteSARIF(out io.Writer, run *sarif.Run) error {
	rep := report.NewV210Report()
	rep.AddRun(run)

	err := rep.Validate()
	if err != nil {
		return fmt.Errorf("validate sarif: %w", err)
	}

	err = rep.PrettyWrite(out)
	if err != nil {
		return fmt.Errorf("write sarif: %w", err)
	}

	return nil
}

// WriteText emits one finding line in the unified format described
// at the package level. The caller passes pre-classified data; this
// function only handles formatting and quoting.
func WriteText(out io.Writer, level Level, tool, rule, module, version string, props map[string]string) error {
	var line strings.Builder
	fmt.Fprintf(&line, "%s: %s/%s: %s@%s", level, tool, rule, module, version)

	for _, k := range sortedKeys(props) {
		line.WriteByte(' ')
		line.WriteString(k)
		line.WriteByte('=')
		line.WriteString(quoteValue(props[k]))
	}

	line.WriteByte('\n')

	_, err := io.WriteString(out, line.String())
	if err != nil {
		return fmt.Errorf("write text finding: %w", err)
	}

	return nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

// quoteValue applies logfmt-style quoting: bare values pass through
// unchanged when they contain no whitespace, quote, or equals sign;
// everything else gets double-quoted with embedded quotes
// backslash-escaped. The empty string round-trips as a quoted
// empty literal.
func quoteValue(value string) string {
	if value == "" {
		return `""`
	}

	if !strings.ContainsAny(value, " \t\"=") {
		return value
	}

	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}
