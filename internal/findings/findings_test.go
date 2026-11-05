// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

package findings_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.tbhb.dev/gomodscan/internal/findings"
)

//nolint:dupl // test scenarios repeat the same arrange and assert steps
func TestWriteText(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		level   findings.Level
		tool    string
		rule    string
		module  string
		version string
		props   map[string]string
		want    string
	}{
		{
			name:  "header only when no properties",
			level: findings.LevelWarning,
			tool:  toolName, rule: "retracted",
			module: modA, version: v100,
			props: nil,
			want:  "warning: depscan/retracted: example.com/a@v1.0.0\n",
		},
		{
			name:  "bare value passes through unquoted",
			level: findings.LevelWarning,
			tool:  toolName, rule: ruleDeprecated,
			module: modA, version: v100,
			props: map[string]string{keyLatest: "v0.2.0"},
			want:  "warning: depscan/deprecated: example.com/a@v1.0.0 latest=v0.2.0\n",
		},
		{
			name:  "value with whitespace is quoted",
			level: findings.LevelWarning,
			tool:  toolName, rule: ruleDeprecated,
			module: modA, version: v100,
			props: map[string]string{keyReason: "use v0.2.0"},
			want:  "warning: depscan/deprecated: example.com/a@v1.0.0 reason=\"use v0.2.0\"\n",
		},
		{
			name:  "embedded quotes are backslash-escaped",
			level: findings.LevelError,
			tool:  "malscan", rule: "malicious-package",
			module: modA, version: v100,
			props: map[string]string{"summary": `says "boom"`},
			want:  "error: malscan/malicious-package: example.com/a@v1.0.0 summary=\"says \\\"boom\\\"\"\n",
		},
		{
			name:  "empty value emits quoted empty literal",
			level: findings.LevelNote,
			tool:  toolName, rule: "retracted",
			module: modA, version: v100,
			props: map[string]string{keyReason: ""},
			want:  "note: depscan/retracted: example.com/a@v1.0.0 reason=\"\"\n",
		},
		{
			name:  "keys sort alphabetically for deterministic output",
			level: findings.LevelWarning,
			tool:  toolName, rule: ruleDeprecated,
			module: modA, version: v100,
			props: map[string]string{keyReason: "use v0.2.0", keyLatest: "v0.2.0"},
			want:  "warning: depscan/deprecated: example.com/a@v1.0.0 latest=v0.2.0 reason=\"use v0.2.0\"\n",
		},
		{
			name:  "value with equals sign forces quoting",
			level: findings.LevelError,
			tool:  "malscan", rule: "malicious-package",
			module: modA, version: v100,
			props: map[string]string{"summary": "k=v in body"},
			want:  "error: malscan/malicious-package: example.com/a@v1.0.0 summary=\"k=v in body\"\n",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer

			err := findings.WriteText(
				&buf,
				testCase.level,
				testCase.tool,
				testCase.rule,
				testCase.module,
				testCase.version,
				testCase.props,
			)
			require.NoError(t, err)
			assert.Equal(t, testCase.want, buf.String())
		})
	}
}

//nolint:dupl // test scenarios repeat the same arrange and assert steps
func TestWriteSARIF_EmitsValidV210Report(t *testing.T) {
	t.Parallel()

	run := findings.NewRun(toolName)
	run.AddRule("retracted").
		WithDescription("Module is retracted at the pinned version")
	findings.AddResult(run, "retracted", findings.LevelWarning,
		"Module retracted at v1.0.0.",
		modA, v100,
		findings.Location{URI: manifestURI, Line: 7},
		map[string]string{keyReason: "checksum"},
	)

	var buf bytes.Buffer
	require.NoError(t, findings.WriteSARIF(&buf, run))

	var decoded struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name           string `json:"name"`
					InformationURI string `json:"informationUri"`
					Rules          []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				Properties          map[string]any    `json:"properties"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				RuleID              string            `json:"ruleId"`
				Level               string            `json:"level"`
				Message             struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
					LogicalLocations []struct {
						Name               string `json:"name"`
						FullyQualifiedName string `json:"fullyQualifiedName"`
						Kind               string `json:"kind"`
					} `json:"logicalLocations"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))

	assert.Equal(t, "2.1.0", decoded.Version)
	assert.Contains(t, decoded.Schema, "sarif-schema-2.1.0")
	require.Len(t, decoded.Runs, 1)

	run0 := decoded.Runs[0]
	assert.Equal(t, toolName, run0.Tool.Driver.Name)
	assert.Equal(t, "https://github.com/tbhb-dev/gomodscan", run0.Tool.Driver.InformationURI)
	require.Len(t, run0.Tool.Driver.Rules, 1)
	assert.Equal(t, "retracted", run0.Tool.Driver.Rules[0].ID)

	require.Len(t, run0.Results, 1)
	result := run0.Results[0]
	assert.Equal(t, "retracted", result.RuleID)
	assert.Equal(t, "warning", result.Level)
	assert.Equal(t, "Module retracted at v1.0.0.", result.Message.Text)
	require.Len(t, result.Locations, 1)
	phys := result.Locations[0].PhysicalLocation
	assert.Equal(t, manifestURI, phys.ArtifactLocation.URI)
	assert.Equal(t, 7, phys.Region.StartLine)
	require.Len(t, result.Locations[0].LogicalLocations, 1)
	loc := result.Locations[0].LogicalLocations[0]
	assert.Equal(t, "example.com/a@v1.0.0", loc.Name)
	assert.Equal(t, "example.com/a@v1.0.0", loc.FullyQualifiedName)
	assert.Equal(t, "module", loc.Kind)
	assert.Equal(t, "checksum", result.Properties[keyReason])
	assert.Equal(t, "example.com/a@v1.0.0", result.PartialFingerprints["modulePathVersion/v1"])
}

func TestWriteSARIF_EmptyRunStillValid(t *testing.T) {
	t.Parallel()

	run := findings.NewRun("malscan")
	run.AddRule("malicious-package")

	var buf bytes.Buffer
	require.NoError(t, findings.WriteSARIF(&buf, run))
	assert.Contains(t, buf.String(), `"version": "2.1.0"`)
}

// goldenRun builds the run behind testdata/report.sarif. It has two rules
// with one result each, in the order the scanner reports them.
//
//nolint:dupl // test scenarios repeat the same arrange and assert steps
func goldenRun() *sarif.Run {
	run := findings.NewRun(toolName)
	run.AddRule("retracted").WithDescription("Module is retracted at the pinned version")
	run.AddRule(ruleDeprecated).WithDescription("Module is deprecated")
	findings.AddResult(run, "retracted", findings.LevelWarning,
		"Module retracted at v1.0.0.",
		modA, v100,
		findings.Location{URI: manifestURI, Line: 1},
		map[string]string{keyReason: "checksum"},
	)
	findings.AddResult(run, ruleDeprecated, findings.LevelNote,
		"Module deprecated at v2.0.0.",
		"example.com/b", "v2.0.0",
		findings.Location{URI: manifestURI, Line: 4},
		map[string]string{keyLatest: "v3.0.0", keyReason: "use v3"},
	)

	return run
}

func TestWriteSARIF_MatchesGolden(t *testing.T) {
	t.Parallel()

	want, err := os.ReadFile(filepath.Join("testdata", "report.sarif"))
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, findings.WriteSARIF(&buf, goldenRun()))
	assert.JSONEq(t, string(want), buf.String())
}

const (
	toolName       = "depscan"
	modA           = "example.com/a"
	ruleDeprecated = "deprecated"
	keyLatest      = "latest"
	keyReason      = "reason"
	manifestURI    = "vendor/modules.txt"
)

const (
	v100 = "v1.0.0"
)

var errSink = errors.New("sink closed")

// failingWriter rejects every write with errSink.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errSink }

func TestWriteSARIF_RejectsInvalidReport(t *testing.T) {
	t.Parallel()

	run := findings.NewRun(toolName)
	run.AddRule("retracted")
	findings.AddResult(run, "retracted", findings.Level("bogus"), "message", modA, v100,
		findings.Location{URI: manifestURI, Line: 1}, nil)

	var buf bytes.Buffer

	err := findings.WriteSARIF(&buf, run)
	require.Error(t, err)
	require.ErrorContains(t, err, "validate sarif")
	require.Error(t, errors.Unwrap(err), "the validation failure stays in the error chain")
	assert.Empty(t, buf.String())
}

func TestWriteSARIF_ReportsWriteError(t *testing.T) {
	t.Parallel()

	err := findings.WriteSARIF(failingWriter{}, goldenRun())
	require.ErrorIs(t, err, errSink)
	require.ErrorContains(t, err, "write sarif")
}

func TestWriteText_ReportsWriteError(t *testing.T) {
	t.Parallel()

	err := findings.WriteText(failingWriter{}, findings.LevelNote, toolName, "retracted", modA, v100, nil)
	require.ErrorIs(t, err, errSink)
	require.ErrorContains(t, err, "write text finding")
}
