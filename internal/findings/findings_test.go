// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

package findings_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbhb-dev/gomodscan/internal/findings"
)

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
			tool:  "depscan", rule: "retracted",
			module: "example.com/a", version: "v1.0.0",
			want: "warning: depscan/retracted: example.com/a@v1.0.0\n",
		},
		{
			name:  "bare value passes through unquoted",
			level: findings.LevelWarning,
			tool:  "depscan", rule: "deprecated",
			module: "example.com/a", version: "v1.0.0",
			props: map[string]string{"latest": "v0.2.0"},
			want:  "warning: depscan/deprecated: example.com/a@v1.0.0 latest=v0.2.0\n",
		},
		{
			name:  "value with whitespace is quoted",
			level: findings.LevelWarning,
			tool:  "depscan", rule: "deprecated",
			module: "example.com/a", version: "v1.0.0",
			props: map[string]string{"reason": "use v0.2.0"},
			want:  "warning: depscan/deprecated: example.com/a@v1.0.0 reason=\"use v0.2.0\"\n",
		},
		{
			name:  "embedded quotes are backslash-escaped",
			level: findings.LevelError,
			tool:  "malscan", rule: "malicious-package",
			module: "example.com/a", version: "v1.0.0",
			props: map[string]string{"summary": `says "boom"`},
			want:  "error: malscan/malicious-package: example.com/a@v1.0.0 summary=\"says \\\"boom\\\"\"\n",
		},
		{
			name:  "empty value emits quoted empty literal",
			level: findings.LevelNote,
			tool:  "depscan", rule: "retracted",
			module: "example.com/a", version: "v1.0.0",
			props: map[string]string{"reason": ""},
			want:  "note: depscan/retracted: example.com/a@v1.0.0 reason=\"\"\n",
		},
		{
			name:  "keys sort alphabetically for deterministic output",
			level: findings.LevelWarning,
			tool:  "depscan", rule: "deprecated",
			module: "example.com/a", version: "v1.0.0",
			props: map[string]string{"reason": "use v0.2.0", "latest": "v0.2.0"},
			want:  "warning: depscan/deprecated: example.com/a@v1.0.0 latest=v0.2.0 reason=\"use v0.2.0\"\n",
		},
		{
			name:  "value with equals sign forces quoting",
			level: findings.LevelError,
			tool:  "malscan", rule: "malicious-package",
			module: "example.com/a", version: "v1.0.0",
			props: map[string]string{"summary": "k=v in body"},
			want:  "error: malscan/malicious-package: example.com/a@v1.0.0 summary=\"k=v in body\"\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			err := findings.WriteText(&buf, tc.level, tc.tool, tc.rule, tc.module, tc.version, tc.props)
			require.NoError(t, err)
			assert.Equal(t, tc.want, buf.String())
		})
	}
}

func TestWriteSARIF_EmitsValidV210Report(t *testing.T) {
	t.Parallel()

	run := findings.NewRun("depscan")
	run.AddRule("retracted").
		WithDescription("Module is retracted at the pinned version")
	findings.AddResult(run, "retracted", findings.LevelWarning,
		"Module retracted at v1.0.0.",
		"example.com/a", "v1.0.0",
		findings.Location{URI: "vendor/modules.txt", Line: 7},
		map[string]string{"reason": "checksum"},
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
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
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
				Properties          map[string]any    `json:"properties"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))

	assert.Equal(t, "2.1.0", decoded.Version)
	assert.Contains(t, decoded.Schema, "sarif-schema-2.1.0")
	require.Len(t, decoded.Runs, 1)

	run0 := decoded.Runs[0]
	assert.Equal(t, "depscan", run0.Tool.Driver.Name)
	assert.Equal(t, "https://github.com/tbhb-dev/gomodscan", run0.Tool.Driver.InformationURI)
	require.Len(t, run0.Tool.Driver.Rules, 1)
	assert.Equal(t, "retracted", run0.Tool.Driver.Rules[0].ID)

	require.Len(t, run0.Results, 1)
	r := run0.Results[0]
	assert.Equal(t, "retracted", r.RuleID)
	assert.Equal(t, "warning", r.Level)
	assert.Equal(t, "Module retracted at v1.0.0.", r.Message.Text)
	require.Len(t, r.Locations, 1)
	phys := r.Locations[0].PhysicalLocation
	assert.Equal(t, "vendor/modules.txt", phys.ArtifactLocation.URI)
	assert.Equal(t, 7, phys.Region.StartLine)
	require.Len(t, r.Locations[0].LogicalLocations, 1)
	loc := r.Locations[0].LogicalLocations[0]
	assert.Equal(t, "example.com/a@v1.0.0", loc.Name)
	assert.Equal(t, "example.com/a@v1.0.0", loc.FullyQualifiedName)
	assert.Equal(t, "module", loc.Kind)
	assert.Equal(t, "checksum", r.Properties["reason"])
	assert.Equal(t, "example.com/a@v1.0.0", r.PartialFingerprints["modulePathVersion/v1"])
}

func TestWriteSARIF_EmptyRunStillValid(t *testing.T) {
	t.Parallel()
	run := findings.NewRun("malscan")
	run.AddRule("malicious-package")

	var buf bytes.Buffer
	require.NoError(t, findings.WriteSARIF(&buf, run))
	assert.Contains(t, buf.String(), `"version": "2.1.0"`)
}
