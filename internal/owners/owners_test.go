// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

// Package owners_test checks that .github/CODEOWNERS and the owner path
// pattern in .agents/agent-skills.conf describe one owner-review policy: the
// file that defines ownership and the file that defines the merge policy
// need the owner. Other paths don't. The package contains only tests.
package owners_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ownerFiles returns the only two paths that need the owner.
func ownerFiles() []string { return []string{".github/CODEOWNERS", ".agents/agent-skills.conf"} }

// repoRoot walks up from the working directory, which go test sets to this
// package's directory, to the directory that holds go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	require.NoError(t, err)

	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "no go.mod above the test's working directory")
		dir = parent
	}
}

func readRepoFile(t *testing.T, name string) string {
	t.Helper()

	root, err := os.OpenRoot(repoRoot(t))
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	data, err := root.ReadFile(name)
	require.NoError(t, err)

	return string(data)
}

// codeownersPatterns returns the path pattern from each rule line.
func codeownersPatterns(t *testing.T) []string {
	t.Helper()

	return rulePatterns(readRepoFile(t, ".github/CODEOWNERS"))
}

func rulePatterns(content string) []string {
	var patterns []string
	for line := range strings.SplitSeq(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		patterns = append(patterns, fields[0])
	}

	return patterns
}

// trackedFiles returns the paths that git tracks, so a file outside the index
// can't back a CODEOWNERS entry.
func trackedFiles(t *testing.T) map[string]bool {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), "git", "ls-files")
	cmd.Dir = repoRoot(t)
	out, err := cmd.Output()
	require.NoError(t, err)

	tracked := map[string]bool{}
	for name := range strings.SplitSeq(string(out), "\n") {
		tracked[name] = true
	}

	return tracked
}

// checkEntries reports how a CODEOWNERS entry list departs from the policy.
// It flags a catch-all rule and an entry beyond the two owner files. It also
// flags a missing owner file and an entry for a file git doesn't track.
func checkEntries(patterns []string, tracked map[string]bool) []string {
	var problems []string

	want := map[string]bool{}
	for _, name := range ownerFiles() {
		want["/"+name] = false
	}

	for _, pattern := range patterns {
		if pattern == "*" || pattern == "/*" || pattern == "**" {
			problems = append(problems, "catch-all rule "+pattern)
		}

		if _, ok := want[pattern]; ok {
			want[pattern] = true
		} else {
			problems = append(problems, "unexpected entry "+pattern)
		}

		if !tracked[strings.TrimPrefix(pattern, "/")] {
			problems = append(problems, "no tracked file for "+pattern)
		}
	}

	for pattern, seen := range want {
		if !seen {
			problems = append(problems, "missing entry "+pattern)
		}
	}

	return problems
}

func TestCodeownersListsExactlyTheOwnerFiles(t *testing.T) {
	t.Parallel()

	assert.Empty(t, checkEntries(codeownersPatterns(t), trackedFiles(t)))
}

// TestCheckEntriesCatchesDrift feeds the entry check one broken list per case,
// so the check on the real file can't pass by accident. The broken lists
// have a catch-all rule, a tracked file that isn't an owner file, a file git
// doesn't track, or a dropped owner file. The first case is the intact pair,
// which has to come back clean, so a check that flags everything fails too.
func TestCheckEntriesCatchesDrift(t *testing.T) {
	t.Parallel()

	tracked := map[string]bool{
		".github/CODEOWNERS":        true,
		".agents/agent-skills.conf": true,
		"go.mod":                    true,
	}
	base := []string{"/.github/CODEOWNERS", "/.agents/agent-skills.conf"}

	cases := []struct {
		name     string
		patterns []string
		want     string
	}{
		{"exact pair", base, ""},
		{"catch-all", append([]string{"*"}, base...), "catch-all rule *"},
		{"extra tracked entry", append([]string{"/go.mod"}, base...), "unexpected entry /go.mod"},
		{"entry naming no tracked file", append([]string{"/nope.txt"}, base...), "no tracked file for /nope.txt"},
		{"missing owner file", base[:1], "missing entry /.agents/agent-skills.conf"},
	}
	for _, tc := range cases {
		problems := checkEntries(tc.patterns, tracked)
		if tc.want == "" {
			assert.Empty(t, problems, tc.name)

			continue
		}

		assert.Contains(t, problems, tc.want, tc.name)
	}
}

// confValue returns a key's value.
func confValue(t *testing.T, key string) string {
	t.Helper()

	var value string

	for line := range strings.SplitSeq(readRepoFile(t, ".agents/agent-skills.conf"), "\n") {
		if v, ok := strings.CutPrefix(line, key+" = "); ok {
			value = v
		}
	}

	require.NotEmpty(t, value, "%s is missing from .agents/agent-skills.conf", key)

	return value
}

func TestOwnerPathsMatchesPolicy(t *testing.T) {
	t.Parallel()

	ownerPaths, err := regexp.Compile(confValue(t, "owner_paths"))
	require.NoError(t, err)

	cases := []struct {
		path string
		want bool
	}{
		{".github/CODEOWNERS", true},
		{".agents/agent-skills.conf", true},

		{"mise.toml", false},
		{"mise.lock", false},
		{"go.mod", false},
		{"go.sum", false},
		{"vendor/modules.txt", false},
		{"vendor/x", false},
		{".github/workflows/ci.yml", false},
		{".github/actions/x/action.yml", false},
		{".github/rulesets/main.json", false},
		{".claude/settings.json", false},
		{".claude/settings.local.json", false},
		{"AGENTS.md", false},
		{".agents/skills/x/SKILL.md", false},
		{"sub/.github/CODEOWNERS", false},
		{"sub/.agents/agent-skills.conf", false},
		{".github/CODEOWNERS.bak", false},
		{"cmd/gomodscan/main.go", false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, ownerPaths.MatchString(tc.path), "owner path pattern on %s", tc.path)
	}
}
