// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

// Package owners_test checks that .github/CODEOWNERS and the owner path
// pattern in .agents/agent-skills.conf describe one owner-review policy. The
// package contains only tests.
package owners_test

import (
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	var patterns []string
	for line := range strings.SplitSeq(readRepoFile(t, ".github/CODEOWNERS"), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		patterns = append(patterns, fields[0])
	}

	return patterns
}

// existsInRepo reports whether a CODEOWNERS pattern without a glob points at
// a path in the repository. A pattern with no inner slash matches at any depth.
func existsInRepo(t *testing.T, root, pattern string) bool {
	t.Helper()

	name := strings.Trim(pattern, "/")
	if strings.HasPrefix(pattern, "/") || strings.Contains(name, "/") {
		_, err := os.Stat(filepath.Join(root, filepath.FromSlash(name)))

		return err == nil
	}

	found := false

	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() && (d.Name() == ".git" || d.Name() == "vendor") {
			return fs.SkipDir
		}

		if d.Name() == name {
			found = true

			return fs.SkipAll
		}

		return nil
	})
	require.NoError(t, err)

	return found
}

// globMatchesTracked reports whether a CODEOWNERS glob matches at least one
// path that git tracks, so a file outside the index can't pass it.
func globMatchesTracked(t *testing.T, root, pattern string) bool {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), "git", "ls-files")
	cmd.Dir = root
	out, err := cmd.Output()
	require.NoError(t, err)

	glob := strings.TrimPrefix(pattern, "/")
	for tracked := range strings.SplitSeq(string(out), "\n") {
		if ok, matchErr := path.Match(glob, tracked); matchErr == nil && ok {
			return true
		}
	}

	return false
}

func TestCodeownersPathsExist(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	patterns := codeownersPatterns(t)
	require.NotEmpty(t, patterns)

	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			t.Parallel()

			if strings.Contains(pattern, "*") {
				assert.True(t, globMatchesTracked(t, root, pattern),
					"CODEOWNERS glob %s matches no tracked path", pattern)

				return
			}
			assert.True(t, existsInRepo(t, root, pattern), "CODEOWNERS pattern %s matches nothing", pattern)
		})
	}
}

func TestCodeownersHasNoCatchAll(t *testing.T) {
	t.Parallel()

	patterns := codeownersPatterns(t)
	require.NotEmpty(t, patterns)
	assert.NotContains(t, patterns, "*", "a catch-all rule sends every change to the owner")
	assert.NotContains(t, patterns, "/*", "a catch-all rule sends every change to the owner")
}

// ownerPathsPattern compiles the owner path pattern from agent-skills.conf.
func ownerPathsPattern(t *testing.T) *regexp.Regexp {
	t.Helper()

	var pattern string

	for line := range strings.SplitSeq(readRepoFile(t, ".agents/agent-skills.conf"), "\n") {
		if value, ok := strings.CutPrefix(line, "owner_paths = "); ok {
			pattern = value
		}
	}

	require.NotEmpty(t, pattern, "the owner path pattern is missing from .agents/agent-skills.conf")
	ownerPaths, err := regexp.Compile(pattern)
	require.NoError(t, err)

	return ownerPaths
}

// representativePaths returns paths that a CODEOWNERS pattern covers. A
// directory pattern yields a file under it, and a glob yields one path with
// the glob empty and one with it filled. A pattern with no slash matches at
// any depth, so it also yields a nested copy.
func representativePaths(pattern string) []string {
	name := strings.TrimPrefix(pattern, "/")
	if strings.HasSuffix(name, "/") {
		name += "x"
	}

	paths := []string{name}
	if strings.Contains(name, "*") {
		paths = []string{strings.ReplaceAll(name, "*", ""), strings.ReplaceAll(name, "*", ".local")}
	}

	if !strings.Contains(pattern, "/") {
		paths = append(paths, "sub/dir/"+paths[0])
	}

	return paths
}

func TestCodeownersIsSubsetOfOwnerPaths(t *testing.T) {
	t.Parallel()

	ownerPaths := ownerPathsPattern(t)
	patterns := codeownersPatterns(t)
	require.NotEmpty(t, patterns)

	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			t.Parallel()

			for _, path := range representativePaths(pattern) {
				assert.True(t, ownerPaths.MatchString(path),
					"CODEOWNERS pattern %s covers %s, which the owner path pattern does not match", pattern, path)
			}
		})
	}
}

func TestOwnerPathsMatchesPolicy(t *testing.T) {
	t.Parallel()

	ownerPaths := ownerPathsPattern(t)

	cases := []struct {
		path string
		want bool
	}{
		{".github/CODEOWNERS", true},
		{".github/rulesets/main.json", true},
		{".github/workflows/ci.yml", true},
		{".github/actions/x/action.yml", true},
		{".agents/agent-skills.conf", true},
		{".claude/settings.json", true},
		{".claude/settings.local.json", true},

		{"go.mod", false},
		{"go.sum", false},
		{"vendor/modules.txt", false},

		{"mise.toml", false},
		{"AGENTS.md", false},
		{".devtools/x", false},
		{".agents/skills/x/SKILL.md", false},
		{".claude/skills/x/SKILL.md", false},
		{".github/renovate.json5", false},
		{"cmd/gomodscan/main.go", false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, ownerPaths.MatchString(tc.path), "owner path pattern on %s", tc.path)
	}
}
