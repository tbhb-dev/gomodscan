#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# Copyright Tony Burns

# Tests for tools/get_workspace_status.sh, the Bazel workspace status command.

setup() {
	SCRIPT="${BATS_TEST_DIRNAME}/get_workspace_status.sh"
	# Isolate git from the user's and the harness's configuration. Harnesses
	# inject GIT_AUTHOR_*, GIT_COMMITTER_* and GIT_CONFIG_* into agent shells.
	local names v
	names=$(compgen -e)
	for v in $names; do
		[[ $v == GIT_* ]] && unset "$v"
	done
	export HOME="${BATS_TEST_TMPDIR}/home"
	export GIT_CONFIG_NOSYSTEM=1
	export GIT_CONFIG_GLOBAL=/dev/null
	export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@example.invalid
	export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@example.invalid
	export GIT_AUTHOR_DATE=2026-01-02T03:04:05Z GIT_COMMITTER_DATE=2026-01-02T03:04:05Z
	mkdir -p "$HOME"
	REPO="${BATS_TEST_TMPDIR}/repo"
}

make_repo() {
	git init -q "$REPO"
	cd "$REPO" || return
	git config commit.gpgsign false
	git config tag.gpgsign false
	echo one >file
	git add file
	git commit -q -m "test: first"
}

# value_of <key>: the value printed for key, from $output.
value_of() {
	local line
	for line in "${lines[@]}"; do
		if [[ $line == "$1 "* ]]; then
			printf '%s\n' "${line#"$1" }"
			return 0
		fi
	done
	return 1
}

# assert_value <key> <expected>
assert_value() {
	local got
	got=$(value_of "$1") || {
		echo "missing key $1" >&2
		return 1
	}
	[[ $got == "$2" ]] || {
		echo "$1: got '$got', want '$2'" >&2
		return 1
	}
}

# assert_value_matches <key> <regex>
assert_value_matches() {
	local got
	got=$(value_of "$1") || {
		echo "missing key $1" >&2
		return 1
	}
	[[ $got =~ $2 ]] || {
		echo "$1: got '$got', want match '$2'" >&2
		return 1
	}
}

@test "prints exactly the three STABLE_BUILD_SCM keys, in order" {
	make_repo
	run sh "$SCRIPT"
	[ "$status" -eq 0 ]
	[ "${#lines[@]}" -eq 3 ]
	[[ "${lines[0]}" == "STABLE_BUILD_SCM_VERSION "* ]]
	[[ "${lines[1]}" == "STABLE_BUILD_SCM_REVISION "* ]]
	[[ "${lines[2]}" == "STABLE_BUILD_SCM_DATE "* ]]
}

@test "untagged repo reports the dev version, the short commit and the commit date" {
	make_repo
	run sh "$SCRIPT"
	[ "$status" -eq 0 ]
	assert_value STABLE_BUILD_SCM_VERSION "0.0.0-dev"
	local rev
	rev=$(git rev-parse --short=12 HEAD)
	assert_value STABLE_BUILD_SCM_REVISION "$rev"
	assert_value STABLE_BUILD_SCM_DATE "2026-01-02"
}

@test "date is the commit date, not the build time" {
	make_repo
	GIT_COMMITTER_DATE=2025-12-31T23:00:00Z git commit -q --allow-empty -m "test: second"
	run sh "$SCRIPT"
	assert_value STABLE_BUILD_SCM_DATE "2025-12-31"
}

@test "tagged commit reports the tag" {
	make_repo
	git tag -a v1.2.3 -m v1.2.3
	run sh "$SCRIPT"
	assert_value STABLE_BUILD_SCM_VERSION "v1.2.3"
}

@test "commits after a tag report the describe form" {
	make_repo
	git tag -a v1.2.3 -m v1.2.3
	git commit -q --allow-empty -m "test: second"
	run sh "$SCRIPT"
	assert_value_matches STABLE_BUILD_SCM_VERSION '^v1\.2\.3-1-g[0-9a-f]+$'
}

@test "uncommitted changes add a -dirty suffix" {
	make_repo
	git tag -a v1.2.3 -m v1.2.3
	echo two >file
	run sh "$SCRIPT"
	assert_value STABLE_BUILD_SCM_VERSION "v1.2.3-dirty"
}

@test "outside a git repository every value falls back" {
	mkdir -p "${BATS_TEST_TMPDIR}/plain"
	cd "${BATS_TEST_TMPDIR}/plain" || return
	export GIT_CEILING_DIRECTORIES="$BATS_TEST_TMPDIR"
	run sh "$SCRIPT"
	[ "$status" -eq 0 ]
	assert_value STABLE_BUILD_SCM_VERSION "0.0.0-dev"
	assert_value STABLE_BUILD_SCM_REVISION "unknown"
	assert_value STABLE_BUILD_SCM_DATE "unknown"
}

@test "a repository with no commits falls back for revision and date" {
	git init -q "$REPO"
	cd "$REPO" || return
	run sh "$SCRIPT"
	[ "$status" -eq 0 ]
	assert_value STABLE_BUILD_SCM_VERSION "0.0.0-dev"
	assert_value STABLE_BUILD_SCM_REVISION "unknown"
	assert_value STABLE_BUILD_SCM_DATE "unknown"
}
