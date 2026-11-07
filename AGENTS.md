# Agent instructions

## What this is

`gomodscan` is a Go command-line tool that scans the modules a Go project vendors. It reports a module that pkg.go.dev marks as retracted or deprecated, and a module that the OSV malicious-package registry flags as malware. Output is text or SARIF, and the Bazel build in this repository pins and runs every check.

The Go module path is `go.tbhb.dev/gomodscan`. Exit status 0 means every module came back clean and 1 means the scan reported a finding. Status 2 means the run failed or the scanner couldn't check a module after the retries, and it takes precedence over 1 when both apply. `-o` (long form `--output`) writes the findings to a file instead of stdout. `--summary-json` writes a JSON summary of the run at schema 1 on every exit status, recording the cause when the scan never started. The scanner replaces both files atomically.

## Layout

`cmd/gomodscan/` holds the command-line entry point and its tests. `internal/` holds the packages behind it: `vendormod` reads `vendor/modules.txt`, `pkgsite` and `osv` query the two registries, `cachehttp` and `retryhttp` wrap their HTTP transport, `findings` writes the text and SARIF output, `exitcode` names the exit statuses, and `buildmeta` resolves version metadata from linker flags or runtime build info. `.go-arch-lint.yml` sets which of them may import which.

Tests read their inputs from `testdata/` directories. The `vendormod` fixture `testdata/self` mirrors what `go mod vendor` writes for this module, and a test compares it with the requirements in `go.mod`. A dependency bump has to update that fixture.

`tools/` holds the lint package and the workspace status script that stamps the version. `docs/` is an OKF bundle with its own rules in `docs/AGENTS.md`. `.github/` holds the workflows, the CODEOWNERS file, and the repository rulesets.

## Commands

Bazel pins every tool and runs every check. The only thing [mise](https://mise.jdx.dev) installs is `bazelisk`, at the version `mise.toml` and `mise.lock` pin. A fresh worktree needs `mise install`, then `bazelisk run //:bazel_env` for the tool shims, while `tbhbdev alpha install` runs once per machine for the user-level harness hooks, whose session start hook installs the clone's git hooks in every worktree, a new one included.

| Command | Purpose |
| --- | --- |
| `bazelisk test //...` | Run every check |
| `bazelisk query 'tests(//...)'` | List the checks |
| `bazelisk run //:format` | Format the tree in place |
| `bazelisk run //:buildifier` | Format the Bazel files |
| `bazelisk run //:gazelle` | Regenerate the `BUILD.bazel` files from the Go sources |
| `bazelisk mod tidy` | Update `use_repo` in `MODULE.bazel` |
| `bazelisk build --config=release //cmd/gomodscan` | Build the binary with version metadata |
| `bazelisk run //cmd/gomodscan -- <flags>` | Run the scanner from source |

Each check runs by its target, such as `bazelisk test //:vale_test`. The Go checks are `//:golangci_lint_test`, `//:go_deadcode_test`, `//:go_arch_lint_test`, `//:go_mod_tidy_test`, `//:govulncheck_test`, `//:gomutants_test` and one `gobco_test` per package. The `nogo` analyzers also run during each Go build, and a finding fails it.

## Go toolchain

`go.mod` declares the `go` line, and Bazel's Go SDK follows it with `GOTOOLCHAIN=local`. The file has no `toolchain` line. Renovate leaves the `go` line alone. Raise it by hand when a tool needs a newer one, as gomutants did.

Run Go commands through `.bazel_env/bin/go` so they use the pinned SDK. Edit imports and dependencies in `go.mod`, then run Gazelle and `bazelisk mod tidy`, and commit `go.sum` and `MODULE.bazel.lock` with them. Bazel generates `MODULE.bazel.lock`, so never edit it by hand.

## Coverage and mutation testing

Each Go package has a `gobco_test` that demands 100% condition coverage. The target has no floor and no exclusion list. A new branch needs a test that takes both outcomes. `gomutants_test` fails while the tests leave a mutant alive. Account for a mutant that behaves like the original with a reviewed `// gomutants:disable-next-line <MUTATOR> reason="..."` directive.

Tests must give the same result on every run. A fixture or a fake transport replaces each registry. Tests run offline and pass in any order.

## Conventions

Change only the files the task needs, and stage paths by name. Run `bazelisk test //...` before committing. Keep private values in an ignored file, never in the tree.

Write each Markdown paragraph on one line. `rumdl`, Vale and cspell check the Markdown and the Go comments, so keep the prose plain.

Commit messages follow Conventional Commits, as `cog.toml` configures. `cog` writes `CHANGELOG.md` from them. The `tbhbdev alpha` hooks stamp the attribution trailers and guard the `gh pr` commands. Open and merge pull requests with `tbhbdev alpha pr` and `tbhbdev alpha merge`. The stamp-docs hook runs `tbhbdev alpha identity stamp-docs`.

## Identities

Create commits as `tbhb-agent`, signed with the machine's key. Route reviews through the reviewer identity that the machine configuration provides. Push only to a branch, and never to `main`. A real commit always runs the full hook suite.

## Workflows

`ci.yml` runs on pull requests and pushes to `main`. A `bazel` job runs `bazelisk test //...` on Linux x64 and arm64, macOS, and Windows, and a final `conclusion` job gives branch protection one required check. `codeql.yml` analyzes Go and the workflows. `renovate.yaml` runs Renovate, and `renovate-config-validator.yaml` validates its configuration. All scheduled times use Coordinated Universal Time (UTC).
