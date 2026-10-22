# Agent instructions

## What this is

`gomodscan` is a Go command-line tool that scans the modules a Go project vendors. It reports a module that pkg.go.dev marks as retracted or deprecated, and a module that the OSV malicious-package registry flags as malware. It writes text or SARIF. The repository also contains its development tools and CI gates, and it uses devtools v0.15.0.

The scanner exits 0 when every module comes back clean and 1 when it reports a finding. Exit 2 means the run failed or the scanner couldn't check a module after the retries. Exit 2 takes precedence over exit 1 when both apply. `-o` (long form `--output`) writes the findings to a file instead of stdout. `--summary-json` writes a JSON summary of the run at schema 1 on every exit status, and it records the cause when the scan never started. The scanner replaces both files atomically.

## Layout

`cmd/gomodscan/` holds the command-line entry point and its tests. `internal/` holds the packages behind it: `vendormod` reads `vendor/modules.txt`, `pkgsite` and `osv` query the two registries, `cachehttp` and `retryhttp` wrap their HTTP transport, `findings` writes the text and SARIF output, `exitcode` names the exit statuses, and `buildmeta` resolves version metadata from linker flags or runtime build info.

`.devtools/` and `.config/mise/conf.d/` hold the devtools v0.15.0 payload. The `vendir` tool owns both directories. Edit repository settings in the root configuration files.

APM deploys the skills and rules from the devtools packages named in `apm.yml` to `.agents/` and `.claude/`. That includes `commit`, `pr`, `merge-pr`, `agent-commit`, `agent-pr`, and `agent-merge-pr`. Deploy them with `mise run devtools:apm-sync` and never edit the deployed copies. `.agents/agent-skills.conf` holds this repository's policy for the agent skills, such as the lint commands and which changed paths go to the owner. The machine supplies the reviewer, the GitHub account, the required reviewer, and the delegation.

## Commands

Read `mise.toml` before trusting it. In each fresh worktree, run `mise trust`, then `mise run bootstrap` to sync the payload and install the tools and hooks.

| Command | Purpose |
| --- | --- |
| `mise run bootstrap` | Sync the payload, install the toolchain, and install the git hooks |
| `mise run devtools:apm-sync` | Deploy agent tooling |
| `mise run lint` | Check every source gate |
| `mise run check` | Tidy, verify, lint, test, scan reachable vulnerabilities, and check vendor drift |
| `mise run check-all` | Run `check`, then the race detector, the fuzz sweep, the self-scan, and gitleaks |
| `mise run build` | Build `bin/gomodscan` with version metadata |
| `mise run test` | Run the Go tests |
| `mise run test-go-race` | Run the Go tests with the race detector |
| `mise run cover-go` | Measure coverage and enforce the floors in `.testcoverage.yml` |
| `mise run lint-go-all` | Run the Go analysis gates |
| `mise run lint-go-fmt` | Check Go formatting |
| `mise run vuln` | Scan reachable Go vulnerabilities |
| `mise run scan` | Scan the vendored modules with gomodscan built from source |
| `mise run fuzz` | Run each fuzz target for `FUZZ_TIME`, 30 seconds by default |
| `mise run mutate-go` | Run mutation testing |
| `mise run vendor` | Tidy `go.mod` and refresh `vendor/` |
| `mise run vendor-check` | Fail when `go.mod`, `go.sum`, or `vendor/` drift from the committed tree |
| `mise run lint-commit-msg` | Check the draft in `COMMIT_AGENTMSG` |
| `mise run devtools:prek-all` | Run every hook on every file |

## Go toolchain

Go 1.27.3 comes from the shared payload, while `go.mod` declares `go 1.26` with `toolchain go1.26.5`. Use `mise exec -- go version` to inspect the active toolchain. Go tool directives declare the analyzer dependencies, and `DEVTOOLS_GO_MODULES_MODE=vendor` loads them from the tracked `vendor/` tree. Commit `go.sum` with the vendored sources.

gomodscan scans itself from source. Both scan tasks and the `scan` hook build `./cmd/gomodscan` and then run the binary. Each scan exercises the code under review, and the scanner's own exit status decides whether the scan passes. The shared `devtools:gomodscan` task needs `go tool gomodscan`, and this module has no such tool directive.

`.testcoverage.yml` sets the coverage floors: 75% for each file, 80% for each package, and 85% for the total. They skip `internal/exitcode`, which holds constants and no statements.

## Conventions

Change only the files the task needs, and stage paths by name. Run the checks before committing. Keep private values in the ignored `mise.local.toml` file.

Commit through the `commit` or `agent-commit` skill. Each drafts the message in `COMMIT_AGENTMSG` and runs `mise run lint-commit-msg` before committing.

Write each Markdown paragraph on one line. The guard-markdown hook checks this rule.

The devtools payload owns `.devtools/` and `.config/mise/conf.d/`. Edit repository policy in `mise.toml`. Keep every devtools pin on the same release, including the tool versions in `mise.toml`, and run `mise run devtools:check-pins` after a pin change.

## Identities

Create commits as `tbhb-agent`. Route reviews through `gh-reviewer` as `tbhb-agent-reviewer`. The agent skills from the devtools packages keep these identities separate, and the accounts come from the machine configuration.

## Workflows

All scheduled times use Coordinated Universal Time (UTC).

`ci.yml` runs on pull requests and pushes to `main`. It checks lint, runs the tests with coverage and the race detector on Linux x64 and arm64, macOS, and Windows, and merges the coverage reports. Separate jobs enforce the coverage floors (`cover-go-check`), scan reachable vulnerabilities (`vuln`), and check Go vendor drift (`vendor-check`). The required `test` summary fails unless every matrix slot succeeds.

`security.yml` runs on pull requests and pushes to `main`, and daily at 07:37. `gitleaks` scans history through the head of the branch on pull requests. `govulncheck` and `gomodscan` upload reports to Code Scanning, and `gomodscan` scans from source.

`codeql.yml` analyzes Go and the workflows on pull requests and pushes to `main`, and on Sundays at 03:27.

`fuzz-nightly.yml` runs the fuzz targets nightly at 03:17, and `mutation-nightly.yml` runs mutation testing nightly at 04:42. Manual dispatch runs either one.

`lint-codeowners.yml` checks CODEOWNERS on every pull request.

`lint-workflows.yml` runs when a pull request or a push to `main` changes a workflow. Manual dispatch runs it too.

`renovate-config-validator.yaml` validates Renovate configuration when a pull request or push to `main` changes `**renovate.json5`, and it also accepts manual dispatch.

`renovate.yaml` runs Renovate at the top of every hour on weekdays and every two hours on weekends. Manual dispatch can enable debug logging.
