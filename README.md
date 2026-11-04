# gomodscan

`gomodscan` is a Go command-line tool that scans the modules a Go project vendors. It reports a module that pkg.go.dev marks as retracted or deprecated, and a module that the OSV malicious-package registry flags as malware. Output is text or SARIF.

## Usage

Run the tool from a module root that has a `vendor/` directory:

```sh
gomodscan -modroot . -format sarif -o gomodscan.sarif --summary-json summary.json
```

Exit status 0 means every module came back clean and 1 means the scan reported a finding. Status 2 means the run failed or the scanner couldn't check a module after the retries, and it takes precedence over 1 when both apply. Run `gomodscan -h` for every flag.

## Development

Bazel builds and tests the project. See `AGENTS.md` for the commands.

## Module path

The Go module path is now `go.tbhb.dev/gomodscan`, moved from `github.com/tbhb-dev/gomodscan`. The old path isn't deprecated. Releases up to v0.1.0 declare the old path.
