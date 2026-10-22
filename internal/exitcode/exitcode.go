// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

// Package exitcode defines the exit-code convention every
// findings-reporting scanner under tools/ follows. Wrapping the
// three integers in a named package lets reviewers grep one place
// to confirm the contract and keeps drift between scanners out of
// the picture.
package exitcode

const (
	// OK signals that the tool ran to completion without any
	// findings.
	OK = 0

	// Findings signals that the tool reported at least one finding. The tool
	// itself ran to completion; the non-zero exit tells the caller
	// to review the output before proceeding.
	Findings = 1

	// ToolFailure signals that the tool couldn't finish the job: an
	// input it scans couldn't be evaluated even after retries, or the
	// run failed outright (bad arguments, a parse error, missing
	// inputs, a failed output write). It takes precedence over Findings,
	// so a run that reported findings but left an input unevaluated still
	// exits ToolFailure, since its findings list may be incomplete.
	// Callers should retry or escalate.
	ToolFailure = 2
)
