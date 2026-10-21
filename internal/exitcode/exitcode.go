// SPDX-License-Identifier: Apache-2.0
// Copyright Tony Burns

// Package exitcode defines the exit-code convention every
// findings-reporting scanner under tools/ follows. Wrapping the
// three integers in a named package lets reviewers grep one place
// to confirm the contract and keeps drift between scanners out of
// the picture.
package exitcode

const (
	// OK signals that no findings surfaced and the tool ran to
	// completion.
	OK = 0

	// Findings signals that at least one finding surfaced. The tool
	// itself ran to completion; the non-zero exit tells the caller
	// to review the output before proceeding.
	Findings = 1

	// ToolFailure signals that the tool couldn't finish the job: an
	// input it scans couldn't be evaluated even after retries, or the
	// run failed outright (bad arguments, a parse error, missing
	// inputs, a failed output write). It outranks Findings, so a run
	// that surfaced findings but left an input unevaluated still
	// exits ToolFailure, since its findings list may be incomplete.
	// Callers should retry or escalate.
	ToolFailure = 2
)
