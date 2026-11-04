# SPDX-License-Identifier: Apache-2.0
# Copyright Tony Burns

"""golangci-lint over this repository's .golangci.yml."""

load("@tbhb_rules_go//:defs.bzl", "golangci_lint_aspect_factory", "golangci_lint_test_factory")

golangci_lint = golangci_lint_aspect_factory(
    config = "//:.golangci.yml",
    go_mod = Label("//:go.mod"),
)

golangci_lint_test = golangci_lint_test_factory(golangci_lint)
