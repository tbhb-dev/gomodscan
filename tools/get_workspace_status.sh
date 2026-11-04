#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright Tony Burns

# Workspace status command for stamped (--config=release) builds.
# Key names follow Bazel's BUILD_SCM_* convention. The STABLE_ prefix makes a
# changed value re-stamp dependent targets; unprefixed keys are volatile.
set -eu
# Each value is computed separately so a git failure falls back explicitly
# instead of being masked inside a command substitution.
version=$(git describe --tags --dirty 2>/dev/null) || version=0.0.0-dev
revision=$(git rev-parse --short=12 HEAD 2>/dev/null) || revision=unknown
date=$(git log -1 --format=%cs 2>/dev/null) || date=unknown

echo "STABLE_BUILD_SCM_VERSION ${version}"
echo "STABLE_BUILD_SCM_REVISION ${revision}"
echo "STABLE_BUILD_SCM_DATE ${date}"
