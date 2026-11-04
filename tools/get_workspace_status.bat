@echo off
rem SPDX-License-Identifier: Apache-2.0
rem Copyright Tony Burns

rem Workspace status command for stamped Windows builds
rem (--config=release-windows); tools/get_workspace_status.sh is the same
rem for macOS and Linux. Bazel runs it directly, without a shell. Key names
rem follow Bazel's BUILD_SCM_* convention, and each value falls back
rem explicitly when git fails. The date goes in commit_date because %date% is
rem cmd's built-in current date, which `if defined` always sees.
setlocal
set "version="
set "revision="
set "commit_date="
for /f "delims=" %%v in ('git describe --tags --dirty 2^>nul') do set "version=%%v"
for /f "delims=" %%v in ('git rev-parse --short^=12 HEAD 2^>nul') do set "revision=%%v"
for /f "delims=" %%v in ('git log -1 --format^=%%cs 2^>nul') do set "commit_date=%%v"
if not defined version set "version=0.0.0-dev"
if not defined revision set "revision=unknown"
if not defined commit_date set "commit_date=unknown"
echo STABLE_BUILD_SCM_VERSION %version%
echo STABLE_BUILD_SCM_REVISION %revision%
echo STABLE_BUILD_SCM_DATE %commit_date%
