@echo off
rem SPDX-License-Identifier: Apache-2.0
rem Copyright Tony Burns

rem Checks tools/get_workspace_status.bat: it prints the three stable keys.
rem The test sandbox has no git repository, so the values are the fallbacks.
setlocal
set "script=%TEST_SRCDIR%\_main\tools\get_workspace_status.bat"
set "out=%TEST_TMPDIR%\status.txt"
cd /d "%TEST_TMPDIR%"
call "%script%" >"%out%" || exit /b 1
findstr /x /c:"STABLE_BUILD_SCM_VERSION 0.0.0-dev" "%out%" >nul || (type "%out%" & exit /b 1)
findstr /x /c:"STABLE_BUILD_SCM_REVISION unknown" "%out%" >nul || (type "%out%" & exit /b 1)
findstr /x /c:"STABLE_BUILD_SCM_DATE unknown" "%out%" >nul || (type "%out%" & exit /b 1)
echo ok
