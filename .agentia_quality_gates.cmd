@echo off
setlocal EnableExtensions
REM Local Agentia quality gates (Windows) for the safefix TypeScript plugin.
REM Runs from the repo root. Must exit non-zero if any check fails.

echo ## Building plugin
call npm run build
if errorlevel 1 exit /b 1

echo ## Running tests
call npm test
if errorlevel 1 exit /b 1

echo ## All quality gates passed
exit /b 0