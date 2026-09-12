@echo off
setlocal enabledelayedexpansion

rem AWGSocks build script. Produces awgsocks.exe for Windows x64.
rem Build-time requirements: Go 1.25 or newer, and Git only if you want the
rem commit hash and date stamped into the binary. No C compiler and no CGO are
rem needed.

cd /d "%~dp0\.."

set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=0

set VERSION=1.0.0
set PKG=github.com/ComoEstaisAmigos/awgsocks/internal/version

set COMMIT=unknown
for /f "delims=" %%i in ('git rev-parse --short^=7 HEAD 2^>nul') do set COMMIT=%%i

rem The stamped date is the commit date, not the moment of the build, so the
rem same commit always builds into the same binary. SOURCE_DATE_EPOCH, the
rem reproducible-builds.org convention, takes precedence when it is set.
set BUILDDATE=unknown
set EPOCH=%SOURCE_DATE_EPOCH%
if not defined EPOCH (
  for /f "delims=" %%i in ('git log -1 --format^=%%ct 2^>nul') do set EPOCH=%%i
)
if defined EPOCH (
  for /f "delims=" %%i in ('powershell -NoProfile -Command "[DateTimeOffset]::FromUnixTimeSeconds(%EPOCH%).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')"') do set BUILDDATE=%%i
)

echo Building AWGSocks %VERSION% (commit %COMMIT%) for %GOOS%/%GOARCH%

go build -trimpath ^
  -ldflags="-s -w -X %PKG%.Version=%VERSION% -X %PKG%.Commit=%COMMIT% -X %PKG%.BuildDate=%BUILDDATE%" ^
  -o awgsocks.exe .\cmd\awgsocks

if errorlevel 1 (
  echo.
  echo BUILD FAILED
  exit /b 1
)

echo.
echo Built: %CD%\awgsocks.exe
.\awgsocks.exe version
endlocal
