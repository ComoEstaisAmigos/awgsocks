@echo off
setlocal enabledelayedexpansion

rem AWGSocks build script. Produces awgsocks.exe for Windows x64.
rem Build-time requirements: Go 1.25 or newer, and Git only if you want the
rem commit hash stamped into the binary. No C compiler and no CGO are needed.

cd /d "%~dp0\.."

set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=0

set VERSION=1.0.0
set PKG=github.com/ComoEstaisAmigos/awgsocks/internal/version

set COMMIT=unknown
for /f "delims=" %%i in ('git rev-parse --short HEAD 2^>nul') do set COMMIT=%%i

for /f "delims=" %%i in ('powershell -NoProfile -Command "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"') do set BUILDDATE=%%i

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
