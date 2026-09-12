@echo off
setlocal enabledelayedexpansion

rem Runs the checks required before a release: formatting, vet, tests, build.

cd /d "%~dp0\.."

echo === gofmt ===
set FMT=
for /f "delims=" %%i in ('gofmt -l .\cmd .\internal') do set FMT=!FMT! %%i
if not "!FMT!"=="" (
  echo Unformatted files:!FMT!
  exit /b 1
)
echo ok

echo.
echo === go vet ===
go vet ./...
if errorlevel 1 exit /b 1

echo.
echo === go test ===
go test ./...
if errorlevel 1 exit /b 1

echo.
echo === go build ===
go build ./...
if errorlevel 1 exit /b 1

echo.
echo All checks passed.
endlocal
