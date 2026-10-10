@echo off
setlocal EnableExtensions
title AWGSocks - status
cd /d "%~dp0"

set "SVCDIR="
for /f "tokens=1,2,*" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\AWGSocks" /v ImagePath 2^>nul') do if /i "%%A"=="ImagePath" call :SERVICE_DIR %%C
if not defined AWGSOCKS_FORWARDED if defined SVCDIR if /i not "%SVCDIR%"=="%~dp0" if exist "%SVCDIR%%~nx0" goto :FORWARD

set "RC=0"
set "AWGSOCKS=%~dp0awgsocks.exe"

net session >nul 2>&1
if errorlevel 1 goto :ELEVATE

sc query AWGSocks >nul 2>&1
if errorlevel 1 (
    echo The AWGSocks service is not installed.
    goto :END
)

if not exist "%AWGSOCKS%" if defined SVCDIR set "AWGSOCKS=%SVCDIR%awgsocks.exe"
if not exist "%AWGSOCKS%" (
    echo awgsocks.exe was not found next to this script.
    echo.
    echo Expected: %AWGSOCKS%
    goto :FAIL
)

"%AWGSOCKS%" status
call :READ_SOCKS

echo.
echo == Applications using the proxy right now ==
powershell -NoProfile -Command ^
  "$c = Get-NetTCPConnection -RemotePort ([int]($env:SOCKS -replace '.*:','')) -State Established -ErrorAction SilentlyContinue;" ^
  "if (-not $c) { '    Nothing is using the proxy at the moment.'; exit }" ^
  "$c | Group-Object OwningProcess | ForEach-Object {" ^
  "  $p = Get-Process -Id $_.Name -ErrorAction SilentlyContinue;" ^
  "  $n = if ($p) { $p.ProcessName } else { 'pid ' + $_.Name };" ^
  "  '    {0,-22} {1} connection(s)' -f $n, $_.Count }"

echo.
echo == Leak check ==
powershell -NoProfile -Command ^
  "$ids = (Get-NetTCPConnection -RemotePort ([int]($env:SOCKS -replace '.*:','')) -State Established -ErrorAction SilentlyContinue).OwningProcess | Select-Object -Unique;" ^
  "if (-not $ids) { '    Nothing is using the proxy, so there is nothing to check.'; exit }" ^
  "$leaks = @();" ^
  "foreach ($procId in $ids) {" ^
  "  $p = Get-Process -Id $procId -ErrorAction SilentlyContinue;" ^
  "  if (-not $p) { continue }" ^
  "  $direct = Get-NetTCPConnection -OwningProcess $procId -State Established -ErrorAction SilentlyContinue |" ^
  "    Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1$)' };" ^
  "  if ($direct) { $leaks += ('    {0}: {1} connection(s) outside the tunnel' -f $p.ProcessName, $direct.Count) } }" ^
  "if ($leaks) { 'LEAK: these applications use the proxy and also connect directly.'; $leaks; '';" ^
  "  'Check their proxy settings. In qBittorrent the peer, RSS and general'; " ^
  "  'proxy boxes all have to be ticked.' }" ^
  "else { '    Every application using the proxy is using it exclusively.' }"

goto :END

:FORWARD
echo AWGSocks is installed in %SVCDIR%
echo Running the script there instead of the copy in %~dp0
echo.
set "AWGSOCKS_FORWARDED=1"
call "%SVCDIR%%~nx0"
endlocal & exit /b %errorlevel%

:READ_SOCKS
set "SOCKS=127.0.0.1:10808"
for /f "usebackq delims=" %%L in (`powershell -NoProfile -Command "try { (Get-Content -Raw -ErrorAction Stop -LiteralPath (Join-Path $env:ProgramData 'AWGSocks\config.json') | ConvertFrom-Json).socks5_listen } catch {}"`) do set "SOCKS=%%L"
exit /b 0

:SERVICE_DIR
set "SVCDIR=%~dp1"
exit /b 0

:ELEVATE
set "SELF=%~f0"
powershell -NoProfile -Command "Start-Process -FilePath $env:SELF -Verb RunAs"
endlocal
exit /b 0

:FAIL
set "RC=1"

:END
echo.
echo Press any key to close...
pause >nul
endlocal & exit /b %RC%
