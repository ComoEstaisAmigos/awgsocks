@echo off
setlocal EnableExtensions
title AWGSocks - status
cd /d "%~dp0"

set "RC=0"
set "AWGSOCKS=%~dp0awgsocks.exe"

net session >nul 2>&1
if errorlevel 1 goto :ELEVATE

if not exist "%AWGSOCKS%" (
    echo awgsocks.exe was not found next to this script.
	echo.
    echo Expected: %AWGSOCKS%
    goto :FAIL
)

sc query AWGSocks >nul 2>&1
if errorlevel 1 (
    echo The AWGSocks service is not installed.
	echo.
    echo Run service-install.bat with your .conf file.
    goto :END
)

"%AWGSOCKS%" status

rem --- Show what is actually talking to the proxy right now --------------------
rem A client's socket has RemotePort 10808. Matching on LocalPort instead would
rem list the service's own accepted sockets and report awgsocks as its own user.
echo.
echo == Applications using the proxy right now ==
powershell -NoProfile -Command ^
  "$c = Get-NetTCPConnection -RemotePort 10808 -State Established -ErrorAction SilentlyContinue;" ^
  "if (-not $c) { '    Nothing is using the proxy at the moment.'; exit }" ^
  "$c | Group-Object OwningProcess | ForEach-Object {" ^
  "  $p = Get-Process -Id $_.Name -ErrorAction SilentlyContinue;" ^
  "  $n = if ($p) { $p.ProcessName } else { 'pid ' + $_.Name };" ^
  "  '    {0,-22} {1} connection(s)' -f $n, $_.Count }"

rem --- Leak check -------------------------------------------------------------
rem Only an application that is using the proxy AND reaching the internet
rem directly at the same time is a leak. Flagging every unproxied program would
rem just report your whole desktop.
echo.
echo == Leak check ==
powershell -NoProfile -Command ^
  "$ids = (Get-NetTCPConnection -RemotePort 10808 -State Established -ErrorAction SilentlyContinue).OwningProcess | Select-Object -Unique;" ^
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

:ELEVATE
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
endlocal
exit /b 0

:FAIL
set "RC=1"

:END
echo.
echo Press any key to close...
pause >nul
endlocal & exit /b %RC%
