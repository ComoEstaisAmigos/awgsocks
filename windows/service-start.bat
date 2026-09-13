@echo off
setlocal EnableExtensions EnableDelayedExpansion
title AWGSocks - start service
cd /d "%~dp0"

set "RC=0"
set "AWGSOCKS=%~dp0awgsocks.exe"
set "SOCKS=127.0.0.1:10808"

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
    echo The AWGSocks service is not installed, so there is nothing to start.
    echo.
    echo Run service-install.bat with your .conf file first.
    goto :END
)

echo Starting the service...
echo.
"%AWGSOCKS%" start
if errorlevel 1 goto :FAIL

echo.
echo Waiting for the proxy to answer...
set "READY="
for /l %%i in (1,1,20) do (
    if not defined READY (
        call :PROBE
        if not errorlevel 1 set "READY=1"
        if not defined READY powershell -NoProfile -Command "Start-Sleep -Milliseconds 500" >nul 2>&1
    )
)
set "PAUSED="
if defined READY call :READ_PAUSE

echo.
if defined PAUSED (
    echo The service is running, but the tunnel is paused: this configuration is
    echo connected on the Windows adapter !PAUSED!.
    echo.
    echo The proxy refuses requests until that adapter disconnects, and the
    echo tunnel resumes by itself when it does.
) else if defined READY (
    echo The SOCKS5 proxy is accepting connections on %SOCKS%
) else (
    echo The service started but %SOCKS% did not answer yet.
    echo Run service-status.bat in a moment to see why.
)
goto :END

:PROBE
powershell -NoProfile -Command "try{$c=New-Object Net.Sockets.TcpClient;$c.Connect('127.0.0.1',10808);$c.Close();exit 0}catch{exit 1}" >nul 2>&1
exit /b %errorlevel%

rem An open port does not mean the proxy is carrying traffic: while the same
rem configuration is connected through another client, the tunnel is paused and
rem the proxy refuses requests. The management pipe comes up a moment after the
rem port, so the question is asked a few times before giving up.
:READ_PAUSE
set "PAUSED="
for /f "usebackq delims=" %%P in (`powershell -NoProfile -Command "for ($i = 0; $i -lt 10; $i++) { try { $s = (& $env:AWGSOCKS status --json | Out-String) | ConvertFrom-Json; if ($s.tunnel) { if ($s.tunnel.paused_by) { $s.tunnel.paused_by }; exit } } catch {}; Start-Sleep -Milliseconds 300 }"`) do set "PAUSED=%%P"
exit /b 0

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
