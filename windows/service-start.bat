@echo off
setlocal EnableExtensions EnableDelayedExpansion
title AWGSocks - start service
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

echo Starting the service...
echo.
"%AWGSOCKS%" start
if errorlevel 1 goto :FAIL

call :READ_SOCKS
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
powershell -NoProfile -Command "try{$h,$p=$env:SOCKS -split ':(?=\d+$)';$c=New-Object Net.Sockets.TcpClient;$c.Connect($h.Trim('[',']'),[int]$p);$c.Close();exit 0}catch{exit 1}" >nul 2>&1
exit /b %errorlevel%

:READ_PAUSE
set "PAUSED="
for /f "usebackq delims=" %%P in (`powershell -NoProfile -Command "for ($i = 0; $i -lt 10; $i++) { try { $s = (& $env:AWGSOCKS status --json | Out-String) | ConvertFrom-Json; if ($s.tunnel) { if ($s.tunnel.paused_by) { $s.tunnel.paused_by }; exit } } catch {}; Start-Sleep -Milliseconds 300 }"`) do set "PAUSED=%%P"
exit /b 0

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
