@echo off
setlocal EnableExtensions
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
echo Waiting for the AmneziaWG handshake...
set "READY="
for /l %%i in (1,1,20) do (
    if not defined READY (
        call :PROBE
        if not errorlevel 1 set "READY=1"
        if not defined READY powershell -NoProfile -Command "Start-Sleep -Milliseconds 500" >nul 2>&1
    )
)

echo.
if defined READY (
    echo The SOCKS5 proxy is accepting connections on %SOCKS%
) else (
    echo The service started but %SOCKS% did not answer yet.
    echo Run service-status.bat in a moment to see why.
)
goto :END

:PROBE
powershell -NoProfile -Command "try{$c=New-Object Net.Sockets.TcpClient;$c.Connect('127.0.0.1',10808);$c.Close();exit 0}catch{exit 1}" >nul 2>&1
exit /b %errorlevel%

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
