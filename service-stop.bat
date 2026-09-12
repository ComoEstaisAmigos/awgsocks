@echo off
setlocal EnableExtensions
title AWGSocks - stop service
cd /d "%~dp0"

set "RC=0"
set "AWGSOCKS=%~dp0awgsocks.exe"

net session >nul 2>&1
if errorlevel 1 goto :ELEVATE

if not exist "%AWGSOCKS%" (
    echo awgsocks.exe was not found next to this script.
    echo Expected: %AWGSOCKS%
    goto :FAIL
)

sc query AWGSocks >nul 2>&1
if errorlevel 1 (
    echo The AWGSocks service is not installed, so there is nothing to stop.
    goto :END
)

echo Stopping the service...
echo.
"%AWGSOCKS%" stop
if errorlevel 1 goto :FAIL

echo.
echo The tunnel is down and 127.0.0.1:10808 is closed. Anything still
echo configured to use the proxy will fail to connect rather than fall back
echo to your default connection.
echo.
echo The service stays installed. Run service-start.bat to bring it back up.
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
