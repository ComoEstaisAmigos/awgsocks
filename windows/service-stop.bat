@echo off
setlocal EnableExtensions
title AWGSocks - stop service
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
    echo Expected: %AWGSOCKS%
    goto :FAIL
)

echo Stopping the service...
echo.
"%AWGSOCKS%" stop
if errorlevel 1 goto :FAIL

call :READ_SOCKS
echo.
echo The tunnel is down and %SOCKS% is closed. Anything still
echo configured to use the proxy will fail to connect rather than fall back
echo to your default connection.
echo.
echo The service stays installed. Run service-start.bat to bring it back up.
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
