@echo off
setlocal EnableExtensions
title AWGSocks - edit settings
cd /d "%~dp0"

set "SVCDIR="
for /f "tokens=1,2,*" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\AWGSocks" /v ImagePath 2^>nul') do if /i "%%A"=="ImagePath" call :SERVICE_DIR %%C
if not defined AWGSOCKS_FORWARDED if defined SVCDIR if /i not "%SVCDIR%"=="%~dp0" if exist "%SVCDIR%%~nx0" goto :FORWARD

set "RC=0"
set "AWGSOCKS=%~dp0awgsocks.exe"
set "CONFIG=%ProgramData%\AWGSocks\config.json"

net session >nul 2>&1
if errorlevel 1 goto :ELEVATE

if not exist "%CONFIG%" (
    echo The AWGSocks service is not installed.
    goto :END
)

if not exist "%AWGSOCKS%" if defined SVCDIR set "AWGSOCKS=%SVCDIR%awgsocks.exe"
if not exist "%AWGSOCKS%" (
    echo awgsocks.exe was not found next to this script.
    echo Expected: %AWGSOCKS%
    goto :FAIL
)

echo Opening the settings file. Close Notepad when you are done.
echo.
echo   %CONFIG%
echo.
echo Every setting is documented at
echo   https://github.com/ComoEstaisAmigos/awgsocks/blob/main/docs/CONFIGURATION.md
echo The one that most often needs changing is log_level, which accepts debug,
echo info, warn or error.
echo.
start /wait notepad "%CONFIG%"

sc query AWGSocks | find "RUNNING" >nul 2>&1
if errorlevel 1 (
    echo The service is not running, so there is nothing to apply to. Your changes
    echo are saved and take effect when it next starts.
    echo.
    echo Run service-start.bat to start it.
    goto :END
)

echo Applying the changes...
echo.
"%AWGSOCKS%" reload
if errorlevel 1 (
    echo.
    echo The settings were NOT applied and the running tunnel was left alone.
    echo The message above says why. If it points at something in the file,
    echo run this script again and correct it.
    goto :FAIL
)

echo.
echo Read the lines above carefully. Anything reported as NOT applied needs
echo service-stop.bat followed by service-start.bat before it takes effect.
goto :END

:FORWARD
echo AWGSocks is installed in %SVCDIR%
echo Running the script there instead of the copy in %~dp0
echo.
set "AWGSOCKS_FORWARDED=1"
call "%SVCDIR%%~nx0"
endlocal & exit /b %errorlevel%

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
