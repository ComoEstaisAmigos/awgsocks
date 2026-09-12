@echo off
setlocal EnableExtensions
title AWGSocks - edit settings
cd /d "%~dp0"

set "RC=0"
set "AWGSOCKS=%~dp0awgsocks.exe"
set "CONFIG=%ProgramData%\AWGSocks\config.json"

net session >nul 2>&1
if errorlevel 1 goto :ELEVATE

if not exist "%AWGSOCKS%" (
    echo awgsocks.exe was not found next to this script.
    echo Expected: %AWGSOCKS%
    goto :FAIL
)

if not exist "%CONFIG%" (
    echo The AWGSocks settings file does not exist, so the service is not installed.
    echo.
    echo Expected: %CONFIG%
    echo.
    echo Run service-install.bat first.
    goto :END
)

echo Opening the settings file. Close Notepad when you are done.
echo.
echo   %CONFIG%
echo.
echo Every setting is documented in docs/CONFIGURATION.md. The one that most
echo often needs changing is log_level, which accepts debug, info, warn or error.
echo.
start /wait notepad "%CONFIG%"

sc query AWGSocks | find "RUNNING" >nul 2>&1
if errorlevel 1 (
    echo.
    echo The service is not running, so there is nothing to apply to. Your changes
    echo are saved and take effect when it next starts.
    echo.
    echo Run service-start.bat to start it.
    goto :END
)

echo.
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
