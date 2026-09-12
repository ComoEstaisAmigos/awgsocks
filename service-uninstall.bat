@echo off
setlocal EnableExtensions EnableDelayedExpansion
title AWGSocks - remove service and data
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

echo This will stop the service, remove it, and delete everything under
echo     C:\ProgramData\AWGSocks
echo.
echo That directory holds the copy of your AmneziaWG configuration that the
echo service runs from, its settings and its log.
echo.
echo Your own .conf file, wherever you keep it, is NOT touched.
echo.

set "ANSWER="
set /p "ANSWER=Type y to continue, anything else to cancel: "
if /i not "!ANSWER!"=="y" (
    echo.
    echo Cancelled. Nothing was changed.
    goto :END
)

echo.
"%AWGSOCKS%" uninstall --purge
if errorlevel 1 (
    echo.
    echo Removal failed.
    goto :FAIL
)

echo.
echo Done. No Wintun adapter was ever created and no route was ever added,
echo so there is nothing else to undo.
echo.
echo To install it again, run service-install.bat with your .conf file.
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
