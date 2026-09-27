@echo off
setlocal EnableExtensions EnableDelayedExpansion
title AWGSocks - remove service and data
cd /d "%~dp0"

set "SVCDIR="
for /f "tokens=1,2,*" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\AWGSocks" /v ImagePath 2^>nul') do if /i "%%A"=="ImagePath" call :SERVICE_DIR %%C
if not defined AWGSOCKS_FORWARDED if defined SVCDIR if /i not "%SVCDIR%"=="%~dp0" if exist "%SVCDIR%%~nx0" goto :FORWARD

set "RC=0"
set "AWGSOCKS=%~dp0awgsocks.exe"

net session >nul 2>&1
if errorlevel 1 goto :ELEVATE

sc query AWGSocks >nul 2>&1
if errorlevel 1 if not exist "%ProgramData%\AWGSocks" (
    echo The AWGSocks service is not installed.
    goto :END
)

if not exist "%AWGSOCKS%" if defined SVCDIR set "AWGSOCKS=%SVCDIR%awgsocks.exe"
if not exist "%AWGSOCKS%" (
    echo awgsocks.exe was not found next to this script.
    echo Expected: %AWGSOCKS%
    goto :FAIL
)

echo This will stop the service, remove it, and delete everything under
echo     %ProgramData%\AWGSocks
echo.
echo That directory holds the copy of your AmneziaWG configuration that the
echo service runs from, its settings and its log.
echo.
echo Your own .conf file, wherever you keep it, is NOT touched.
if defined SVCDIR if exist "!SVCDIR!service-install.bat" (
    echo Neither is the program in !SVCDIR!, so its
    echo service-install.bat can set the service up again.
)
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
if defined SVCDIR if exist "!SVCDIR!service-install.bat" echo To remove the program too, delete !SVCDIR!
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
