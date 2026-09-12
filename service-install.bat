@echo off
setlocal EnableExtensions EnableDelayedExpansion
title AWGSocks - install service
cd /d "%~dp0"

set "RC=0"
set "AWGSOCKS=%~dp0awgsocks.exe"
set "SOCKS=127.0.0.1:10808"
set "PICKED=%TEMP%\awgsocks-selected.conf"

net session >nul 2>&1
if errorlevel 1 goto :ELEVATE

if not exist "%AWGSOCKS%" (
    echo awgsocks.exe was not found next to this script.
	echo.
    echo Expected: %AWGSOCKS%
    goto :FAIL
)

rem --- Locate the AmneziaWG configuration -------------------------------------
rem A single .conf next to this script is used as is. Anything else opens a
rem file picker.

set "CONF="
set "COUNT=0"
for %%F in (*.conf) do (
    set /a COUNT+=1
    set "FOUND=%%~fF"
)
if !COUNT! EQU 1 set "CONF=!FOUND!"
if !COUNT! GTR 1 (
    echo Several .conf files sit next to this script, so it cannot choose
    echo for you:
    echo.
    for %%F in (*.conf) do echo     %%~nxF
)

if not defined CONF (
    if !COUNT! EQU 0 echo No AmneziaWG .conf file was found next to this script.
	echo.
    echo Opening a file picker...
    echo.
    call :PICK_CONF
)

if not defined CONF (
    echo No configuration was selected, so nothing was installed.
    echo.
    echo Put your .conf file in this folder next to awgsocks.exe, or run the
    echo script again and pick it from the dialog.
    goto :FAIL
)
if not exist "!CONF!" (
    echo This file does not exist: !CONF!
    goto :FAIL
)

echo Configuration : !CONF!
echo SOCKS5        : %SOCKS%
echo.

rem --- Validate before touching the service control manager -------------------
echo Validating the configuration...
"%AWGSOCKS%" check --config "!CONF!"
if errorlevel 1 (
    echo.
    echo The configuration was rejected. Nothing was installed.
    goto :FAIL
)
echo.

rem --- Replace any previous installation --------------------------------------
sc query AWGSocks >nul 2>&1
if not errorlevel 1 (
    echo An older AWGSocks service is present, removing it first...
    "%AWGSOCKS%" uninstall >nul 2>&1
    echo.
)

echo Installing the service...
"%AWGSOCKS%" install --config "!CONF!" --socks %SOCKS% --start
if errorlevel 1 (
    echo.
    echo Installation failed.
    goto :FAIL
)

rem --- Wait for the tunnel, then prove the proxy actually answers --------------
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
"%AWGSOCKS%" status

echo.
if defined READY (
    echo The SOCKS5 proxy is accepting connections on %SOCKS%
	echo.
    echo Point your browser or torrent client at it. Enable remote DNS.
) else (
    echo The service is installed but %SOCKS% did not answer yet.
	echo.
    echo Run service-status.bat in a moment to see why.
)

echo.
echo Your own .conf file was left where it is. The service runs from a
echo protected copy under C:\ProgramData\AWGSocks.
echo.
echo Windows routing, the default gateway and system DNS were not touched.
goto :END

rem --- Subroutines ------------------------------------------------------------

rem This script elevates itself, and Windows refuses drag and drop onto an
rem elevated window (User Interface Privilege Isolation), so it cannot ask you
rem to drop a file into its console. Open a real file picker instead.
rem
rem The picker copies the chosen file to a path this script composed itself
rem rather than handing back the path as text. Reading a path back from a file
rem would decode it with the console code page and corrupt anything holding
rem non ASCII characters, which is common enough in a user profile path.
:PICK_CONF
set "CONF="
if exist "%PICKED%" del "%PICKED%" >nul 2>&1
set "PICKDIR=%~dp0"
rem If the official AmneziaVPN client is installed, its configurations live in a
rem known place. Start the picker there, since that is where most people already
rem keep the file they want.
if exist "%ProgramFiles%\AmneziaVPN\conf" set "PICKDIR=%ProgramFiles%\AmneziaVPN\conf"
rem ...unless this folder is where the configurations actually are.
if exist "%~dp0*.conf" set "PICKDIR=%~dp0"
powershell -NoProfile -STA -Command ^
  "Add-Type -AssemblyName System.Windows.Forms;" ^
  "$d = New-Object System.Windows.Forms.OpenFileDialog;" ^
  "$d.Title = 'Select your AmneziaWG .conf file';" ^
  "$d.Filter = 'AmneziaWG configuration (*.conf)|*.conf|All files (*.*)|*.*';" ^
  "$d.InitialDirectory = $env:PICKDIR;" ^
  "if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {" ^
  "  Copy-Item -LiteralPath $d.FileName -Destination $env:PICKED -Force;" ^
  "  Write-Host ('Selected: ' + $d.FileName) }"
if exist "%PICKED%" set "CONF=%PICKED%"
exit /b 0

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
rem The file picker leaves a copy of the configuration, private key included,
rem in the temporary directory. The service already has its own copy under
rem ProgramData by now, so remove this one on the way out whatever happened.
if exist "%PICKED%" del "%PICKED%" >nul 2>&1
echo.
echo Press any key to close...
pause >nul
endlocal & exit /b %RC%
