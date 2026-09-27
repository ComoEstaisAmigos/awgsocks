@echo off
setlocal EnableExtensions EnableDelayedExpansion
title AWGSocks - install service
cd /d "%~dp0"

set "RC=0"
set "AWGSOCKS=%~dp0awgsocks.exe"
set "PICKED=%TEMP%\awgsocks-selected.conf"

net session >nul 2>&1
if errorlevel 1 goto :ELEVATE

if not exist "%AWGSOCKS%" (
    echo awgsocks.exe was not found next to this script.
    echo.
    echo Expected: %AWGSOCKS%
    goto :FAIL
)

sc query AWGSocks >nul 2>&1
if not errorlevel 1 call :CONFIRM_REPLACE
if defined CANCELLED goto :END

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

call :READ_SOCKS
echo Configuration : !CONF!
echo SOCKS5        : !SOCKS!
echo.

echo Validating the configuration...
"%AWGSOCKS%" check --config "!CONF!"
if errorlevel 1 (
    echo.
    echo The configuration was rejected. Nothing was installed.
    goto :FAIL
)
echo.

set "REMOVE_FAILED="
sc query AWGSocks >nul 2>&1
if not errorlevel 1 call :REMOVE_OLD
if defined REMOVE_FAILED goto :FAIL

echo Installing the service...
"%AWGSOCKS%" install --config "!CONF!" --start
if errorlevel 1 (
    echo.
    echo Installation failed.
    goto :FAIL
)

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
"%AWGSOCKS%" status

echo.
if defined PAUSED (
    echo The service is installed, but the tunnel is paused: this configuration
    echo is connected on the Windows adapter !PAUSED!.
    echo.
    echo The proxy refuses requests until that adapter disconnects, and the
    echo tunnel resumes by itself when it does. To use both at once, give
    echo AWGSocks a configuration of its own.
) else if defined READY (
    echo The SOCKS5 proxy is accepting connections on %SOCKS%
    echo.
    echo Point your browser or torrent client at it. Enable remote DNS.
) else (
    echo The service is installed but %SOCKS% did not answer yet.
    echo.
    echo Run service-status.bat in a moment to see why.
)

echo.
echo Your own .conf file was left where it is. The service keeps its own copy,
echo closed to standard users, under %ProgramData%\AWGSocks.
set "SVCDIR="
for /f "tokens=1,2,*" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\AWGSocks" /v ImagePath 2^>nul') do if /i "%%A"=="ImagePath" call :SERVICE_DIR %%C
if defined SVCDIR (
    echo.
    echo AWGSocks and these scripts are installed in !SVCDIR!
    echo and the service runs from there as NT SERVICE\AWGSocks.
    if /i not "%~dp0"=="!SVCDIR!" echo The folder you installed from is no longer needed.
)
echo.
echo Windows routing, the default gateway and system DNS were not touched.
goto :END

:PICK_CONF
set "CONF="
if exist "%PICKED%" del "%PICKED%" >nul 2>&1
set "PICKDIR=%~dp0"
if exist "%ProgramFiles%\AmneziaVPN\conf" set "PICKDIR=%ProgramFiles%\AmneziaVPN\conf"
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

:CONFIRM_REPLACE
set "CANCELLED="
set "SVCDIR="
for /f "tokens=1,2,*" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\AWGSocks" /v ImagePath 2^>nul') do if /i "%%A"=="ImagePath" call :SERVICE_DIR %%C
set "OLDVER="
if defined SVCDIR if exist "%SVCDIR%awgsocks.exe" for /f "usebackq delims=" %%V in (`"%SVCDIR%awgsocks.exe" version`) do if not defined OLDVER set "OLDVER=%%V"
if not defined OLDVER set "OLDVER=unknown"
set "NEWVER="
for /f "usebackq delims=" %%V in (`"%AWGSOCKS%" version`) do if not defined NEWVER set "NEWVER=%%V"
set "STATE=installed but currently stopped"
sc query AWGSocks | find "RUNNING" >nul 2>&1
if not errorlevel 1 set "STATE=installed and currently running"
echo AWGSocks is already !STATE!.
echo.
echo   Installed      : !OLDVER!
echo   In this folder : !NEWVER!
echo.
echo Continuing replaces it with the .conf you choose next. Your settings in
echo config.json are kept.
echo.
echo To only start or stop it, or to change a setting, use service-start.bat,
echo service-stop.bat or service-config.bat instead.
echo.
set "ANSWER="
set /p "ANSWER=Type y to continue, anything else to cancel: "
echo.
if /i not "!ANSWER!"=="y" (
    echo Cancelled. Nothing was changed.
    set "CANCELLED=1"
)
exit /b 0

:REMOVE_OLD
echo Removing the installed service, keeping its settings...
echo.
"%AWGSOCKS%" uninstall --keep-settings
set "RESULT=!errorlevel!"
echo.
sc query AWGSocks >nul 2>&1
if errorlevel 1 exit /b 0
set "REMOVE_FAILED=1"
echo The installed service could not be removed, so nothing was installed.
echo.
if not "!RESULT!"=="0" (
    echo If the message above says -keep-settings is not defined, the
    echo awgsocks.exe in this folder is older than this script. Build or
    echo download it again so that both come from the same version.
) else (
    echo Windows may still be finishing the removal. Close the Services window
    echo if it is open, or restart, then run this script again.
)
exit /b 0

:READ_SOCKS
set "SOCKS=127.0.0.1:10808"
for /f "usebackq delims=" %%L in (`powershell -NoProfile -Command "try { (Get-Content -Raw -ErrorAction Stop -LiteralPath (Join-Path $env:ProgramData 'AWGSocks\config.json') | ConvertFrom-Json).socks5_listen } catch {}"`) do set "SOCKS=%%L"
exit /b 0

:SERVICE_DIR
set "SVCDIR=%~dp1"
exit /b 0

:PROBE
powershell -NoProfile -Command "try{$h,$p=$env:SOCKS -split ':(?=\d+$)';$c=New-Object Net.Sockets.TcpClient;$c.Connect($h.Trim('[',']'),[int]$p);$c.Close();exit 0}catch{exit 1}" >nul 2>&1
exit /b %errorlevel%

:READ_PAUSE
set "PAUSED="
for /f "usebackq delims=" %%P in (`powershell -NoProfile -Command "for ($i = 0; $i -lt 10; $i++) { try { $s = (& $env:AWGSOCKS status --json | Out-String) | ConvertFrom-Json; if ($s.tunnel) { if ($s.tunnel.paused_by) { $s.tunnel.paused_by }; exit } } catch {}; Start-Sleep -Milliseconds 300 }"`) do set "PAUSED=%%P"
exit /b 0

:ELEVATE
set "SELF=%~f0"
powershell -NoProfile -Command "Start-Process -FilePath $env:SELF -Verb RunAs"
endlocal
exit /b 0

:FAIL
set "RC=1"

:END
if exist "%PICKED%" del "%PICKED%" >nul 2>&1
echo.
echo Press any key to close...
pause >nul
endlocal & exit /b %RC%
