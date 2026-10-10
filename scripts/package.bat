@echo off
rem Builds the release zip from committed source. The work is in package.ps1;
rem this wrapper exists so that the default PowerShell execution policy, which
rem refuses to run .ps1 files, does not stand in the way.
rem
rem   scripts\package.bat                 package HEAD into release\
rem   scripts\package.bat -Ref v1.2.3     package a tag
rem   scripts\package.bat -OutDir C:\out  write somewhere else

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0package.ps1" %*
exit /b %errorlevel%
