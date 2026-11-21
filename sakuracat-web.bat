@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0sakuracat-web.ps1" %*
if not errorlevel 1 exit /b 0
pause
exit /b 1
