@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0web-guard.ps1" -Mode On
if errorlevel 1 goto failed
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0web-guard.ps1" -Mode Open
if errorlevel 1 goto failed
exit /b 0
:failed
echo Protected browser launch stopped. See the message above.
pause
exit /b 1
