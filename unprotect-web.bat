@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0web-guard.ps1" -Mode Off
if errorlevel 1 goto failed
pause
exit /b 0
:failed
echo Could not confirm that the Chrome guard was removed.
pause
exit /b 1
