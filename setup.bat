@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (set "PYTHON=python") else (set "PYTHON=py -3")
if not exist ".venv\Scripts\python.exe" %PYTHON% -m venv .venv
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed
if not exist config.json copy /y config.example.json config.json >nul
echo Setup complete. Edit config.json, then run start.bat.
pause
exit /b 0
:failed
echo Setup failed. Install Python 3.10+ from python.org and try again.
pause
exit /b 1
