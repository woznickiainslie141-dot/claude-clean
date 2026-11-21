@echo off
setlocal
cd /d "%~dp0"
set "PYTHONUTF8=1"
chcp 65001 >nul
set "pyexe=python.exe"
if exist ".venv\Scripts\python.exe" set "pyexe=.venv\Scripts\python.exe"
if not "%~1"=="" goto command
"%pyexe%" -B phone_guard.py check
echo.
echo 1. 打开手机系统 VPN 设置
echo 2. 监测手机出口，异常时在电脑提醒
echo 3. 监测并在异常时请求停止手机 Claude
echo 4. 退出
choice /c 1234 /n
if errorlevel 4 exit /b 0
if errorlevel 3 goto stopmode
if errorlevel 2 goto watch
"%pyexe%" -B phone_guard.py settings
goto done
:stopmode
"%pyexe%" -B phone_guard.py watch-stop
goto done
:watch
"%pyexe%" -B phone_guard.py watch
goto done
:command
"%pyexe%" -B phone_guard.py %*
exit /b %errorlevel%
:done
set "result=%errorlevel%"
pause
exit /b %result%
