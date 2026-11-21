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
echo 1. 启动手机独立守护（拔线后可用，异常时仅停止 Claude）
echo 2. 查看手机独立守护状态
echo 3. 停止手机独立守护
echo 4. 打开手机系统 VPN 设置
echo 5. USB 监测，异常时仅在电脑提醒
echo 6. USB 监测，异常时请求停止手机 Claude
echo 7. 退出
choice /c 1234567 /n
if errorlevel 7 exit /b 0
if errorlevel 6 goto stopmode
if errorlevel 5 goto watch
if errorlevel 4 goto settings
if errorlevel 3 goto devicestop
if errorlevel 2 goto devicestatus
"%pyexe%" -B device_guard.py start
goto done
:devicestatus
"%pyexe%" -B device_guard.py status
goto done
:devicestop
"%pyexe%" -B device_guard.py stop
goto done
:settings
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
