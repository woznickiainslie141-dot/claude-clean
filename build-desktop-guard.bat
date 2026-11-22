@echo off
setlocal
set "finder=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%finder%" for /f "usebackq delims=" %%i in (`"%finder%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "vsroot=%%i"
if not defined vsroot if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" set "vsroot=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools"
if not defined vsroot goto missing
call "%vsroot%\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 -no_logo
if errorlevel 1 exit /b 1
set "build=%TEMP%\ClaudeDesktopBuild-%RANDOM%-%RANDOM%"
mkdir "%build%" || exit /b 1
pushd "%build%" || exit /b 1
cl.exe /nologo /std:c++17 /EHsc /utf-8 /O2 /MT /W4 "%~dp0desktop-wfp.cpp" /Fe:desktop-wfp.exe
if errorlevel 1 goto failed
copy /y desktop-wfp.exe "%~dp0desktop-wfp.exe" >nul || goto failed
popd
exit /b 0
:failed
popd
exit /b 1
:missing
echo Install Visual Studio C++ Build Tools and a Windows SDK to build the desktop network guard.
exit /b 1
