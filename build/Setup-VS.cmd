@echo off
set "WGWC_DEV_CMD="
set "WGWC_VSWHERE="
if not defined VSCMD_VER goto discover
if not "%VSCMD_VER:~0,3%"=="17." goto discover
if not defined VSINSTALLDIR goto discover
if exist "%VSINSTALLDIR%\Common7\Tools\VsDevCmd.bat" set "WGWC_DEV_CMD=%VSINSTALLDIR%\Common7\Tools\VsDevCmd.bat"
if defined WGWC_DEV_CMD goto initialize

:discover
set "WGWC_VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%WGWC_VSWHERE%" goto missing
for /f "usebackq delims=" %%I in (`call "%WGWC_VSWHERE%" -latest -products * -version "[17.0,18.0)" -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "WGWC_DEV_CMD=%%I\Common7\Tools\VsDevCmd.bat"
if not defined WGWC_DEV_CMD goto missing
if not exist "%WGWC_DEV_CMD%" goto missing

:initialize
call "%WGWC_DEV_CMD%" -no_logo -arch=x64 -host_arch=x64
if errorlevel 1 goto failed
set "WGWC_DEV_CMD="
set "WGWC_VSWHERE="
exit /b 0

:missing
>&2 echo Visual Studio 2022 or Build Tools 2022 with the C++ x64 tools and Windows SDK is required.
set "WGWC_DEV_CMD="
set "WGWC_VSWHERE="
exit /b 1

:failed
>&2 echo Failed to initialize the Visual Studio x64 developer environment.
set "WGWC_DEV_CMD="
set "WGWC_VSWHERE="
exit /b 1
