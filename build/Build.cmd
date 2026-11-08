@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "WGWC_ORIGINAL_CODEPAGE="
for /f "tokens=2 delims=:" %%C in ('chcp') do for /f "tokens=*" %%D in ("%%C") do set "WGWC_ORIGINAL_CODEPAGE=%%D"
if not defined WGWC_ORIGINAL_CODEPAGE exit /b 1
chcp 65001 >nul
if not "%errorlevel%"=="0" exit /b %errorlevel%

call :build %*
set "WGWC_EXIT_CODE=%errorlevel%"
chcp %WGWC_ORIGINAL_CODEPAGE% >nul
exit /b %WGWC_EXIT_CODE%

:build

set "CONFIG="
for %%C in (ReleaseMT Release Debug) do if /i "%~1"=="%%C" set "CONFIG=%%C"
if "%~1"=="" set "CONFIG=ReleaseMT"
if not defined CONFIG goto usage
if not "%~2"=="" goto usage

call "%~dp0Setup-VS.cmd"
if not "%errorlevel%"=="0" exit /b %errorlevel%

for %%I in ("%~dp0..") do set "WGWC_SOURCE_DIR=%%~fI"
for %%I in ("%VSINSTALLDIR%\.") do set "WGWC_VS_INSTANCE=%%~fI"
set "WGWC_BUILD_DIR=%WGWC_SOURCE_DIR%\.build\cmake"
if exist "%WGWC_BUILD_DIR%\CMakeCache.txt" call :check_cache
if not "%errorlevel%"=="0" exit /b %errorlevel%

set "WGWC_CMAKE="
set "WGWC_CMAKE_VERSION="
for /f "delims=" %%I in ('where.exe cmake.exe 2^>nul') do if not defined WGWC_CMAKE call :try_cmake "%%I"
if not defined WGWC_CMAKE call :try_cmake "%WGWC_VS_INSTANCE%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if not defined WGWC_CMAKE goto missing_cmake

echo CMake: "%WGWC_CMAKE%" ^(version %WGWC_CMAKE_VERSION%^)
"%WGWC_CMAKE%" -S "%WGWC_SOURCE_DIR%" -B "%WGWC_BUILD_DIR%" -G "Visual Studio 17 2022" -A x64 -T v143 "-DCMAKE_GENERATOR_INSTANCE:PATH=%WGWC_VS_INSTANCE%"
if not "%errorlevel%"=="0" exit /b %errorlevel%
"%WGWC_CMAKE%" --build "%WGWC_BUILD_DIR%" --config "%CONFIG%" --parallel 2
if not "%errorlevel%"=="0" exit /b %errorlevel%
echo Build complete: "%WGWC_BUILD_DIR%\bin\%CONFIG%"
exit /b 0

:try_cmake
if not exist "%~1" exit /b 0
set "WGWC_CANDIDATE_VERSION=unavailable"
"%~1" --version >nul 2>&1
if not "%errorlevel%"=="0" goto reject_cmake
for /f "tokens=1,2,3" %%A in ('call "%~1" --version 2^>nul') do if "%%A %%B"=="cmake version" set "WGWC_CANDIDATE_VERSION=%%C"
set "WGWC_CMAKE_MAJOR="
set "WGWC_CMAKE_MINOR="
for /f "tokens=1,2 delims=." %%A in ("%WGWC_CANDIDATE_VERSION%") do (
    set "WGWC_CMAKE_MAJOR=%%A"
    set "WGWC_CMAKE_MINOR=%%B"
)
if not defined WGWC_CMAKE_MAJOR goto reject_cmake
if not defined WGWC_CMAKE_MINOR goto reject_cmake
for /f "delims=0123456789" %%A in ("%WGWC_CMAKE_MAJOR%%WGWC_CMAKE_MINOR%") do goto reject_cmake
if %WGWC_CMAKE_MAJOR% LSS 3 goto reject_cmake
if %WGWC_CMAKE_MAJOR% EQU 3 if %WGWC_CMAKE_MINOR% LSS 21 goto reject_cmake
set "WGWC_CMAKE=%~1"
set "WGWC_CMAKE_VERSION=%WGWC_CANDIDATE_VERSION%"
exit /b 0

:reject_cmake
>&2 echo Skipping CMake: "%~1" ^(version %WGWC_CANDIDATE_VERSION%; requires 3.21+^).
exit /b 0

:check_cache
set "WGWC_CACHE_SOURCE="
set "WGWC_CACHE_GENERATOR="
set "WGWC_CACHE_PLATFORM="
set "WGWC_CACHE_TOOLSET="
set "WGWC_CACHE_INSTANCE="
for /f "usebackq tokens=1,* delims==" %%A in ("%WGWC_BUILD_DIR%\CMakeCache.txt") do (
    for /f "tokens=1 delims=:" %%K in ("%%A") do (
        if "%%K"=="CMAKE_HOME_DIRECTORY" set "WGWC_CACHE_SOURCE=%%B"
        if "%%K"=="CMAKE_GENERATOR" set "WGWC_CACHE_GENERATOR=%%B"
        if "%%K"=="CMAKE_GENERATOR_PLATFORM" set "WGWC_CACHE_PLATFORM=%%B"
        if "%%K"=="CMAKE_GENERATOR_TOOLSET" set "WGWC_CACHE_TOOLSET=%%B"
        if "%%K"=="CMAKE_GENERATOR_INSTANCE" set "WGWC_CACHE_INSTANCE=%%B"
    )
)
if defined WGWC_CACHE_SOURCE set "WGWC_CACHE_SOURCE=%WGWC_CACHE_SOURCE:/=\%"
if defined WGWC_CACHE_INSTANCE set "WGWC_CACHE_INSTANCE=%WGWC_CACHE_INSTANCE:/=\%"
if defined WGWC_CACHE_SOURCE for %%I in ("%WGWC_CACHE_SOURCE%\.") do set "WGWC_CACHE_SOURCE=%%~fI"
if defined WGWC_CACHE_INSTANCE for %%I in ("%WGWC_CACHE_INSTANCE%\.") do set "WGWC_CACHE_INSTANCE=%%~fI"
set "WGWC_CACHE_REASON=source directory"
if /i not "%WGWC_CACHE_SOURCE%"=="%WGWC_SOURCE_DIR%" goto incompatible_cache
set "WGWC_CACHE_REASON=generator"
if not "%WGWC_CACHE_GENERATOR%"=="Visual Studio 17 2022" goto incompatible_cache
set "WGWC_CACHE_REASON=target architecture"
if /i not "%WGWC_CACHE_PLATFORM%"=="x64" goto incompatible_cache
set "WGWC_CACHE_REASON=toolset"
if /i not "%WGWC_CACHE_TOOLSET%"=="v143" goto incompatible_cache
set "WGWC_CACHE_REASON=Visual Studio instance"
if /i not "%WGWC_CACHE_INSTANCE%"=="%WGWC_VS_INSTANCE%" goto incompatible_cache
exit /b 0

:incompatible_cache
>&2 echo Existing CMake cache is incompatible: %WGWC_CACHE_REASON%.
>&2 echo Cache: "%WGWC_BUILD_DIR%\CMakeCache.txt"
>&2 echo Cached source: "%WGWC_CACHE_SOURCE%"
>&2 echo Cached generator: "%WGWC_CACHE_GENERATOR%" / "%WGWC_CACHE_PLATFORM%" / "%WGWC_CACHE_TOOLSET%"
>&2 echo Cached VS: "%WGWC_CACHE_INSTANCE%"
>&2 echo Current source: "%WGWC_SOURCE_DIR%"
>&2 echo Current VS: "%WGWC_VS_INSTANCE%"
>&2 echo Expected generator: Visual Studio 17 2022 / x64 / v143.
>&2 echo Close any build processes, then rename or remove only "%WGWC_BUILD_DIR%" and rerun this script.
>&2 echo No cached files have been changed or deleted.
exit /b 1

:usage
>&2 echo Usage: build\Build.cmd [ReleaseMT^|Release^|Debug]
exit /b 2

:missing_cmake
>&2 echo No usable CMake 3.21 or newer was found on PATH or in the selected Visual Studio instance.
>&2 echo Install CMake on PATH or the Visual Studio C++ CMake tools component.
exit /b 1
