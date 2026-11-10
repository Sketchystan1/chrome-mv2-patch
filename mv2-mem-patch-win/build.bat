@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "MV2_ARCH=%~1"
if not defined MV2_ARCH set "MV2_ARCH=all"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (echo Visual Studio Installer is required. & exit /b 1)
set "MV2_VS="
for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "MV2_VS=%%I"
if not defined MV2_VS (echo MSVC tools are required. & exit /b 1)
if /I "%MV2_ARCH%"=="all" (
  for %%A in (x64 x86 arm64) do (
    call :build %%A
    if errorlevel 1 exit /b 1
  )
  exit /b 0
)
call :build "%MV2_ARCH%"
exit /b %errorlevel%

:build
setlocal
set "MV2_TARGET="
for %%A in (x64 x86 arm64) do if /I "%~1"=="%%A" set "MV2_TARGET=%%A"
if not defined MV2_TARGET (echo Usage: build.bat [x64^|x86^|arm64^|all] & exit /b 1)
set "MV2_ENV=x64_%MV2_TARGET%"
if "%MV2_TARGET%"=="x64" set "MV2_ENV=x64"
call "%MV2_VS%\VC\Auxiliary\Build\vcvarsall.bat" %MV2_ENV% >nul
if errorlevel 1 exit /b 1
rem vcvarsall can succeed while leaving the host compiler on PATH.
if not exist "%VCToolsInstallDir%bin\Hostx64\%MV2_TARGET%\cl.exe" (
  echo Install the MSVC C++ %MV2_TARGET% compiler tools.
  exit /b 1
)
set "PATH=%MV2_VS%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%MV2_VS%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%"
cmake --preset %MV2_TARGET%
if errorlevel 1 exit /b 1
cmake --build --preset %MV2_TARGET%
endlocal & exit /b %errorlevel%
