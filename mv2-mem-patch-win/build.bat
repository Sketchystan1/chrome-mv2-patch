@echo off
rem Build the mv2-mem-patch version.dll proxy for one or more architectures.
rem
rem   build.bat [x64|x86|arm64|all]      (default: all)
rem
rem Fetches the Detours source on first use (curl, built into Windows 10 1803+),
rem then compiles out\<arch>\version.dll. A version.dll proxy is loaded INTO
rem chrome.exe, so it must match chrome.exe's architecture: place the DLL from
rem out\<arch>\ next to the matching chrome.exe, together with signatures.json.
rem
rem An architecture whose MSVC target toolchain is not installed is skipped with
rem a clear note (install "C++ ARM64 build tools" for arm64, etc.).
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

set "WHAT=%~1"
if not defined WHAT set "WHAT=all"

rem ---- Detours source (fetch only what is missing; folds in get-detours) -----
set "SRC=detours\src"
set "REF=main"
set "BASE=https://raw.githubusercontent.com/microsoft/Detours/%REF%"
set "NEED=detours.h detours.cpp disasm.cpp image.cpp modules.cpp disolx86.cpp disolx64.cpp disolarm64.cpp"
if not exist "%SRC%" mkdir "%SRC%"
set "MISSING="
for %%F in (%NEED%) do if not exist "%SRC%\%%F" set "MISSING=1"
if not exist "detours\LICENSE" set "MISSING=1"
if defined MISSING (
  where curl >nul 2>nul || ( echo curl not found - cannot fetch Detours source. & exit /b 1 )
  echo fetching Detours source from %REF% ...
  for %%F in (%NEED%) do (
    if not exist "%SRC%\%%F" (
      curl -fsSL -o "%SRC%\%%F" "%BASE%/src/%%F" || ( echo download failed: %%F & exit /b 1 )
    )
  )
  if not exist "detours\LICENSE" (
    curl -fsSL -o "detours\LICENSE" "%BASE%/LICENSE" || ( echo download failed: LICENSE & exit /b 1 )
  )
  echo done: %SRC% ready.
)

rem ---- Locate Visual Studio (robust to how the shell exports env vars) -------
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=C:\Program Files\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo Visual Studio Installer not found. Install Visual Studio with the
  echo "Desktop development with C++" workload.
  exit /b 1
)
set "VSDIR="
for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%I"
if not defined VSDIR ( echo Visual Studio C++ tools not found. & exit /b 1 )
set "VCVARS=%VSDIR%\VC\Auxiliary\Build\vcvarsall.bat"

rem ---- Build the requested architecture(s) ----------------------------------
set "BUILT="
set "FAILED="
if /i "%WHAT%"=="all" (
  call :one x64   x64        _AMD64_ X64   disolx64   && set "BUILT=!BUILT! x64"   || set "FAILED=!FAILED! x64"
  call :one x86   x64_x86    _X86_   X86   disolx86   && set "BUILT=!BUILT! x86"   || set "FAILED=!FAILED! x86"
  call :one arm64 x64_arm64  _ARM64_ ARM64 disolarm64 && set "BUILT=!BUILT! arm64" || set "FAILED=!FAILED! arm64"
) else if /i "%WHAT%"=="x64" (
  call :one x64   x64        _AMD64_ X64   disolx64   && set "BUILT=!BUILT! x64"   || set "FAILED=!FAILED! x64"
) else if /i "%WHAT%"=="x86" (
  call :one x86   x64_x86    _X86_   X86   disolx86   && set "BUILT=!BUILT! x86"   || set "FAILED=!FAILED! x86"
) else if /i "%WHAT%"=="arm64" (
  call :one arm64 x64_arm64  _ARM64_ ARM64 disolarm64 && set "BUILT=!BUILT! arm64" || set "FAILED=!FAILED! arm64"
) else (
  echo unknown target "%WHAT%" - use x64, x86, arm64, or all.
  exit /b 1
)

echo.
if defined BUILT   echo Built:            !BUILT!
if defined FAILED  echo Skipped/failed:  !FAILED!   ^(that target's MSVC toolchain may not be installed^)
if not defined BUILT ( echo Nothing was built. & exit /b 1 )
echo Place out\^<arch^>\version.dll next to the matching chrome.exe, with signatures.json.
exit /b 0

rem ===========================================================================
rem :one <arch> <vcvars-arg> <detours-define> <link-machine> <disol-file>
rem Builds one architecture in its own environment. Returns 1 (skip) if the
rem target toolchain is not installed, or on a compile/link failure.
rem ===========================================================================
:one
setlocal EnableExtensions
set "ARCH=%~1"
set "VCARG=%~2"
set "DDEF=%~3"
set "MACH=%~4"
set "DISOL=%~5"
echo.
echo === %ARCH% ===
call "%VCVARS%" %VCARG% >nul 2>nul
if errorlevel 1 ( echo   [skip] %ARCH%: "vcvarsall %VCARG%" failed - toolchain not installed. & endlocal & exit /b 1 )
rem vcvarsall returns success even when the requested TARGET compiler is missing
rem (it just leaves the host compiler on PATH). Verify the real cross-compiler
rem for this target exists, so we never compile arm64 headers with the x64 cl.
if not exist "%VCToolsInstallDir%bin\Host%VSCMD_ARG_HOST_ARCH%\%VSCMD_ARG_TGT_ARCH%\cl.exe" (
  echo   [skip] %ARCH%: the %MACH% cross-compiler is not installed.
  echo          Add "MSVC ... C++ %MACH% build tools" in the Visual Studio Installer.
  endlocal & exit /b 1
)
where cl >nul 2>nul || ( echo   [skip] %ARCH%: cl not found for %VCARG%. & endlocal & exit /b 1 )

set "OBJ=build\%ARCH%"
if not exist "%OBJ%" mkdir "%OBJ%"
if not exist "out\%ARCH%" mkdir "out\%ARCH%"

rem Detours: common sources plus this arch's opcode-length table. /FIintrin.h
rem force-includes the intrinsics first so the SDK headers find Interlocked*64
rem on ARM64 (harmless on x64/x86, which already pull it in).
cl /nologo /c /O2 /W3 /EHsc /FIintrin.h /DUNICODE /D_UNICODE /D%DDEF% /I detours\src ^
  /Fo%OBJ%\ detours\src\detours.cpp detours\src\disasm.cpp ^
  detours\src\image.cpp detours\src\modules.cpp detours\src\%DISOL%.cpp
if errorlevel 1 ( echo   [fail] %ARCH%: Detours compile failed. & endlocal & exit /b 1 )

rem The patch DLL.
cl /nologo /c /O2 /W3 /EHsc /std:c++20 /FIintrin.h /DUNICODE /D_UNICODE ^
  /I detours\src /Fo%OBJ%\mv2-mem-patch.obj mv2-mem-patch.cpp
if errorlevel 1 ( echo   [fail] %ARCH%: patch compile failed. & endlocal & exit /b 1 )

link /nologo /DLL /OUT:out\%ARCH%\version.dll /IMPLIB:%OBJ%\version.lib ^
  /DYNAMICBASE /MANIFEST:NO /MACHINE:%MACH% kernel32.lib user32.lib winhttp.lib ^
  %OBJ%\detours.obj %OBJ%\disasm.obj %OBJ%\image.obj %OBJ%\modules.obj ^
  %OBJ%\%DISOL%.obj %OBJ%\mv2-mem-patch.obj
if errorlevel 1 ( echo   [fail] %ARCH%: link failed. & endlocal & exit /b 1 )

echo   [ok] out\%ARCH%\version.dll
endlocal
exit /b 0
