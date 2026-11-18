@echo off
rem Install the local MV2 proxy or clean up an older installation without downloading files.
rem Keep delayed expansion off so browser paths containing exclamation marks survive.
setlocal EnableExtensions DisableDelayedExpansion
rem Keep the outer console alive even if the worker aborts before reaching its exit handler.
if defined MV2_CONSOLE_CHILD goto :run
set "MV2_CONSOLE_CHILD=1"
rem CALL treats any help switch as its own, so handle help before forwarding arguments.
:help_scan
if "%~1"=="" goto :start_worker
if /i "%~1"=="/?" goto :run
shift /1
goto :help_scan

:start_worker
call "%~f0" %*
set "MV2_EXIT=%errorlevel%"
if not "%MV2_EXIT%"=="0" pause
exit /b %MV2_EXIT%

:run
rem Clear inherited installer variables so a previous run cannot supply a cleanup target.
for /f "delims==" %%V in ('set MV2_ 2^>nul') do set "%%V="
rem Obtain the ANSI escape character from cmd's prompt for colored messages.
for /f %%E in ('echo prompt $E ^| cmd.exe /d') do set "MV2_ESC=%%E"
set "MV2_INFO=%MV2_ESC%[96m"
set "MV2_WARN=%MV2_ESC%[93m"
set "MV2_ERROR=%MV2_ESC%[91m"
set "MV2_OK=%MV2_ESC%[92m"
set "MV2_RESET=%MV2_ESC%[0m"
set "MV2_COMMAND=install"
set "MV2_QUIET=0"
set "MV2_CODE=1"
set "MV2_COUNT=0"
set "MV2_SOURCE=%~dp0secur32.dll"
set "MV2_BATCH=%~f0"
set "MV2_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
rem A 32-bit cmd must query 64-bit browsers through the native PowerShell host.
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "MV2_POWERSHELL=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
rem Mouse text selection can suspend console output until Enter or Esc is pressed.
call :configure_console
rem This extension ID is used only to check or remove old uBlock registration.
set "MV2_UBO_ID=fkgkibajhfbepljeaefdnfnegdcjomkh"
rem Older installers may have written entries to both native and 32-bit registry views.
set "MV2_VIEWS=32"
if defined ProgramW6432 set "MV2_VIEWS=64 32"
if /i not "%PROCESSOR_ARCHITECTURE%"=="x86" set "MV2_VIEWS=64 32"
set "MV2_MENU=1"
set "MV2_ADMIN=1"
rem Check elevation before showing browser menus or allowing any changes.
fltmc.exe >nul 2>&1
if errorlevel 1 set "MV2_ADMIN=0"

:arguments
rem Explicit arguments bypass the action menu. Quiet mode disables interactive prompts.
if "%~1"=="" goto :select_target
set "MV2_MENU="
if /i "%~1"=="/?" (call :usage & exit /b 0)
if /i "%~1"=="install" (set "MV2_COMMAND=install" & shift /1 & goto :arguments)
if /i "%~1"=="uninstall" (set "MV2_COMMAND=uninstall" & shift /1 & goto :arguments)
if /i "%~1"=="check" (set "MV2_COMMAND=check" & shift /1 & goto :arguments)
if /i "%~1"=="cleanup" (set "MV2_COMMAND=cleanup" & shift /1 & goto :arguments)
if /i "%~1"=="-Quiet" (set "MV2_QUIET=1" & shift /1 & goto :arguments)
if /i "%~1"=="-Search" (set "MV2_SEARCH=1" & shift /1 & goto :arguments)
set "MV2_ARGUMENT=%~1"
if "%MV2_ARGUMENT:~0,1%"=="-" goto :bad_arguments
if defined MV2_PATH goto :bad_arguments
set "MV2_PATH=%~1"
shift /1
goto :arguments

:bad_arguments
echo %MV2_ERROR%Invalid arguments.%MV2_RESET%
call :usage
goto :finish

:select_target
rem Quiet mode can select a browser automatically only when discovery finds one installation.
if "%MV2_ADMIN%"=="0" (
  echo %MV2_WARN%[WARNING] Not running as administrator.%MV2_RESET%
  echo %MV2_WARN%Right-click this batch file and select "Run as administrator".%MV2_RESET%
  goto :finish
)
if "%MV2_COMMAND%"=="cleanup" (echo %MV2_INFO%Chrome / Chromium / Edge legacy cleanup%MV2_RESET%) else echo %MV2_INFO%Chrome / Chromium / Edge MV2 installer%MV2_RESET%
call :discover
if defined MV2_SEARCH call :search_browsers
if errorlevel 1 goto :finish
if defined MV2_PATH goto :resolve_target
if "%MV2_COMMAND%"=="cleanup" goto :cleanup_old
if "%MV2_COUNT%"=="0" if "%MV2_QUIET%"=="1" goto :custom_path
:browser_menu
call :show_browsers
if "%MV2_QUIET%"=="1" (
  if not "%MV2_COUNT%"=="1" (
    echo %MV2_ERROR%Specify a browser path when more than one installation is found.%MV2_RESET%
    goto :finish
  )
  set "MV2_SELECTED=1"
  goto :load_target
)
set /a MV2_SEARCH_OPTION=MV2_COUNT+1 >nul
echo %MV2_INFO%[%MV2_SEARCH_OPTION%] Scan for Custom Browser Paths%MV2_RESET%
echo %MV2_INFO%[0] Custom path%MV2_RESET%
:choose_browser
rem Numbered entries can have multiple digits; other input is treated as a pasted path.
set "MV2_SELECTED="
set /p "MV2_SELECTED=Select a number or paste a browser path (blank to quit): "
if not defined MV2_SELECTED (set "MV2_CODE=0" & goto :finish)
set MV2_SELECTED | findstr.exe /r /x /c:"MV2_SELECTED=[0-9][0-9]*" >nul
if errorlevel 1 goto :pasted_path
if "%MV2_SELECTED%"=="0" goto :custom_path
if "%MV2_SELECTED%"=="%MV2_SEARCH_OPTION%" goto :search_drives
for /l %%N in (1,1,%MV2_COUNT%) do if "%MV2_SELECTED%"=="%%N" goto :load_target
goto :bad_selection

:search_drives
call :search_browsers
if errorlevel 1 goto :finish
goto :browser_menu

:pasted_path
rem Strip pasted quotes before expanding input so shell syntax stays inside the quoted path.
set "MV2_PATH=%MV2_SELECTED:"=%"
if exist "%MV2_PATH%" goto :resolve_target

:bad_selection
echo %MV2_ERROR%Enter a listed number or an existing browser path.%MV2_RESET%
goto :choose_browser

:load_target
call :load_item
set "MV2_PATH=%MV2_APP%"
goto :resolve_target

:load_item
for %%F in (APP NAME EXE REG) do (
  for /f "tokens=1,* delims==" %%A in ('set MV2_ITEM_%%F_%MV2_SELECTED% 2^>nul') do (
    if /i "%%A"=="MV2_ITEM_%%F_%MV2_SELECTED%" set "MV2_%%F=%%B"
  )
)
exit /b 0

:custom_path
if "%MV2_QUIET%"=="1" (
  echo %MV2_ERROR%No browser found. Specify its Application folder or executable path.%MV2_RESET%
  goto :finish
)
set "MV2_PATH="
set /p "MV2_PATH=Browser folder, executable or DLL path (blank to quit): "
if not defined MV2_PATH (set "MV2_CODE=0" & goto :finish)

:resolve_target
rem Accept an Application folder or a browser binary and resolve the executable's folder.
set "MV2_PATH=%MV2_PATH:"=%"
if not exist "%MV2_PATH%" (
  echo %MV2_ERROR%Browser path does not exist.%MV2_RESET%
  goto :finish
)
for %%I in ("%MV2_PATH%") do (
  set "MV2_APP=%%~fI"
  if /i "%%~nxI"=="chrome.exe" set "MV2_EXE=chrome.exe"
  if /i "%%~nxI"=="chrome.dll" set "MV2_EXE=chrome.exe"
  if /i "%%~nxI"=="msedge.exe" set "MV2_EXE=msedge.exe"
  if /i "%%~nxI"=="msedge.dll" set "MV2_EXE=msedge.exe"
)
if not exist "%MV2_APP%\" for %%I in ("%MV2_APP%") do set "MV2_APP=%%~dpI."
for %%I in ("%MV2_APP%") do set "MV2_APP=%%~fI"
if not defined MV2_EXE (
  set "MV2_EXE=chrome.exe"
  if exist "%MV2_APP%\msedge.exe" set "MV2_EXE=msedge.exe"
  if exist "%MV2_APP%\..\msedge.exe" set "MV2_EXE=msedge.exe"
)
if not exist "%MV2_APP%\%MV2_EXE%" for %%I in ("%MV2_APP%\..") do set "MV2_APP=%%~fI"
if not exist "%MV2_APP%\%MV2_EXE%" (
  echo %MV2_ERROR%No chrome.exe or msedge.exe found beside or above that path.%MV2_RESET%
  goto :finish
)
rem Keep registry operations scoped to the selected browser family.
set "MV2_REG=Google\Chrome"
if /i "%MV2_EXE%"=="msedge.exe" (
  set "MV2_REG=Microsoft\Edge"
  if not defined MV2_NAME set "MV2_NAME=Edge"
) else if not defined MV2_NAME set "MV2_NAME=Chrome"
if /i "%MV2_EXE%"=="chrome.exe" for %%I in ("%MV2_APP%" "%MV2_APP%\..") do if /i "%%~nxI"=="Chromium" set "MV2_NAME=Chromium"
if /i "%MV2_NAME%"=="Chromium" set "MV2_REG=Chromium"
rem Include a supplied portable installation in cleanup even if discovery did not find it.
set "MV2_CANDIDATE=%MV2_APP%"
call :record_install
echo %MV2_INFO%Selected: %MV2_NAME%%MV2_RESET%
if not defined MV2_MENU goto :dispatch
rem Print colored labels separately because choice displays ANSI codes literally in its prompt.
echo %MV2_INFO%[1] Install  [2] Uninstall  [0] Quit%MV2_RESET%
choice.exe /c 120 /n /m "Select action: "
if not errorlevel 1 (set "MV2_CODE=0" & goto :finish)
if errorlevel 3 (set "MV2_CODE=0" & goto :finish)
if errorlevel 2 (set "MV2_COMMAND=uninstall" & goto :dispatch)

:dispatch
rem Status checks stay read-only. Other actions validate cleanup paths before making changes.
if "%MV2_COMMAND%"=="check" goto :check
call :cleanup_check
if errorlevel 1 goto :finish
if "%MV2_COMMAND%"=="cleanup" goto :cleanup_old
if "%MV2_COMMAND%"=="uninstall" goto :uninstall
rem Verify DLL identity and architecture before closing the browser or replacing files.
if not exist "%MV2_SOURCE%" (
  echo %MV2_ERROR%Missing secur32.dll beside install.bat.%MV2_RESET%
  goto :finish
)
rem Let cmd open Unicode paths that findstr cannot pass as filenames.
findstr.exe /m /l /c:"[mv2patch" <"%MV2_SOURCE%" >nul 2>&1
if errorlevel 1 (
  echo %MV2_ERROR%The adjacent secur32.dll is not a recognized MV2 patcher.%MV2_RESET%
  goto :finish
)
call :make_work
if errorlevel 1 goto :finish
set "MV2_PROBE=%MV2_SOURCE%"
call :architecture
if errorlevel 1 (echo %MV2_ERROR%Invalid secur32.dll PE header.%MV2_RESET% & goto :finish)
set "MV2_SOURCE_ARCH=%MV2_ARCH%"
set "MV2_PROBE=%MV2_APP%\%MV2_EXE%"
call :architecture
if errorlevel 1 (echo %MV2_ERROR%Cannot read the browser PE architecture.%MV2_RESET% & goto :finish)
if not "%MV2_ARCH%"=="%MV2_SOURCE_ARCH%" (
  echo %MV2_ERROR%DLL architecture %MV2_SOURCE_ARCH% does not match browser architecture %MV2_ARCH%.%MV2_RESET%
  goto :finish
)
if exist "%MV2_APP%\secur32.dll" (
  findstr.exe /m /l /c:"[mv2patch" <"%MV2_APP%\secur32.dll" >nul 2>&1
  if errorlevel 1 (echo %MV2_ERROR%Refusing to overwrite an unrelated secur32.dll.%MV2_RESET% & goto :finish)
)
rem Skip replacement when the installed DLL matches the local DLL.
set "MV2_INSTALL_NEEDED=1"
if exist "%MV2_APP%\secur32.dll" (
  fc.exe /b "%MV2_SOURCE%" "%MV2_APP%\secur32.dll" >nul 2>&1
  if not errorlevel 1 set "MV2_INSTALL_NEEDED="
)
if not defined MV2_INSTALL_NEEDED goto :install_cleanup
call :close_browser
if errorlevel 1 goto :finish
rem Verify a staged copy before replacing the installed proxy.
set "MV2_NEW=%MV2_APP%\secur32.dll.mv2-%RANDOM%-%RANDOM%.tmp"
if exist "%MV2_NEW%" (echo %MV2_ERROR%Temporary target already exists.%MV2_RESET% & goto :finish)
set "MV2_STAGE=%MV2_NEW%"
copy /b /y "%MV2_SOURCE%" "%MV2_STAGE%" >nul 2>&1
if errorlevel 1 (echo %MV2_ERROR%DLL copy failed.%MV2_RESET% & goto :finish)
fc.exe /b "%MV2_SOURCE%" "%MV2_STAGE%" >nul 2>&1
if errorlevel 1 (echo %MV2_ERROR%DLL copy verification failed.%MV2_RESET% & goto :finish)

:install_cleanup
rem Clean every detected installation before committing the verified DLL to the selected browser.
call :cleanup_all
if errorlevel 1 goto :finish
if not defined MV2_INSTALL_NEEDED (
  echo %MV2_OK%%MV2_NAME% is already installed.%MV2_RESET%
  set "MV2_CODE=0"
  goto :finish
)
call :browser_running
if errorlevel 2 (echo %MV2_ERROR%Cannot inspect running browser processes.%MV2_RESET% & goto :finish)
if not errorlevel 1 (echo %MV2_ERROR%The browser restarted during installation. Run the batch again.%MV2_RESET% & goto :finish)
move /y "%MV2_STAGE%" "%MV2_APP%\secur32.dll" >nul 2>&1
if errorlevel 1 (echo %MV2_ERROR%DLL replacement failed.%MV2_RESET% & goto :finish)
set "MV2_STAGE="
echo %MV2_OK%Installed secur32.dll (%MV2_SOURCE_ARCH%).%MV2_RESET%
set "MV2_CODE=0"
goto :finish

:uninstall
rem Preserve unrelated DLLs even when their filename matches the proxy.
if exist "%MV2_APP%\secur32.dll" (
  findstr.exe /m /l /c:"[mv2patch" <"%MV2_APP%\secur32.dll" >nul 2>&1
  if errorlevel 1 (echo %MV2_ERROR%Refusing to delete an unrelated secur32.dll.%MV2_RESET% & goto :finish)
)
rem Leave the browser running when no proxy or old installer data needs removal.
if not exist "%MV2_APP%\secur32.dll" if not defined MV2_CLEANUP_NEEDED call :probe_registry
if not exist "%MV2_APP%\secur32.dll" if not defined MV2_CLEANUP_NEEDED (
  echo %MV2_OK%Nothing to uninstall.%MV2_RESET%
  set "MV2_CODE=0"
  goto :finish
)
call :close_browser
if errorlevel 1 goto :finish
if exist "%MV2_APP%\secur32.dll" del /f /q "%MV2_APP%\secur32.dll" >nul 2>&1
if exist "%MV2_APP%\secur32.dll" (echo %MV2_ERROR%DLL removal failed.%MV2_RESET% & goto :finish)
call :cleanup_legacy
if errorlevel 1 goto :finish
echo %MV2_OK%Uninstall complete.%MV2_RESET%
set "MV2_CODE=0"
goto :finish

:cleanup_old
rem Cleanup mode does not need a source DLL and preserves the current secur32 proxy.
call :cleanup_all
if errorlevel 1 goto :finish
set "MV2_CODE=0"
goto :finish

:check
set "MV2_PROBE=%MV2_APP%\secur32.dll"
if not exist "%MV2_PROBE%" (echo %MV2_WARN%secur32.dll is not installed.%MV2_RESET% & goto :finish)
findstr.exe /m /l /c:"[mv2patch" <"%MV2_PROBE%" >nul 2>&1
if errorlevel 1 (echo %MV2_ERROR%The installed secur32.dll is unrelated to this project.%MV2_RESET% & goto :finish)
call :make_work
if errorlevel 1 goto :finish
call :architecture
if errorlevel 1 (echo %MV2_ERROR%Invalid installed DLL PE header.%MV2_RESET% & goto :finish)
echo %MV2_OK%secur32.dll is installed (%MV2_ARCH%).%MV2_RESET%
set "MV2_UBO_FOUND="
for %%V in (%MV2_VIEWS%) do (
  reg.exe query "HKLM\Software\%MV2_REG%\Extensions\%MV2_UBO_ID%" /reg:%%V >nul 2>&1
  if not errorlevel 1 set "MV2_UBO_FOUND=1"
)
if defined MV2_UBO_FOUND (echo %MV2_INFO%uBlock Origin is registered.%MV2_RESET%) else echo %MV2_INFO%uBlock Origin is not registered.%MV2_RESET%
set "MV2_CODE=0"
goto :finish

:discover
rem Search each channel across all roots so browser groups stay together in the numbered list.
for %%S in (
  "Google\Chrome|Chrome Stable|chrome.exe|Google\Chrome"
  "Google\Chrome Beta|Chrome Beta|chrome.exe|Google\Chrome"
  "Google\Chrome Dev|Chrome Dev|chrome.exe|Google\Chrome"
  "Google\Chrome SxS|Chrome Canary|chrome.exe|Google\Chrome"
  "Chromium|Chromium|chrome.exe|Chromium"
  "Microsoft\Edge|Edge Stable|msedge.exe|Microsoft\Edge"
  "Microsoft\Edge Beta|Edge Beta|msedge.exe|Microsoft\Edge"
  "Microsoft\Edge Dev|Edge Dev|msedge.exe|Microsoft\Edge"
  "Microsoft\Edge SxS|Edge Canary|msedge.exe|Microsoft\Edge"
) do for /f "tokens=1-4 delims=|" %%A in ("%%~S") do (
  for %%R in ("%ProgramW6432%" "%ProgramFiles%" "%ProgramFiles(x86)%" "%LOCALAPPDATA%") do if not "%%~R"=="" (
    set "MV2_CANDIDATE=%%~R\%%A\Application"
    set "MV2_NAME=%%B"
    set "MV2_EXE=%%C"
    set "MV2_REG=%%D"
    call :record_install
  )
)
set "MV2_NAME="
set "MV2_EXE="
set "MV2_REG="
exit /b 0

:record_install
rem Environment roots can overlap, so list each browser folder only once.
if not exist "%MV2_CANDIDATE%\%MV2_EXE%" exit /b 0
for /f "tokens=1,* delims==" %%A in ('set MV2_ITEM_APP_ 2^>nul') do if /i "%%B"=="%MV2_CANDIDATE%" exit /b 0
set /a MV2_COUNT+=1 >nul
set "MV2_ITEM_APP_%MV2_COUNT%=%MV2_CANDIDATE%"
set "MV2_ITEM_NAME_%MV2_COUNT%=%MV2_NAME%"
set "MV2_ITEM_EXE_%MV2_COUNT%=%MV2_EXE%"
set "MV2_ITEM_REG_%MV2_COUNT%=%MV2_REG%"
exit /b 0

:search_browsers
if not exist "%MV2_POWERSHELL%" (echo %MV2_ERROR%Windows PowerShell is unavailable. Cannot search local drives.%MV2_RESET% & exit /b 1)
call :make_work
if errorlevel 1 exit /b 1
set "MV2_SEARCH_FILE=%MV2_WORK%\browsers.txt"
set "MV2_SEARCH_BEFORE=%MV2_COUNT%"
echo %MV2_INFO%Searching local drives for chrome.exe and msedge.exe...%MV2_RESET%
call :search_powershell
if errorlevel 1 (echo %MV2_ERROR%Browser search failed.%MV2_RESET% & exit /b 1)
rem Read UTF-8 paths without consuming pending menu replies.
if not defined MV2_CODE_PAGE for /f "tokens=2 delims=:" %%C in ('chcp ^<nul') do set "MV2_CODE_PAGE=%%C"
chcp 65001 <nul >nul
for /f "usebackq delims=" %%P in ("%MV2_SEARCH_FILE%") do (
  set "MV2_CANDIDATE=%%P"
  call :record_search
)
set "MV2_NAME="
set "MV2_EXE="
set "MV2_REG="
set /a MV2_FOUND=MV2_COUNT-MV2_SEARCH_BEFORE >nul
echo %MV2_INFO%Found %MV2_FOUND% additional browser installation(s).%MV2_RESET%
exit /b 0

:record_search
for %%I in ("%MV2_CANDIDATE%") do (
  set "MV2_EXE=%%~nxI"
  set "MV2_CANDIDATE=%%~dpI."
)
for %%I in ("%MV2_CANDIDATE%") do set "MV2_CANDIDATE=%%~fI"
set "MV2_NAME=Chrome"
set "MV2_REG=Google\Chrome"
for %%I in ("%MV2_CANDIDATE%" "%MV2_CANDIDATE%\..") do if /i "%%~nxI"=="Chromium" set "MV2_NAME=Chromium"
if "%MV2_NAME%"=="Chromium" set "MV2_REG=Chromium"
if /i "%MV2_EXE%"=="msedge.exe" (set "MV2_NAME=Edge" & set "MV2_REG=Microsoft\Edge")
set "MV2_COUNT_BEFORE=%MV2_COUNT%"
call :record_install
if not "%MV2_COUNT%"=="%MV2_COUNT_BEFORE%" set "MV2_ITEM_SEARCH_%MV2_COUNT%=1"
exit /b 0

:show_browsers
setlocal
for /l %%N in (1,1,%MV2_COUNT%) do (
  set "MV2_SELECTED=%%N"
  call :show_browser
)
endlocal
exit /b 0

:show_browser
call :load_item
set "MV2_STATE="
if exist "%MV2_APP%\secur32.dll" (
  findstr.exe /m /l /c:"[mv2patch" <"%MV2_APP%\secur32.dll" >nul 2>&1
  if not errorlevel 1 set "MV2_STATE= - patch installed"
)
if defined MV2_ITEM_SEARCH_%MV2_SELECTED% (
  echo %MV2_INFO%[%MV2_SELECTED%] %MV2_NAME%%MV2_STATE% - "%MV2_APP%"%MV2_RESET%
) else echo %MV2_INFO%[%MV2_SELECTED%] %MV2_NAME%%MV2_STATE%%MV2_RESET%
exit /b 0

:make_work
if defined MV2_WORK exit /b 0
set "MV2_NEW=%TEMP%\mv2-install-%RANDOM%-%RANDOM%"
if exist "%MV2_NEW%" (echo %MV2_ERROR%Temporary directory already exists.%MV2_RESET% & exit /b 1)
md "%MV2_NEW%" >nul 2>&1
if errorlevel 1 (echo %MV2_ERROR%Cannot create temporary directory.%MV2_RESET% & exit /b 1)
set "MV2_WORK=%MV2_NEW%"
exit /b 0

:architecture
rem Use the PE header's machine type to distinguish x86, x64 and ARM64 without a scripting runtime.
set "MV2_ARCH="
certutil.exe -f -encodehex "%MV2_PROBE%" "%MV2_WORK%\image.hex" 4 >nul 2>&1
if errorlevel 1 exit /b 1
set "MV2_HEX_LINE="
set /p "MV2_HEX_LINE="<"%MV2_WORK%\image.hex"
if /i not "%MV2_HEX_LINE:~0,5%"=="4d 5a" exit /b 1
rem The little-endian e_lfanew field at byte 60 gives the actual PE header offset.
for /f "usebackq skip=3 tokens=13-16" %%A in ("%MV2_WORK%\image.hex") do (
  set "MV2_OFFSET_HEX=%%D%%C%%B%%A"
  goto :dos_header
)
exit /b 1

:dos_header
set /a "MV2_OFFSET=0x%MV2_OFFSET_HEX%" >nul 2>&1
if errorlevel 1 exit /b 1
if %MV2_OFFSET% lss 64 exit /b 1
for %%I in ("%MV2_PROBE%") do if %MV2_OFFSET% geq %%~zI exit /b 1
set /a "MV2_ROW=MV2_OFFSET/16, MV2_COLUMN=(MV2_OFFSET%%16)*2" >nul
rem Read two rows because the PE signature and machine type can cross a hex row boundary.
set "MV2_PE_BYTES="
set "MV2_SECOND_LINE="
for /f "usebackq skip=%MV2_ROW% delims=" %%L in ("%MV2_WORK%\image.hex") do (
  set "MV2_HEX_LINE=%%L"
  call :append_hex
  if errorlevel 1 goto :pe_header
)
exit /b 1

:append_hex
set "MV2_PE_BYTES=%MV2_PE_BYTES%%MV2_HEX_LINE: =%"
if defined MV2_SECOND_LINE exit /b 1
set "MV2_SECOND_LINE=1"
exit /b 0

:pe_header
rem Read at e_lfanew, not an arbitrary PE-looking byte sequence in the file.
call set "MV2_PE=%%MV2_PE_BYTES:~%MV2_COLUMN%,12%%"
if /i "%MV2_PE%"=="504500006486" set "MV2_ARCH=x64"
if /i "%MV2_PE%"=="504500004c01" set "MV2_ARCH=x86"
if /i "%MV2_PE%"=="5045000064aa" set "MV2_ARCH=arm64"
if not defined MV2_ARCH exit /b 1
exit /b 0

:close_browser
call :make_work
if errorlevel 1 exit /b 1
call :browser_running
if errorlevel 2 (echo %MV2_ERROR%Cannot inspect running browser processes.%MV2_RESET% & exit /b 1)
if errorlevel 1 exit /b 0
rem Prepare the restart task first so a failed setup leaves the browser running.
call :prepare_reopen
if errorlevel 1 exit /b 1
set "MV2_HAS_WINDOWS="
call :browser_running windows
if errorlevel 2 (echo %MV2_ERROR%Cannot inspect browser windows.%MV2_RESET% & exit /b 1)
if not errorlevel 1 set "MV2_HAS_WINDOWS=1"
echo %MV2_INFO%Closing %MV2_NAME%. The selected browser will reopen with its last session.%MV2_RESET%
set "MV2_REOPEN=1"
if not defined MV2_HAS_WINDOWS goto :close_background
call :browser_process close
rem Background mode can keep Edge alive after its last window saves and closes.
call :wait_closed 15 windows
if errorlevel 2 (echo %MV2_ERROR%Cannot inspect running browser processes.%MV2_RESET% & exit /b 1)
if not errorlevel 1 goto :close_background
echo %MV2_WARN%The browser did not exit. Force-closing remaining %MV2_NAME% processes.%MV2_RESET%
goto :force_browser

:close_background
if not defined MV2_HAS_WINDOWS goto :stop_background
rem Give session writes already in progress time to finish after the last window closes.
call :wait_closed 2
if errorlevel 2 (echo %MV2_ERROR%Cannot inspect running browser processes.%MV2_RESET% & exit /b 1)
if not errorlevel 1 exit /b 0

:stop_background
call :browser_running
if errorlevel 2 (echo %MV2_ERROR%Cannot inspect running browser processes.%MV2_RESET% & exit /b 1)
if errorlevel 1 exit /b 0
echo %MV2_INFO%Closing remaining %MV2_NAME% background processes.%MV2_RESET%

:force_browser
call :browser_process force
call :wait_closed 5 force
if errorlevel 1 (echo %MV2_ERROR%Could not close the browser. No changes were made.%MV2_RESET% & exit /b 1)
exit /b 0

:browser_running
rem Return zero when running, one when closed and two when process inspection fails.
if /i "%~1"=="windows" (call :browser_process windows & exit /b)
call :browser_process running
exit /b %errorlevel%

:configure_console
rem Prevent selection stalls without consuming keyboard or redirected input.
if not exist "%MV2_POWERSHELL%" exit /b 0
set "MV2_PROCESS_MODE=console"
call :powershell_script
exit /b 0

:browser_process
rem Pass paths as environment data, never interpolate them into PowerShell source.
set "MV2_PROCESS_MODE=%~1"
set "MV2_PROCESS_PATH=%MV2_APP%\%MV2_EXE%"
if not exist "%MV2_POWERSHELL%" (echo %MV2_ERROR%Windows PowerShell is unavailable. Cannot inspect the selected browser.%MV2_RESET% & exit /b 2)

:powershell_script
"%MV2_POWERSHELL%" -NoProfile -NonInteractive -Command "$source=[IO.File]::ReadAllText($env:MV2_BATCH); & ([scriptblock]::Create(($source -split '(?m)^# MV2_PROCESS_SCRIPT\r?$',2)[1]))" >nul 2>&1
exit /b %errorlevel%

:search_powershell
rem The search worker must not consume replies intended for the browser menu.
"%MV2_POWERSHELL%" -NoProfile -NonInteractive -Command "$source=[IO.File]::ReadAllText($env:MV2_BATCH); & ([scriptblock]::Create(($source -split '(?m)^# MV2_SEARCH_SCRIPT\r?$',2)[1]))" <nul
exit /b %errorlevel%

:wait_closed
for /l %%N in (1,1,%~1) do (
  call :browser_running %~2
  if errorlevel 2 exit /b 2
  if errorlevel 1 exit /b 0
  ping.exe -n 2 -w 1000 127.0.0.1 >nul 2>&1
  rem Repeat normal requests for multiple windows, or clear respawned background workers.
  if /i "%~2"=="windows" call :browser_process close
  if /i "%~2"=="force" call :browser_process force
)
call :browser_running %~2
if errorlevel 2 exit /b 2
if errorlevel 1 exit /b 0
exit /b 1

:prepare_reopen
set "MV2_TASK=chrome-mv2-reopen-%RANDOM%-%RANDOM%"
schtasks.exe /query /tn "%MV2_TASK%" >nul 2>&1
if not errorlevel 1 (echo %MV2_ERROR%Temporary restart task already exists.%MV2_RESET% & exit /b 1)
setlocal EnableDelayedExpansion
set "MV2_XML_APP=!MV2_APP:&=&amp;!"
set "MV2_XML_USER=!USERDOMAIN!\!USERNAME!"
set "MV2_XML_USER=!MV2_XML_USER:&=&amp;!"
set "MV2_REOPEN_XML=<?xml version='1.0' encoding='UTF-16'?><Task version='1.2' xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'>"
set "MV2_REOPEN_XML=!MV2_REOPEN_XML!<Principals><Principal id='BrowserUser'><UserId>!MV2_XML_USER!</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>"
set "MV2_REOPEN_XML=!MV2_REOPEN_XML!<Settings><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>"
rem Custom startup flags are not retained; restart the selected executable with its saved session.
set "MV2_REOPEN_XML=!MV2_REOPEN_XML!<Actions Context='BrowserUser'><Exec><Command>!MV2_XML_APP!\!MV2_EXE!</Command><Arguments>--restore-last-session</Arguments><WorkingDirectory>!MV2_XML_APP!</WorkingDirectory></Exec></Actions></Task>"
setlocal DisableDelayedExpansion
rem Task Scheduler requires the byte-order marker that cmd /u omits.
>"%MV2_WORK%\xml-bom.hex" echo ff fe
certutil.exe -f -decodehex "%MV2_WORK%\xml-bom.hex" "%MV2_WORK%\reopen.xml" 4 >nul 2>&1
if errorlevel 1 (
  endlocal
  endlocal
  echo %MV2_ERROR%Cannot prepare the browser restart XML.%MV2_RESET%
  exit /b 1
)
cmd.exe /d /u /v:on /c "echo(!MV2_REOPEN_XML!" >>"%MV2_WORK%\reopen.xml"
schtasks.exe /create /tn "%MV2_TASK%" /xml "%MV2_WORK%\reopen.xml" >nul 2>&1
if errorlevel 1 (
  endlocal
  endlocal
  echo %MV2_ERROR%Cannot prepare a browser restart. Check that the Task Scheduler service is running.%MV2_RESET%
  exit /b 1
)
endlocal
endlocal
set "MV2_TASK_READY=1"
exit /b 0

:reopen_browser
call :browser_running
if errorlevel 2 goto :reopen_failed
if not errorlevel 1 exit /b 0
echo %MV2_INFO%Reopening %MV2_NAME% with its last session...%MV2_RESET%
rem The temporary task starts with the user's normal token, not this batch's administrator token.
schtasks.exe /run /tn "%MV2_TASK%" >nul 2>&1
if errorlevel 1 goto :reopen_failed
for /l %%N in (1,1,15) do (
  call :browser_running
  if errorlevel 2 goto :reopen_failed
  if not errorlevel 1 (echo %MV2_OK%Browser reopened.%MV2_RESET% & exit /b 0)
  ping.exe -n 2 -w 1000 127.0.0.1 >nul 2>&1
)
:reopen_failed
echo %MV2_WARN%[WARNING] Could not reopen the browser. Start it manually; tabs are under History / Recently closed.%MV2_RESET%
exit /b 0

:cleanup_all
setlocal
set "MV2_TARGET_APP=%MV2_APP%"
set "MV2_AUTO_CLEANUP="
if /i "%MV2_COMMAND%"=="install" set "MV2_AUTO_CLEANUP=1"
set "MV2_COMMAND=cleanup"
rem Validate every folder before cleanup modifies files in any installation.
for /l %%N in (1,1,%MV2_COUNT%) do (
  set "MV2_SELECTED=%%N"
  call :load_item
  call :cleanup_check
  if errorlevel 1 goto :cleanup_all_failed
)
for /l %%N in (1,1,%MV2_COUNT%) do (
  set "MV2_SELECTED=%%N"
  call :cleanup_install
  if errorlevel 1 goto :cleanup_all_failed
)
endlocal & exit /b 0

:cleanup_all_failed
endlocal & exit /b 1

:cleanup_install
rem Each installation owns its own temporary files and exact restart executable.
setlocal
call :load_item
set "MV2_CLEANUP_NEEDED="
set "MV2_WORK="
set "MV2_REOPEN="
set "MV2_TASK_READY="
set "MV2_STAGE="
set "MV2_CODE=1"
call :cleanup_check
if errorlevel 1 goto :cleanup_install_finish
call :probe_registry
if not defined MV2_CLEANUP_NEEDED (set "MV2_CODE=0" & goto :cleanup_install_finish)
rem Automatic install cleanup preserves other running installations. Explicit cleanup may close them.
if defined MV2_AUTO_CLEANUP if /i not "%MV2_APP%"=="%MV2_TARGET_APP%" (
  call :browser_running
  if errorlevel 2 goto :cleanup_install_finish
  if not errorlevel 1 (
    echo %MV2_WARN%Skipping legacy cleanup for running %MV2_NAME%. Use cleanup to handle it explicitly.%MV2_RESET%
    set "MV2_CODE=0"
    goto :cleanup_install_finish
  )
)
call :close_browser
if errorlevel 1 goto :cleanup_install_finish
call :cleanup_legacy
if errorlevel 1 goto :cleanup_install_finish
set "MV2_CODE=0"

:cleanup_install_finish
call :finish_work
endlocal & exit /b %MV2_CODE%

:probe_registry
rem Channels share registry keys; only entries still present require cleanup.
for %%V in (%MV2_VIEWS%) do (
  reg.exe query "HKLM\Software\%MV2_REG%\Extensions\%MV2_UBO_ID%" /reg:%%V >nul 2>&1
  if not errorlevel 1 set "MV2_CLEANUP_NEEDED=1"
  if /i not "%MV2_COMMAND%"=="uninstall" if /i "%MV2_REG%"=="Google\Chrome" (
    reg.exe query "HKLM\Software\Policies\Google\Chrome" /reg:%%V >nul 2>&1
    if not errorlevel 1 set "MV2_CLEANUP_NEEDED=1"
  )
)
exit /b 0

:cleanup_check
set "MV2_LEGACY="
rem shortcut: legacy byte patches need a validated restore; never overwrite a browser from an unchecked backup.
if /i not "%MV2_COMMAND%"=="uninstall" if /i "%MV2_EXE%"=="chrome.exe" (
  dir /b /s /a-d "%MV2_APP%\chrome.dll.bak" 2>nul | findstr.exe . >nul
  if not errorlevel 1 (
    echo %MV2_ERROR%Legacy chrome.dll.bak found. Restore stock Chrome before cleanup.%MV2_RESET%
    exit /b 1
  )
)
rem Remove only this project's branded legacy proxy and preserve unrelated version DLLs.
if exist "%MV2_APP%\version.dll" (
  findstr.exe /m /l /c:"[mv2patch" <"%MV2_APP%\version.dll" >nul 2>&1
  if not errorlevel 1 (
    set "MV2_LEGACY=1"
    set "MV2_CLEANUP_NEEDED=1"
  )
)
if not defined LOCALAPPDATA (echo %MV2_ERROR%LOCALAPPDATA is not set.%MV2_RESET% & exit /b 1)
for %%F in ("%MV2_APP%\signatures.json" "%LOCALAPPDATA%\chrome-mv2-patch\signatures.json") do (
  if exist "%%~fF\" (echo %MV2_ERROR%%MV2_NAME%: a signature path is a directory. Cleanup stopped.%MV2_RESET% & exit /b 1)
  if exist "%%~fF" set "MV2_CLEANUP_NEEDED=1"
)
exit /b 0

:cleanup_legacy
rem Recheck processes in case the browser restarted after it was closed.
call :browser_running
if errorlevel 2 (echo %MV2_ERROR%Cannot inspect running browser processes.%MV2_RESET% & exit /b 1)
if not errorlevel 1 (
  echo %MV2_ERROR%The browser started again during cleanup. Run the batch again.%MV2_RESET%
  exit /b 1
)
if exist "%MV2_APP%\version.dll" (
  findstr.exe /m /l /c:"[mv2patch" <"%MV2_APP%\version.dll" >nul 2>&1
  if not errorlevel 1 (
    echo %MV2_WARN%%MV2_NAME%: removing the old version.dll proxy.%MV2_RESET%
    del /f /q "%MV2_APP%\version.dll" >nul 2>&1
    if exist "%MV2_APP%\version.dll" (echo %MV2_ERROR%Legacy proxy removal failed.%MV2_RESET% & exit /b 1)
  )
)
if /i not "%MV2_COMMAND%"=="uninstall" if /i "%MV2_REG%"=="Google\Chrome" (
  call :remove_policies
  if errorlevel 1 exit /b 1
)
call :remove_ubo
if errorlevel 1 exit /b 1
rem Delete only obsolete signature files and preserve the current autoscan cache.
for %%F in ("%MV2_APP%\signatures.json" "%LOCALAPPDATA%\chrome-mv2-patch\signatures.json") do (
  if exist "%%~fF\" (echo %MV2_ERROR%%MV2_NAME%: a signature path is a directory. Cleanup stopped.%MV2_RESET% & exit /b 1)
  if exist "%%~fF" del /f /q "%%~fF" >nul 2>&1
  if exist "%%~fF" (echo %MV2_ERROR%%MV2_NAME%: signature removal failed.%MV2_RESET% & exit /b 1)
)
echo %MV2_OK%%MV2_NAME%: legacy cleanup complete.%MV2_RESET%
exit /b 0

:remove_policies
rem This clears the entire machine Chrome policy key, including unrelated policies.
for %%V in (%MV2_VIEWS%) do (
  reg.exe query "HKLM\Software\Policies\Google\Chrome" /reg:%%V >nul 2>&1
  if not errorlevel 1 (
    reg.exe delete "HKLM\Software\Policies\Google\Chrome" /f /reg:%%V >nul 2>&1
    if errorlevel 1 (echo %MV2_ERROR%Chrome policy cleanup failed.%MV2_RESET% & exit /b 1)
  )
)
exit /b 0

:remove_ubo
rem Remove only the current browser's old extension registration. Never install uBlock.
for %%V in (%MV2_VIEWS%) do (
  reg.exe query "HKLM\Software\%MV2_REG%\Extensions\%MV2_UBO_ID%" /reg:%%V >nul 2>&1
  if not errorlevel 1 (
    reg.exe delete "HKLM\Software\%MV2_REG%\Extensions\%MV2_UBO_ID%" /f /reg:%%V >nul 2>&1
    if errorlevel 1 (echo %MV2_ERROR%uBlock Origin removal failed.%MV2_RESET% & exit /b 1)
  )
)
exit /b 0

:usage
echo %MV2_INFO%Usage: install.bat [install^|uninstall^|check^|cleanup] ["browser path"] [-Search] [-Quiet]%MV2_RESET%
echo %MV2_INFO%No arguments: select a browser and action. Use Run as administrator.%MV2_RESET%
echo %MV2_INFO%-Search: find browsers on all local drives before selecting a target.%MV2_RESET%
exit /b 0

:finish_work
rem Restore the browser and remove temporary files and tasks, including after a failure.
if defined MV2_STAGE if exist "%MV2_STAGE%" del /q "%MV2_STAGE%" >nul 2>&1
if defined MV2_REOPEN call :reopen_browser
if defined MV2_TASK_READY (
  schtasks.exe /delete /tn "%MV2_TASK%" /f >nul 2>&1
  if errorlevel 1 echo %MV2_WARN%[WARNING] Could not remove temporary restart task "%MV2_TASK%".%MV2_RESET%
)
if defined MV2_WORK (
  for %%F in (image.hex reopen.xml xml-bom.hex browsers.txt) do if exist "%MV2_WORK%\%%F" del /q "%MV2_WORK%\%%F" >nul 2>&1
  rd "%MV2_WORK%" >nul 2>&1
)
if defined MV2_CODE_PAGE chcp %MV2_CODE_PAGE% <nul >nul
exit /b 0

:finish
call :finish_work
if "%MV2_CODE%"=="0" if "%MV2_QUIET%"=="0" pause
exit /b %MV2_CODE%

# MV2_PROCESS_SCRIPT
# Adapted from Get-BrowserProcesses and CloseWindows in the legacy chrome-mv2.ps1.
# This section is read by Windows PowerShell; cmd exits before reaching it.
$ErrorActionPreference = 'Stop'
$live = @()
try {
    $mode = $env:MV2_PROCESS_MODE
    if ($mode -eq 'console') {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class Mv2ConsoleInput {
    [StructLayout(LayoutKind.Sequential)]
    struct ConsoleSelectionInfo {
        public uint Flags;
        public short AnchorX, AnchorY, Left, Top, Right, Bottom;
    }
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetConsoleMode(SafeFileHandle input, out uint mode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetConsoleMode(SafeFileHandle input, uint mode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetConsoleSelectionInfo(out ConsoleSelectionInfo selection);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll", SetLastError = true)]
    static extern bool PostMessageW(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
    public static void DisableQuickEdit() {
        // CONIN$ still addresses the attached console when stdin is a file or pipe.
        using (var input = CreateFileW("CONIN$", 0xc0000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
            if (input.IsInvalid) return; // No attached console in a background run.
            uint mode;
            if (!GetConsoleMode(input, out mode)) throw new Win32Exception();
            // ENABLE_EXTENDED_FLAGS is required when clearing ENABLE_QUICK_EDIT_MODE.
            if (!SetConsoleMode(input, (mode | 0x0080u) & ~0x0040u)) throw new Win32Exception();
            // Clearing QuickEdit does not release a selection started during helper startup.
            // Cancel only an active selection in our own window; never read or flush input.
            ConsoleSelectionInfo selection;
            if (GetConsoleSelectionInfo(out selection) && (selection.Flags & 0x0001u) != 0) {
                var window = GetConsoleWindow();
                if (window != IntPtr.Zero) {
                    if (!PostMessageW(window, 0x0100, new IntPtr(0x1b), new IntPtr(0x00010001))) throw new Win32Exception();
                    if (!PostMessageW(window, 0x0101, new IntPtr(0x1b), new IntPtr(unchecked((int)0xc0010001)))) throw new Win32Exception();
                }
            }
        }
    }
}
'@
        [Mv2ConsoleInput]::DisableQuickEdit()
        exit 0
    }
    if ($mode -notin 'running', 'windows', 'close', 'force') { exit 2 }
    $target = [IO.Path]::GetFullPath($env:MV2_PROCESS_PATH)
    $name = [IO.Path]::GetFileNameWithoutExtension($target)
    if ($name -notin 'chrome', 'msedge') { exit 2 }
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $candidates = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='$name.exe'")
    foreach ($candidate in $candidates) {
        $image = [string]$candidate.ExecutablePath
        if ($image -and [IO.Path]::GetFullPath($image) -ne $target) { continue }
        $process = $null
        try {
            $owner = Invoke-CimMethod -InputObject $candidate -MethodName GetOwnerSid
            if ($owner.ReturnValue -ne 0) { throw 'Cannot identify the process owner.' }
            if ($owner.Sid -ne $user) { continue }
            if (-not $image) { throw 'Cannot identify the browser executable.' }
            $process = Get-Process -Id $candidate.ProcessId
            # Pin the process object before checking its path; a recycled PID cannot
            # turn a later close or Kill into an operation on another installation.
            $null = $process.Handle
            if ($process.HasExited) { $process.Dispose(); continue }
            $path = $process.Path
            if (-not $path) { throw 'Cannot identify the browser executable.' }
            if ([IO.Path]::GetFullPath($path) -ne $target) { $process.Dispose(); continue }
            # Recheck the owner while this process handle pins its identity.
            $owner = Invoke-CimMethod -InputObject $candidate -MethodName GetOwnerSid
            if ($owner.ReturnValue -ne 0) { throw 'Cannot identify the process owner.' }
            if ($owner.Sid -eq $user) { $live += $process }
            else { $process.Dispose() }
        } catch {
            if ($process -and $process.HasExited) { $process.Dispose(); continue }
            if (-not $process -and -not [Diagnostics.Process]::GetProcessesByName($name).Where({ $_.Id -eq $candidate.ProcessId }).Count) { continue }
            throw
        }
    }
    if ($mode -eq 'running') {
        if ($live.Count) { exit 0 }
        exit 1
    }
    if ($mode -eq 'force') {
        foreach ($process in $live) {
            if (-not $process.HasExited) { $process.Kill() }
        }
        exit 0
    }
    if (-not $live.Count) {
        if ($mode -eq 'close') { exit 0 }
        exit 1
    }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class Mv2BrowserWindows {
    delegate bool EnumWindowsProc(IntPtr window, IntPtr parameter);
    [DllImport("user32.dll", SetLastError = true)]
    static extern bool EnumWindows(EnumWindowsProc callback, IntPtr parameter);
    [DllImport("user32.dll")]
    static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
    [DllImport("user32.dll")]
    static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")]
    static extern bool IsWindow(IntPtr window);
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool PostMessageW(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
    public static int Inspect(int[] processIds, bool close) {
        var selected = new HashSet<uint>();
        foreach (int id in processIds) selected.Add((uint)id);
        int count = 0;
        bool failed = false;
        if (!EnumWindows(delegate(IntPtr window, IntPtr parameter) {
            uint owner;
            GetWindowThreadProcessId(window, out owner);
            if (selected.Contains(owner) && IsWindowVisible(window)) {
                count++;
                if (close && !PostMessageW(window, 0x0010, IntPtr.Zero, IntPtr.Zero) && IsWindow(window)) failed = true;
            }
            return true;
        }, IntPtr.Zero)) throw new Win32Exception();
        if (failed) throw new Win32Exception();
        return count;
    }
}
'@
    $windows = [Mv2BrowserWindows]::Inspect([int[]]@($live | ForEach-Object { $_.Id }), $mode -eq 'close')
    if ($mode -eq 'close' -or $windows) { exit 0 }
    exit 1
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
} finally {
    foreach ($process in $live) { $process.Dispose() }
}

# MV2_SEARCH_SCRIPT
$ErrorActionPreference = 'Stop'
try {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
public static class Mv2BrowserSearch {
    [StructLayout(LayoutKind.Sequential)]
    struct MftEnumData {
        public ulong Start;
        public long Low, High;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct FileId {
        public uint Size, Type;
        public ulong Id, Padding;
    }
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(SafeFileHandle volume, uint code, ref MftEnumData input, uint inputSize, [Out] byte[] output, uint outputSize, out uint returned, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern SafeFileHandle OpenFileById(SafeFileHandle volume, ref FileId id, uint access, uint share, IntPtr security, uint flags);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint size, uint flags);

    static bool IsBrowser(string name) {
        return name.Equals("chrome.exe", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("msedge.exe", StringComparison.OrdinalIgnoreCase);
    }

    public static IEnumerable<ulong> BrowserIds(byte[] data, int count) {
        if (count < 8 || count > data.Length) throw new InvalidDataException("Invalid MFT buffer.");
        for (int offset = 8; offset < count;) {
            if (count - offset < 60) throw new InvalidDataException("Truncated MFT record.");
            uint length = BitConverter.ToUInt32(data, offset);
            if (length < 60 || length > count - offset || (length & 7) != 0 ||
                BitConverter.ToUInt16(data, offset + 4) != 2)
                throw new InvalidDataException("Unsupported MFT record.");
            int nameLength = BitConverter.ToUInt16(data, offset + 56);
            int nameOffset = BitConverter.ToUInt16(data, offset + 58);
            if (nameOffset < 60 || nameOffset > length || nameLength > length - nameOffset ||
                (nameLength & 1) != 0)
                throw new InvalidDataException("Invalid MFT filename.");
            uint attributes = BitConverter.ToUInt32(data, offset + 52);
            if ((attributes & 0x410) == 0 && nameLength == 20 &&
                IsBrowser(Encoding.Unicode.GetString(data, offset + nameOffset, nameLength)))
                yield return BitConverter.ToUInt64(data, offset + 8);
            offset += (int)length;
        }
    }

    // NTFS enumeration visits metadata once; resolve paths only for browser names.
    static List<string> Mft(string root) {
        var found = new List<string>();
        using (var volume = CreateFileW(@"\\.\" + root.Substring(0, 2), 0x80000000, 7, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
            if (volume.IsInvalid) throw new Win32Exception();
            var input = new MftEnumData { High = long.MaxValue };
            var data = new byte[1024 * 1024];
            var path = new StringBuilder(32768);
            while (true) {
                uint returned;
                if (!DeviceIoControl(volume, 0x000900b3, ref input, 24, data, (uint)data.Length, out returned, IntPtr.Zero)) {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 38) break; // ERROR_HANDLE_EOF ends MFT enumeration.
                    throw new Win32Exception(error);
                }
                foreach (ulong number in BrowserIds(data, checked((int)returned))) {
                    var id = new FileId { Size = 24, Id = number };
                    using (var file = OpenFileById(volume, ref id, 0, 7, IntPtr.Zero, 0x00200000)) {
                        if (file.IsInvalid) continue; // Deleted or inaccessible since enumeration.
                        uint size = GetFinalPathNameByHandleW(file, path, (uint)path.Capacity, 0);
                        if (size == 0 || size >= path.Capacity) continue;
                        string full = path.ToString();
                        if (full.StartsWith(@"\\?\", StringComparison.Ordinal)) full = full.Substring(4);
                        // shortcut: MFT returns one path per file ID; scan directories if hard-link aliases must all be listed.
                        if (full.StartsWith(root, StringComparison.OrdinalIgnoreCase) &&
                            IsBrowser(Path.GetFileName(full)) && File.Exists(full)) found.Add(full);
                    }
                }
                ulong next = BitConverter.ToUInt64(data, 0);
                if (next <= input.Start) throw new InvalidDataException("MFT enumeration did not advance.");
                input.Start = next;
            }
        }
        return found;
    }

    public static List<string> Folders(string root) {
        var found = new List<string>();
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count != 0) {
            string folder = pending.Pop();
            try {
                // One pass per directory; junctions can leave the drive or form cycles.
                foreach (var entry in new DirectoryInfo(folder).EnumerateFileSystemInfos()) {
                    if ((entry.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                    if ((entry.Attributes & FileAttributes.Directory) != 0) pending.Push(entry.FullName);
                    else if (IsBrowser(entry.Name)) found.Add(entry.FullName);
                }
            } catch (UnauthorizedAccessException) {
            } catch (IOException) {
            }
        }
        return found;
    }

    public static string[] Find(string[] roots) {
        var found = new ConcurrentBag<string>();
        Parallel.ForEach(roots, root => {
            Console.Error.WriteLine("Searching " + root);
            List<string> matches;
            try {
                matches = root.Equals(Path.GetPathRoot(root), StringComparison.OrdinalIgnoreCase) ? Mft(root) : Folders(root);
            } catch (Win32Exception) {
                Console.Error.WriteLine(root + ": fast search unavailable; searching folders.");
                matches = Folders(root);
            } catch (IOException) {
                Console.Error.WriteLine(root + ": fast search unavailable; searching folders.");
                matches = Folders(root);
            }
            foreach (string match in matches) found.Add(match);
        });
        return found.ToArray();
    }
}
'@
    $roots = @([IO.DriveInfo]::GetDrives() | Where-Object {
        $_.DriveType -in 'Fixed', 'Removable', 'Ram' -and $_.IsReady
    } | ForEach-Object { $_.Name })
    $found = [string[]]@([Mv2BrowserSearch]::Find([string[]]$roots) | Sort-Object -Unique)
    [IO.File]::WriteAllLines($env:MV2_SEARCH_FILE, $found, [Text.UTF8Encoding]::new($false))
    exit 0
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}

