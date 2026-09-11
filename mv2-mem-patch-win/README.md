# mv2-mem-patch-win

Turns Manifest V2 extensions back on in Windows Chrome.

A small `version.dll` that Chrome loads at startup and patches Chrome's MV2 switch
**in memory** — `chrome.dll` on disk is never touched, so DRM (Widevine) still works.
The fix re-applies every launch on its own. Works on x64, x86, and ARM64.

## Build

Needs Visual Studio 

```bat
build.bat
```

## Install

Easiest — the installer script downloads the matching `version.dll` + signatures,
drops them next to `chrome.exe`, clears leftover Chrome policies, and offers to
add uBlock Origin (elevates via UAC):

```powershell
powershell "irm github.com/Sketchystan1/chrome-mv2-patch/raw/master/chrome-mv2.ps1|iex"
```

`chrome-mv2.ps1 uninstall` removes it again; `chrome-mv2.ps1 update` refreshes
signatures.

Manual:

1. Close Chrome.
2. Copy the matching `version.dll` next to `chrome.exe`.
3. Start Chrome.

It downloads its patch data on first launch (that start may pause a few seconds).
It survives Chrome updates and refreshes itself for new versions.

Remove: close Chrome, delete `version.dll`.

## Install uBlock Origin (MV2)

The installer script prompts for this. To do it by hand, force-install uBO
off-store with an elevated PowerShell (writes `HKLM`), then restart Chrome:

```powershell
reg.exe add "HKLM\Software\Google\Chrome\Extensions\fkgkibajhfbepljeaefdnfnegdcjomkh" /v update_url /t REG_SZ /d "https://github.com/gorhill/uBlock/raw/refs/heads/master/dist/chromium/update.xml" /f 
```

## Notes

- Debug: run **DebugView** and watch for `[mv2patch]` lines.
- The signatures URL is a compile-time constant; the `%LOCALAPPDATA%\mv2-mem-patch\signatures.json` cache and self-heal are unchanged.
- Not Microsoft-signed, so strict enterprise/AV setups may block it.
