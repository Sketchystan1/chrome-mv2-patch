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

1. Close Chrome.
2. Copy the matching `version.dll` next to `chrome.exe`.
3. Start Chrome.

It downloads its patch data on first launch (that start may pause a few seconds).
It survives Chrome updates and refreshes itself for new versions.

Remove: close Chrome, delete `version.dll`.

## Notes

- Optional config file at `%LOCALAPPDATA%\mv2-mem-patch\config.txt`:

  ```toml
  # where to get patch data — a URL (default, self-updating) or a local file path
  signatures = "https://github.com/Sketchystan1/chrome-mv2-patch/raw/master/signatures.json"

  # max wait for the first-launch download, in ms (default 8000)
  download_timeout_ms = 8000
  ```
- Debug: run **DebugView** and watch for `[mv2patch]` lines.
- Not Microsoft-signed, so strict enterprise/AV setups may block it.
