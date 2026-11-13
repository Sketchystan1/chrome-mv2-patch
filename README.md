# Chrome MV2 Extension Patcher

Re-enables Manifest V2 extensions in Chrome.
Windows: `secur32.dll` discovers and patches MV2 checks in memory at startup,
leaving the browser's disk image unchanged.
See [`mv2-reversing.md`](mv2-reversing.md) for details.

## Windows

### Chrome 152-159 x64, x86, ARM

[Compact Windows DLL without signatures.json](mv2-mem-patch-win/README.md):
build this branch for x64, x86 or ARM64 with `build.bat` or Visual Studio.
The only deployment DLL is [`secur32.dll`](mv2-mem-patch-win/README.md#secur32dll-automatic-patcher-beside-the-executable),
placed beside `chrome.exe` or `msedge.exe`.
The local x64 build enables [off-store extensions](mv2-mem-patch-win/README.md#off-store-extensions)
automatically on recognized versions, with no extra launch flag.
It also supports [installing downloaded CRX files](mv2-mem-patch-win/README.md#installing-downloaded-crx-files)
without Web Store publisher proof on recognized download-gate layouts.
Edge x64 supports the same CRX installation and source-block fix on recognized
layouts; see [Edge instructions](mv2-mem-patch-win/README.md#installing-downloaded-crx-files).

The installer downloads the published `secur32.dll` automatic-patcher release.
It requires a release archive named `secur32.dll-v<version>.zip`; this branch
must be published before the new archive is available. Run the installer again
to replace an older DLL. The native DLL needs no signature table; `update`
refreshes tables used by legacy restore/diagnostics and Unix patching.
[Performance research and measured results](mv2-mem-patch-win/PERFORMANCE.md).

Run in terminal:

```powershell
powershell "irm github.com/Sketchystan1/chrome-mv2-patch/raw/master/chrome-mv2.ps1|iex"
```

<details>
    <summary>Manual install</summary>
    Copy the matching secur32.dll next to chrome.exe (or msedge.exe).
    Install uBlock Origin Run in Terminal (admin).

    reg.exe add "HKLM\Software\Google\Chrome\Extensions\fkgkibajhfbepljeaefdnfnegdcjomkh" /v update_url /t REG_SZ /d "https://github.com/gorhill/uBlock/raw/refs/heads/master/dist/chromium/update.xml" /f /reg:32
</details>

## Linux, macOS

<details>
  <summary>Work in Progress</summary>
    Chrome 152-159 x64, ARM, macOS ARM (159 requires chrome-mv2.sh 1.16.0 or later)

    curl -sL github.com/Sketchystan1/chrome-mv2-patch/raw/master/chrome-mv2.sh | sudo bash
</details>


## Donate

USDT (TRC20): TDAr6Lu2sYtArJYAgUpyfuk6rKNvvyMA87
USDC (Base): 0x762712dcC8e3E757Cf3FC077AeF0b4EDa8692b7B

## License

Released under the [MIT License](LICENSE).

## Release history

<details>
<summary>Earlier releases and branch changes</summary>

### Unreleased

- Keep `secur32.dll` as the only Windows automatic-patcher carrier.
- Consolidate performance notes and result JSON into one performance record.
- Remove the optional MV3 `webRequestBlocking` permission patches from all tables.
- Add experimental Windows x64 MV2 discovery without a signature table or debug symbols.
- Speed up the Windows auto-patcher with native SIMD searches, parallel BLAKE3 identity checks, relocation filtering and a persistent protected plan cache. Raise the DLL/scanner size limit to 300,000 bytes.
- Balance hashing across an adaptive CPU budget, defer completed scan-view cleanup and reuse exact function trimming results; preserve full identity and loaded-code checks.
- Batch decision-page protection checks, use dynamic hash TLS to skip DLL thread notifications, and screen discovery candidates before function trimming.

### [1.16.0] - 2026-11-07

- Chrome 159 support.
- New instruction forms require an updated patcher.

### [1.15.0] - 2026-10-23

- Chrome 158 support.
- Fix Windows 157 x86.

### [1.14.0] - 2026-10-05

- Chrome 157 support.

### [1.13.0] - 2026-09-16

- Chrome 156 support.

### [1.12.0] - 2026-09-11

- chrome-mv2.ps1 switch from byte-patching to version.dll.

### [1.11.1] - 2026-09-11

- Fix 154.

### [1.11.0] - 2026-09-11

- Enable webRequestBlocking MV3.
- Drop Chromium support.

### [1.10.1] - 2026-09-09

- Fix macOS signatures.
- Fix Windows 154 signatures.

### [1.10.0] - 2026-09-07

- Drop 151 support, macos-x64.
- New ARM cbz based patch.

### [1.8.0] - 2026-09-05

- Enable webRequestBlocking MV3.
- Enable ExtensionSettings policy.

### [1.7.0] - 2026-09-02

- Chrome 155 support.
- Bug fixes.
- Python scripts updated.

### [1.6.1] - 2026-08-29

- New menu UI.

### [1.6.0] - 2026-08-23

- Chrome 154 support.

### [1.5.1] - 2026-08-21

- Windows script bug fixes.

### [1.5.0] - 2026-08-15

- Chromium support.

### [1.4.0] - 2026-08-14

- Linux ARM (arm64) support.

### [1.3.0] - 2026-08-13

- macOS x64, ARM support.
- Windows ARM support.

### [1.2.0] - 2026-08-12

- Linux support.
- Windows x86 support.
- Migrated from a binary to scripts.

### [1.1.0] - 2026-08-09

- Chrome 152 support.
- Windows x64 support.

### [1.0.0] - 2026-08-07

- First public release.
- Windows x64 support.
- Chrome 151 support.

</details>
