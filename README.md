# Chrome MV2 Extension Patcher

Re-enables Manifest V2 extensions in Chrome.  
Windows: `version.dll` that Chrome loads at startup and patches MV2 switch in memory. DRM works.  
See [`mv2-reversing.md`](mv2-reversing.md) for details.

## Windows
### Chrome 152-159 x64, x86, ARM

[Compact Windows DLL without signatures.json](mv2-mem-patch-win/README.md):
build this branch for x64, x86 or ARM64 with `build.bat` or Visual Studio.
Local builds also include [`secur32.dll`](mv2-mem-patch-win/README.md#secur32dll-automatic-patcher-beside-the-executable),
placed beside `chrome.exe` or `msedge.exe`.
The local x64 build enables [off-store extensions](mv2-mem-patch-win/README.md#off-store-extensions)
automatically on recognized versions, with no extra launch flag.
It also supports [installing downloaded CRX files](mv2-mem-patch-win/README.md#installing-downloaded-crx-files)
without Web Store publisher proof on recognized download-gate layouts.
Edge x64 supports the same CRX installation and source-block fix on recognized
layouts; see [Edge instructions](mv2-mem-patch-win/README.md#installing-downloaded-crx-files).

The installer below downloads the published table-based release. Chrome 159
requires `version.dll` **1.16.0 or later** and the updated signatures.
Run the installer again to replace an older DLL; `update` refreshes signatures only.

Run in terminal:

```powershell
powershell "irm github.com/Sketchystan1/chrome-mv2-patch/raw/master/chrome-mv2.ps1|iex"
```

<details> 
    <summary>Manual install</summary>
    Copy version.dll next to chrome.exe.  
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
