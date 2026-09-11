# Chrome MV2 Extension Patcher

Re-enables Manifest V2 extensions in Chrome.  
Windows: `version.dll` that Chrome loads at startup and patches MV2 switch in memory. DRM works.  
See [`mv2-reversing.md`](mv2-reversing.md) for details.

## Windows
### Chrome 152-155 x64, x86, ARM

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
    Chrome 152-155 x64, ARM, macOS ARM

    curl -sL github.com/Sketchystan1/chrome-mv2-patch/raw/master/chrome-mv2.sh | sudo bash
</details>


## Donate

USDT (TRC20): TDAr6Lu2sYtArJYAgUpyfuk6rKNvvyMA87  
USDC (Base): 0x762712dcC8e3E757Cf3FC077AeF0b4EDa8692b7B

## License

Released under the [MIT License](LICENSE).
