# Chrome MV2 Extension Patcher

Re-enables Manifest V2 extensions in Chrome. On **Windows** it installs a small
`version.dll` that patches Chrome's MV2 switch *in memory* every launch —
`chrome.dll` on disk is never touched, so Widevine DRM keeps working. On Linux
and macOS it byte-patches the binary. See [`mv2-reversing.md`](mv2-reversing.md)
for details.

## Supported Versions

- ✅ Chrome 152-155
- ✅ Windows x64, x86
- ✅ Linux x64

### Should work. Please check.

- 🧪 Windows ARM
- 🧪 Linux ARM
- 🧪 macOS ARM



## Usage

Run in Terminal:

### Windows

```powershell
powershell "irm github.com/Sketchystan1/chrome-mv2-patch/raw/master/chrome-mv2.ps1|iex"
```

Installs `version.dll` and prompts to add uBlock Origin. Other commands:
`chrome-mv2.ps1 uninstall` (remove it), `chrome-mv2.ps1 update` (refresh
signatures), `chrome-mv2.ps1 check` (status). Add `-Ublock` to install uBO
without prompting.

### Linux, macOS

```bash
curl -sL github.com/Sketchystan1/chrome-mv2-patch/raw/master/chrome-mv2.sh | sudo bash
```

### Python option (any OS)

```bash
python3 chrome-mv2.py
```

## Testing

The Windows installer offers to add uBlock Origin (MV2). To force-install it by
hand off-store, elevated PowerShell (then restart Chrome):

```powershell
reg.exe add "HKLM\Software\Google\Chrome\Extensions\fkgkibajhfbepljeaefdnfnegdcjomkh" /v update_url /t REG_SZ /d "https://github.com/gorhill/uBlock/raw/refs/heads/master/dist/chromium/update.xml" /f
```


## Donate

USDT (TRC20): TDAr6Lu2sYtArJYAgUpyfuk6rKNvvyMA87  
USDC (Base): 0x762712dcC8e3E757Cf3FC077AeF0b4EDa8692b7B

## License

Released under the [MIT License](LICENSE).
