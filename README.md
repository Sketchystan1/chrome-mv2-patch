# Chrome MV2 Extension Patcher

Re-enables Manifest V2 extensions in Chrome by patching a few bytes. See [`mv2-reversing.md`](mv2-reversing.md) for details.

## Supported Versions

- ✅ Chrome 152-155
- ✅ Windows x64, x86
- ✅ Linux x64

### Should work. Please check.

- 🧪 Chromium
- 🧪 Windows ARM
- 🧪 Linux ARM
- 🧪 macOS ARM



## Usage

Run in Terminal:

### Windows

```powershell
powershell "irm github.com/Sketchystan1/chrome-mv2-patch/raw/master/chrome-mv2.ps1|iex"
```

### Linux, macOS

```bash
curl -sL github.com/Sketchystan1/chrome-mv2-patch/raw/master/chrome-mv2.sh | sudo bash
```

### Python option (any OS)

```bash
python3 chrome-mv2.py
```

## Testing

Install uBlock Original mv2 with auto update.
Powershell (admin):
```powershell
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v ExtensionSettings /t REG_SZ /d '{"fkgkibajhfbepljeaefdnfnegdcjomkh":{"installation_mode":"normal_installed","update_url":"https://github.com/gorhill/uBlock/raw/refs/heads/master/dist/chromium/update.xml"}}' /f
```


## Donate

USDT (TRC20): TDAr6Lu2sYtArJYAgUpyfuk6rKNvvyMA87  
USDC (Base): 0x762712dcC8e3E757Cf3FC077AeF0b4EDa8692b7B

## License

Released under the [MIT License](LICENSE).
