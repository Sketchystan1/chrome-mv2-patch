# Chrome MV2 Extension Patcher

Re-enables Manifest V2 extensions in Chrome by patching a few bytes. See [`mv2-reversing.md`](mv2-reversing.md) for details.

## Supported Versions

- ✅ Chrome 151-155
- ✅ Windows x64, x86
- ✅ Linux x64

### Should work. Please check.

- 🧪 Chromium
- 🧪 Windows ARM
- 🧪 Linux ARM
- 🧪 macOS x64, ARM



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

Install [uBlock Origin](https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm) from the Chrome Web Store (available until end of August 2026).

Or load it unpacked: turn on Developer mode at `chrome://extensions`, click Load unpacked, and pick the `uBlock0.chromium` folder from a [uBlock Origin release](https://github.com/gorhill/uBlock/releases).

## Donate

USDT (TRC20): TDAr6Lu2sYtArJYAgUpyfuk6rKNvvyMA87  
USDC (Base): 0x762712dcC8e3E757Cf3FC077AeF0b4EDa8692b7B  
[Boosty](https://boosty.to/sketchystan1)

## License

Released under the [MIT License](LICENSE).
