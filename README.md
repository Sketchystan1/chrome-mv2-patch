# Chrome MV2 Extension Patcher

Re-enables Manifest V2 extensions in Chrome by patching a few bytes. See [`mv2-reversing.md`](mv2-reversing.md) for details.

## Supported Versions

- ✅ Chrome 151-154
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

## Testing

Install [uBlock Origin](https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm) from the Chrome Web Store (available until end of August 2026).

Or load it unpacked: turn on Developer mode at `chrome://extensions`, click Load unpacked, and pick the `uBlock0.chromium` folder from a [uBlock Origin release](https://github.com/gorhill/uBlock/releases).

## Troubleshooting

**Windows: "running scripts is disabled on this system"** — the execution policy blocks `.ps1` files. Start it as `powershell -ExecutionPolicy Bypass -File .\chrome-mv2.ps1`, or use the `irm ... | iex` one-liner above.

**Windows: `MethodInvocationNotSupportedInConstrainedLanguage` / `ConversionSupportedOnlyToCoreTypes`** — a WDAC code-integrity policy has locked PowerShell into ConstrainedLanguage, where no execution policy or PowerShell version can help. Use the Python fallback, which applies the same patch.

It needs Python 3.8+ and a clone of this repository, because it reads `signatures.json` next to it:

```powershell
git clone https://github.com/Sketchystan1/chrome-mv2-patch
cd chrome-mv2-patch
```

Find the DLL, then inspect it — `check` only reads, so no elevation is needed:

```powershell
$dll = (Get-ChildItem "C:\Program Files\Google\Chrome\Application\*\chrome.dll" | Sort-Object { [version]$_.Directory.Name })[-1].FullName
python scripts\mv2_apply.py check "$dll"
```

If that reports a matched milestone with all sites `stock`, close Chrome completely and patch from an **elevated** shell. A `.bak` snapshot is written next to the DLL:

```powershell
python scripts\mv2_apply.py patch "$dll"
```

To undo it, restoring the original bytes from that snapshot:

```powershell
python scripts\mv2_apply.py restore "$dll"
```

To rehearse without touching the installation, `patch --out <copy>` writes the patched result elsewhere and leaves the target alone. Chrome's own updater replaces `chrome.dll`, so a browser update reverts the patch — rerun `check` after one. See [`scripts/README.md`](scripts/README.md) for the full flag list and the backup format.

## Donate

USDT (TRC20): TDAr6Lu2sYtArJYAgUpyfuk6rKNvvyMA87  
USDC (Base): 0x762712dcC8e3E757Cf3FC077AeF0b4EDa8692b7B  
[Boosty](https://boosty.to/sketchystan1)

## License

Released under the [MIT License](LICENSE).
