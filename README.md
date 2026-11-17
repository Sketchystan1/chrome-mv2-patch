# Chrome MV2 Extension Patcher

Re-enables Manifest V2 extensions in Chrome, Chromium, Edge.  
Windows: `.dll` that browser loads at startup and patches MV2 switch in memory. DRM works.  

See [`reversing.md`](mv2-reversing.md) for reversing details.  
See [`CHANGELOG.md`](CHANGELOG.md) for releases changes. 

Linux, macOS: maybe in the future...

## Windows

Download [latest release](https://github.com/Sketchystan1/chrome-mv2-patch/releases/latest) and run `install.bat`.  

Manual: copy `.dll` next to browser `.exe`.  
If older patcher installed, delete `version.dll`.

Verify by installing [uBlock Origin](https://github.com/gorhill/uBlock/releases) `.crx` MV2 extension.

## Donate

USDT (TRC20): `TDAr6Lu2sYtArJYAgUpyfuk6rKNvvyMA87`  
USDC (Base): `0x762712dcC8e3E757Cf3FC077AeF0b4EDa8692b7B`

## License

Released under the [MIT License](LICENSE).
