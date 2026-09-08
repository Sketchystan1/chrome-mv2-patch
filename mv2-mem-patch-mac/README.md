# mv2-mem-patch-mac

Turns Manifest V2 extensions back on in macOS Chrome. The Mac version of
`mv2-mem-patch-win/`.

A small **dylib** Chrome loads at startup, patching Chrome's MV2 switch **in memory**.
*Google Chrome Framework* on disk stays untouched, so Widevine DRM still sees Google's
bytes. Re-applies every launch.

The catch: to load the dylib, `install.sh` re-signs Chrome's main program (ad-hoc). The
framework stays stock, but you should **check Widevine still plays** after installing.

## Build (on a Mac)

```sh
./build.sh      # needs Xcode Command Line Tools
```

## Use

```sh
./install.sh --offline "/Applications/Google Chrome.app"   # look only
./install.sh           "/Applications/Google Chrome.app"   # install
./install.sh --restore "/Applications/Google Chrome.app"   # undo
```

Then enable an MV2 extension.

## Install uBlock Origin (MV2)

Re-enabling MV2 doesn't install the extension. Force-install uBO off-store via Chrome's
managed policy, then restart Chrome:

```sh
defaults write com.google.Chrome ExtensionSettings '{"fkgkibajhfbepljeaefdnfnegdcjomkh" = {"installation_mode" = "normal_installed"; "update_url" = "https://github.com/gorhill/uBlock/raw/refs/heads/master/dist/chromium/update.xml";};}'
```

## Notes

- No SIP change, but editing `/Applications` needs **Full Disk Access** for your
  terminal (System Settings → Privacy & Security).
- Re-run `install.sh` after Chrome auto-updates.
- Chrome's main program is a tiny stub with little header room. The dylib installs
  next to it as `Contents/MacOS/mv` and loads via a short `@loader_path/mv` path so
  the load command fits; the injector also drops a few metadata-only load commands
  (UUID / source-version / function-starts / data-in-code) from the stub to make
  room. Execution is unaffected; the framework and helpers are never touched.
  `signatures.json` stays in `Contents/Frameworks/mv2/`. `--restore` undoes it all.
- Debug: `MV2_MEMPATCH_DEBUG=1 "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"`.
- DRM: if Widevine drops a tier, the ad-hoc signature is why — `--restore` and use the
  disk patch `chrome-mv2.sh` instead.
