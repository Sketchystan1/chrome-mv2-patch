#!/bin/bash
# install.sh - install / inspect / restore the macOS in-process MV2 mem-patch.
#
# Makes production Google Chrome load mv2-mem-patch.dylib, which flips the Manifest
# V2 gates in the *Google Chrome Framework* MEMORY image at launch. The framework
# file is left byte-for-byte stock on disk, so Widevine's on-disk hash still passes
# (the DRM-preserving point of this build). To load a dylib into hardened Chrome,
# macOS requires it in the load commands + a valid signature, so this:
#   1. injects an LC_LOAD_DYLIB into Chrome's MAIN EXECUTABLE only (never the
#      framework), via ../scripts/macho_insert_dylib.py;
#   2. re-signs the main executable ad-hoc and NON-hardened, merging Chrome's own
#      entitlements with disable-library-validation + allow-unsigned-executable-memory,
#      and re-seals the bundle WITHOUT --deep so the framework/helpers keep their
#      stock Google signatures.
#
# No SIP changes are needed. Modifying an app in /Applications needs App Management
# / Full Disk Access (macOS TCC) - if a step is denied, grant that to Terminal or
# copy Chrome to a writable folder and pass --chrome.
#
#   ./install.sh [--offline] [--restore|--uninstall] [--chrome <Chrome.app>]
#
# Run build.sh first to produce mv2-mem-patch.dylib, mv2-inspect and signatures.json.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOAD_PATH="@executable_path/../Frameworks/mv2/mv2-mem-patch.dylib"
ENT_KEYS=(com.apple.security.cs.disable-library-validation \
          com.apple.security.cs.allow-unsigned-executable-memory)

info() { printf '%s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# ---- locate helpers -------------------------------------------------------- #
find_python() { command -v python3 || command -v python || return 1; }

find_injector() {
  for p in "$SCRIPT_DIR/macho_insert_dylib.py" "$SCRIPT_DIR/../scripts/macho_insert_dylib.py"; do
    [ -f "$p" ] && { printf '%s\n' "$p"; return 0; }
  done
  return 1
}

bundle_value() {  # key app
  /usr/libexec/PlistBuddy -c "Print $1" "$2/Contents/Info.plist" 2>/dev/null
}

main_exe() {  # app -> path to main executable
  local app="$1" name
  name="$(bundle_value CFBundleExecutable "$app")"
  [ -n "$name" ] || name="Google Chrome"
  printf '%s\n' "$app/Contents/MacOS/$name"
}

framework_bin() {  # app -> path to the versioned framework Mach-O
  local app="$1" fw name bin
  fw="$(ls -d "$app/Contents/Frameworks/"*" Framework.framework" 2>/dev/null | head -1)"
  [ -n "$fw" ] || return 1
  name="$(basename "$fw" .framework)"
  bin="$fw/Versions/Current/$name"
  [ -e "$bin" ] || bin="$(ls "$fw/Versions/"*/"$name" 2>/dev/null | tail -1)"
  [ -n "$bin" ] && printf '%s\n' "$bin"
}

backup_dir() {  # app -> stable per-app backup dir outside the bundle
  local app="$1" bid key
  bid="$(bundle_value CFBundleIdentifier "$app")"; [ -n "$bid" ] || bid=unknown
  key="$(printf '%s|%s' "$bid" "$app" | shasum | cut -c1-16)"
  printf '%s\n' "$HOME/Library/Application Support/mv2-mem-patch/$key"
}

require_writable() {  # app
  local app="$1" probe="$1/Contents/.mv2_write_probe"
  if ! touch "$probe" 2>/dev/null; then
    cat >&2 <<EOF
ERROR: cannot write inside $app

macOS is blocking changes to this app (App Management / TCC). Do ONE of:
  * System Settings > Privacy & Security > App Management (or Full Disk Access):
    add and enable your terminal, then re-run.
  * Or copy Chrome somewhere writable and target that copy:
      cp -R "$app" ~/Desktop/ && ./install.sh --chrome ~/Desktop/$(basename "$app")
EOF
    exit 1
  fi
  rm -f "$probe"
}

# Build a merged entitlements plist: the source binary's own entitlements plus our
# two keys. Reads from the STOCK executable (clean signature). Falls back to the
# shipped entitlements.plist / an empty dict if read-back is unavailable.
merge_entitlements() {  # src_macho out_plist
  local src="$1" out="$2" k
  if ! { codesign -d --entitlements - --xml "$src" 2>/dev/null > "$out" \
         && [ -s "$out" ] && plutil -lint "$out" >/dev/null 2>&1; }; then
    if [ -f "$SCRIPT_DIR/entitlements.plist" ]; then
      cp "$SCRIPT_DIR/entitlements.plist" "$out"
    else
      printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' \
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
        '<plist version="1.0"><dict/></plist>' > "$out"
    fi
  fi
  for k in "${ENT_KEYS[@]}"; do
    /usr/libexec/PlistBuddy -c "Delete :$k" "$out" 2>/dev/null
    /usr/libexec/PlistBuddy -c "Add :$k bool true" "$out" >/dev/null 2>&1 \
      || die "could not edit entitlements plist"
  done
}

# ---- actions --------------------------------------------------------------- #
do_offline() {  # app  (returns inspector's exit code)
  local app="$1" fw
  fw="$(framework_bin "$app")" || die "couldn't find the Chrome Framework inside $app"
  [ -x "$SCRIPT_DIR/mv2-inspect" ] || die "mv2-inspect not built - run ./build.sh first"
  [ -f "$SCRIPT_DIR/signatures.json" ] || die "signatures.json missing next to install.sh - run ./build.sh"
  "$SCRIPT_DIR/mv2-inspect" "$fw" "$SCRIPT_DIR/signatures.json"
}

do_install() {  # app
  local app="$1" exe bk py inj ent mv2dir
  exe="$(main_exe "$app")"; [ -e "$exe" ] || die "main executable not found: $exe"
  py="$(find_python)"       || die "python3 not found (install Xcode Command Line Tools: xcode-select --install)"
  inj="$(find_injector)"    || die "macho_insert_dylib.py not found (keep the repo's scripts/ alongside, or copy it next to install.sh)"
  [ -f "$SCRIPT_DIR/mv2-mem-patch.dylib" ] || die "mv2-mem-patch.dylib missing - run ./build.sh"
  [ -f "$SCRIPT_DIR/signatures.json" ]     || die "signatures.json missing - run ./build.sh"

  require_writable "$app"

  info "Checking this Chrome against signatures.json ..."
  do_offline "$app" || die "This Chrome version isn't covered by signatures.json yet - nothing was changed."

  bk="$(backup_dir "$app")"
  mv2dir="$app/Contents/Frameworks/mv2"

  # Establish a STOCK base for the executable (robust to re-install and to Chrome
  # auto-update, which drops in a fresh stock exe with no load command of ours).
  if "$py" "$inj" present "$LOAD_PATH" "$exe"; then
    if [ -f "$bk/main.stock" ]; then
      cp "$bk/main.stock" "$exe" || die "could not restore stock executable from backup"
    else
      "$py" "$inj" remove "$LOAD_PATH" "$exe" || die "could not strip prior load command"
    fi
  fi
  # Back up the current stock executable (overwrites a stale backup after an update).
  mkdir -p "$bk" || die "could not create backup dir $bk"
  cp "$exe" "$bk/main.stock" || die "could not back up the stock executable"
  printf '%s\n' "$exe" > "$bk/meta"

  # Place the dylib + signatures beside it, inside the bundle.
  mkdir -p "$mv2dir" || die "could not create $mv2dir"
  cp "$SCRIPT_DIR/mv2-mem-patch.dylib" "$mv2dir/" || die "could not copy dylib"
  cp "$SCRIPT_DIR/signatures.json"     "$mv2dir/" || die "could not copy signatures.json"
  [ -f "$SCRIPT_DIR/config.txt" ] && cp "$SCRIPT_DIR/config.txt" "$mv2dir/"

  # Inject the load command into the main executable only.
  "$py" "$inj" insert "$LOAD_PATH" "$exe" || die "load-command injection failed"

  # Re-sign: dylib ad-hoc; main exe ad-hoc + merged entitlements, NON-hardened; then
  # re-seal the bundle (no --deep) so framework/helpers keep their stock signatures.
  ent="$(mktemp)"; merge_entitlements "$bk/main.stock" "$ent"
  codesign --force --sign - "$mv2dir/mv2-mem-patch.dylib" || die "could not sign the dylib"
  if ! codesign --force --sign - --entitlements "$ent" "$app"; then
    rm -f "$ent"
    die "re-signing failed - if it looks like a permissions error, grant Full Disk Access (see above) or use --chrome on a writable copy"
  fi
  rm -f "$ent"

  if codesign --verify "$app" 2>/dev/null; then
    info "signature verified"
  else
    warn "codesign --verify reported issues (usually benign for an ad-hoc/mixed-signer bundle)"
  fi

  cat <<EOF

Done. MV2 mem-patch installed on:
  $app
Launch Chrome NORMALLY (icon/Spotlight) and load a Manifest V2 extension.
The Chrome Framework on disk is unchanged (Widevine hash preserved); the gates are
flipped only in memory, re-applied automatically on every launch.

Re-run this after Chrome auto-updates (an update replaces the executable).
To undo:  ./install.sh --restore --chrome "$app"
Debug:    set MV2_MEMPATCH_DEBUG=1 and watch: log stream --predicate 'eventMessage CONTAINS "[mv2patch]"'
EOF
}

do_restore() {  # app
  local app="$1" exe bk py inj ent
  exe="$(main_exe "$app")"; [ -e "$exe" ] || die "main executable not found: $exe"
  require_writable "$app"
  bk="$(backup_dir "$app")"

  if [ -f "$bk/main.stock" ]; then
    cp "$bk/main.stock" "$exe" || die "could not restore the stock executable"
    info "restored the stock main executable from backup"
  else
    py="$(find_python)" && inj="$(find_injector)" \
      && "$py" "$inj" remove "$LOAD_PATH" "$exe" \
      && info "stripped the load command (no backup was present)" \
      || warn "no backup found and could not strip the load command"
  fi
  rm -rf "$app/Contents/Frameworks/mv2"

  # Re-seal ad-hoc, keeping disable-library-validation so the (now ad-hoc) main exe
  # can still load the stock Google-signed framework at launch.
  ent="$(mktemp)"; merge_entitlements "$exe" "$ent"
  codesign --force --sign - --entitlements "$ent" "$app" || warn "re-seal after restore failed"
  rm -f "$ent"

  cat <<EOF

Restored. The MV2 mem-patch is removed and MV2 is off.
NOTE: the executable is stock BYTES but re-signed ad-hoc; only reinstalling Chrome
(or letting it auto-update) restores Google's original Developer ID signature.
EOF
}

# ---- arg parsing ----------------------------------------------------------- #
MODE=install
APP="/Applications/Google Chrome.app"
while [ $# -gt 0 ]; do
  case "$1" in
    --offline)            MODE=offline ;;
    --restore|--uninstall) MODE=restore ;;
    --chrome)             shift; [ -n "${1:-}" ] || die "--chrome needs a path"; APP="$1" ;;
    -h|--help)            sed -n '2,20p' "$0"; exit 0 ;;
    /*|./*|../*|*.app)    APP="$1" ;;
    *)                    die "unknown argument: $1 (use --help)" ;;
  esac
  shift
done
[ -d "$APP" ] || die "not an app bundle: $APP"

case "$MODE" in
  offline) do_offline "$APP" ;;
  restore) do_restore "$APP" ;;
  install) do_install "$APP" ;;
esac
