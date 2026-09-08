#!/bin/bash
# Build the macOS in-process MV2 mem-patch dylib (universal: arm64 + x86_64) and
# the offline inspector. Run this ON A MAC (needs clang + Command Line Tools); it
# cannot build on Windows/Linux.
set -e
cd "$(dirname "$0")"

# 1) Bring the shared gate table next to the artifacts. signatures.json is the
#    single source of truth shared with the .ps1/.sh/.py/PE launchers.
if [ -f ../signatures.json ]; then
  cp ../signatures.json ./signatures.json
  echo "copied signatures.json from repo root"
elif [ -f ./signatures.json ]; then
  echo "using the signatures.json already in this folder"
else
  echo "WARN: no signatures.json found — copy one next to install.sh before installing"
fi

COMMON="-std=c++17 -O2 -Wall -Wextra -arch arm64 -arch x86_64"

# 2) The dylib. Its install name matches where install.sh places it in the bundle
#    (Contents/MacOS/, next to the main-exe stub) so the SHORT LC_LOAD_DYLIB we
#    inject (@loader_path/mv) fits the stub's tiny header. System libs only
#    (mach_vm*, dyld, dladdr, sys_icache_invalidate live in libSystem); no
#    framework link needed. signatures.json/config.txt stay in Frameworks/mv2/
#    (the dylib searches ../Frameworks/mv2/ relative to itself).
clang++ $COMMON -dynamiclib \
    -install_name "@loader_path/mv" \
    -o mv2-mem-patch.dylib mv2-mem-patch.mm
echo "built mv2-mem-patch.dylib (universal)"

# 3) The offline inspector (install.sh --offline). Same core, no bundle needed.
clang++ $COMMON -o mv2-inspect mv2-inspect.cpp
echo "built mv2-inspect (universal)"

# 4) Ad-hoc sign the dylib. On Apple Silicon every loaded dylib must carry at
#    least an ad-hoc signature; disable-library-validation on the re-signed host
#    (install.sh) then lets Chrome's main executable load it regardless of signer.
codesign --force --sign - mv2-mem-patch.dylib
codesign --force --sign - mv2-inspect 2>/dev/null || true
echo "ad-hoc signed"

cat <<'EOF'

Next steps:
  1. Inspect your Chrome build (changes nothing):
       ./install.sh --offline "/Applications/Google Chrome.app"
  2. Install (injects the dylib + re-signs the app; Framework stays stock on disk):
       ./install.sh "/Applications/Google Chrome.app"
     Grant Terminal "Full Disk Access" if it reports an App-Management/TCC block.
  3. Launch Chrome normally and load a Manifest V2 extension.
  4. Read README.md for the DRM verification steps and the honest risk matrix.
EOF
