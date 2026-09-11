"""Fetch the stock, gate-bearing Chrome binary for MV2 signature derivation.

The rest of the toolkit (`fetch_symbols.py` -> `symbols_from_pdb.py` / `nm` ->
`derive_milestone.py`) all start from ONE artifact: the browser binary that
carries the inlined `IsExtensionAffected` gates --

    Windows x64    chrome.dll   (PE32+, container "pe")
    Windows x86    chrome.dll   (PE32,  container "pe32")
    Windows arm64  chrome.dll   (PE32+, container "pe-arm64")
    Linux  x86-64  chrome       (ELF,   container "elf")
    macOS  arm64   Google Chrome Framework  (Mach-O, container "macho-arm64")

macOS has no consumer offline installer we can unwrap off-Mac (it ships a `.dmg`),
so the mac platforms always fetch the per-arch Chrome for Testing zip -- a plain
zip 7-Zip opens trivially. CfT is UNBRANDED, so a mac table derived from it must
be re-verified against a real `Google Chrome.app` install (the macOS CI does this).

Windows on ARM (win-arm64) has no Chrome for Testing build, so it cannot pin an
old version via CfT. Its current stable/beta build is fetched from the arm64
enterprise MSI (`googlechromestandaloneenterprise_arm64.msi`, a stable
non-versioned URL); to pin an older build pass `--url` (the per-build
dl.google.com/release2 installer), or hand-copy an arm64 chrome.dll. The unwrap
chain is otherwise identical to win64's MSI path.

Google publishes offline installers only for each channel's CURRENT build, so
that is what this fetches by default -- the same consumer binary the patcher
runs against. `--version` falls back to the Chrome for Testing archive for an
older build; CfT is a portable, UNBRANDED build whose codegen can differ from
consumer stable, so a signature table derived from it must be re-verified
against the real install before shipping.

The binary is unwrapped out of the installer and dropped in `_scratch/`
(gitignored) under a clean, arch-tagged name, ready to hand to the next step:

    python scripts/fetch_chrome_binary.py                      # current stable, host arch
    python scripts/fetch_chrome_binary.py --platform linux
    python scripts/fetch_chrome_binary.py --platform win       # 32-bit chrome.dll
    python scripts/fetch_chrome_binary.py --platform mac-arm64 # Apple Silicon framework
    python scripts/fetch_chrome_binary.py --platform win-arm64          # arm64 enterprise MSI
    python scripts/fetch_chrome_binary.py --channel beta
    python scripts/fetch_chrome_binary.py --version 152.0.7977.30
    python scripts/fetch_chrome_binary.py --list               # just print current versions

Pure stdlib, but extraction shells out to 7-Zip: the installer nests
(.exe -> updater.7z -> <ver>_chrome_installer.exe -> chrome.7z -> Chrome-bin/,
the beta .msi wraps the same offline .exe, and the .deb holds
data.tar.xz -> ./opt/google/chrome/chrome), so several layers open before the
binary appears.
"""

import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO / "_scratch"

CHANNELS = ("stable", "beta")

# The patcher targets, keyed by the --platform value. Each carries the
# VersionHistory API platform id, the container tag derive_milestone.py stamps,
# the gate binary's filename, and how to recognise the right one on disk:
#   PE optional-header magic 0x20B (PE32+) / 0x10B (PE32) tells x64/arm64 from
#   x86, and the "machine" field (0x8664 x64 vs 0xAA64 arm64) then splits the two
#   PE32+ builds so a win64 fetch never grabs the arm64 dll and vice-versa. The
#   Linux ELF is matched by class byte (2 == 64-bit) instead.
PLATFORMS = {
    "win64":     {"api": "win64", "container": "pe",   "binary": "chrome.dll", "pe_magic": 0x20B, "machine": 0x8664, "tag": "win64",   "suffix": ".dll", "cft": "win64"},
    "win":       {"api": "win",   "container": "pe32", "binary": "chrome.dll", "pe_magic": 0x10B, "tag": "win32",   "suffix": ".dll", "cft": "win32"},
    # Windows on ARM: native arm64 chrome.dll (PE32+, machine 0xAA64), same
    # bcond flip as macOS arm64. Chrome for Testing has no win-arm64 build, so
    # there is no CfT --version fallback; the stable/beta arm64 *enterprise MSI*
    # (INSTALLERS below) is a stable non-versioned URL for the current build.
    # Pin an older build with --url (a per-build dl.google.com/release2 installer),
    # or hand-copy an arm64 chrome.dll.
    "win-arm64": {"api": "win_arm64", "container": "pe-arm64", "binary": "chrome.dll", "pe_magic": 0x20B, "machine": 0xAA64, "tag": "win-arm64", "suffix": ".dll"},
    "linux":     {"api": "linux", "container": "elf",  "binary": "chrome",     "pe_magic": None,  "machine": 0x3E, "tag": "linux64", "suffix": "",     "cft": "linux64"},
    # Linux on ARM: native aarch64 `chrome` ELF (EM_AARCH64 0xB7), same bcond flip
    # as Windows/macOS arm64. Google began shipping official arm64 Linux .debs in
    # mid-2026; they share the `linux` VersionHistory feed (one version for both
    # arches) but there is NO Chrome for Testing arm64 Linux build, so -- like
    # win-arm64 -- there is no CfT --version fallback: use --channel stable/beta
    # for the current build, or hand-copy an arm64 `chrome`.
    "linux-arm64": {"api": "linux", "container": "elf-arm64", "binary": "chrome", "pe_magic": None, "machine": 0xB7, "tag": "linux-arm64", "suffix": ""},
    # macOS: CfT-only. The gate binary is the framework Mach-O inside the .app;
    # matched brand-agnostically by a "framework" name + the slice's cputype.
    "mac-arm64": {"api": "mac_arm64", "container": "macho-arm64", "binary": None, "pe_magic": None, "tag": "mac-arm64", "suffix": "", "cft": "mac-arm64", "cputype": 0x0100000C, "cft_only": True},
}

# The channel's CURRENT-build offline installers. These URLs always serve the
# version the API reports for the channel, so no version appears in the link.
# Windows x64/x86 stable ship a self-extracting EXE; Windows beta and all
# Windows arm64 builds ship an enterprise MSI (no consumer arm64 standalone EXE
# exists); Linux both channels a .deb -- all carry the full Chrome-bin.
INSTALLERS = {
    "stable": {
        "win64":     "https://dl.google.com/chrome/install/standalonesetup64.exe",
        "win":       "https://dl.google.com/chrome/install/standalonesetup.exe",
        "win-arm64": "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise_arm64.msi",
        "linux":     "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb",
        "linux-arm64": "https://dl.google.com/linux/direct/google-chrome-stable_current_arm64.deb",
    },
    "beta": {
        "win64":     "https://dl.google.com/tag/s/dl/chrome/install/beta/googlechromebetastandaloneenterprise64.msi",
        "win":       "https://dl.google.com/tag/s/dl/chrome/install/beta/googlechromebetastandaloneenterprise.msi",
        "win-arm64": "https://dl.google.com/tag/s/dl/chrome/install/beta/googlechromebetastandaloneenterprise_arm64.msi",
        "linux":     "https://dl.google.com/linux/direct/google-chrome-beta_current_amd64.deb",
        "linux-arm64": "https://dl.google.com/linux/direct/google-chrome-beta_current_arm64.deb",
    },
}

# Branded macOS universal DMG (holds both x86_64 and arm64 framework slices).
# Chrome for Testing is UNBRANDED and its clang build dead-code-eliminates the
# InstallVerifier from_webstore inline (ShouldEnforce() folds to false off-brand),
# so a #if GOOGLE_CHROME_BRANDING gate (the Route A InstallVerifier gate) can ONLY
# be derived from this branded framework. Off-Mac unwrap needs a recent 7-Zip
# (>= ~21.x for APFS/DMG; 26.x reads Chrome's DMG directly).
MAC_DMG = {
    "stable": "https://dl.google.com/chrome/mac/universal/stable/GGRO/googlechrome.dmg",
    "beta":   "https://dl.google.com/chrome/mac/universal/beta/GGRO/googlechrome.dmg",
}

VERSION_API = (
    "https://versionhistory.googleapis.com/v1/chrome/platforms/{platform}"
    "/channels/{channel}/versions/all/releases?filter=endtime=none"
)

# The only official archive of version-pinned builds. It carries Chrome for
# Testing (unbranded), NOT consumer stable, so it is a --version fallback only
# (and the sole source for the mac platforms, which have no unwrappable installer).
CFT_ENDPOINT = (
    "https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json"
)
CFT_LAST_KNOWN = (
    "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"
)


def http_get(url, timeout=60):
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    return urllib.request.urlopen(request, timeout=timeout)


def version_key(version):
    """Sort key comparing version parts numerically, so 7922.108 > 7922.99."""
    return tuple(int(part) if part.isdigit() else -1 for part in version.split("."))


def binary_version(path):
    """The version the artifact itself reports, or None.

    PE: the VS_VERSION_INFO FileVersion, read straight out of the resource
    directory (no Windows API, so this also works when cross-fetching from
    Linux/macOS). ELF and Mach-O carry no equivalent record, so they fall back to
    the caller's value.
    """
    try:
        with open(path, "rb") as handle:
            head = handle.read(0x400)
            if head[:2] != b"MZ":
                return None
            pe = struct.unpack_from("<I", head, 0x3C)[0]
            if head[pe:pe + 4] != b"PE\0\0":
                return None
            magic = struct.unpack_from("<H", head, pe + 24)[0]
            fixed = 112 if magic == 0x20B else 96
            rsrc_rva, rsrc_size = struct.unpack_from("<II", head, pe + 24 + fixed + 2 * 8)
            if not rsrc_rva:
                return None
            nsec = struct.unpack_from("<H", head, pe + 6)[0]
            sec = pe + 24 + struct.unpack_from("<H", head, pe + 20)[0]
            for i in range(nsec):
                off = sec + i * 40
                vsz, va, rsz, raw = struct.unpack_from("<IIII", head, off + 8)
                if va <= rsrc_rva < va + max(vsz, rsz):
                    handle.seek(raw + (rsrc_rva - va))
                    blob = handle.read(min(rsrc_size, 8 << 20))
                    break
            else:
                return None
        # VS_FIXEDFILEINFO starts at its 0xFEEF04BD signature; FileVersion is the
        # next four 16-bit fields, stored most-significant pair first.
        at = blob.find(b"\xbd\x04\xef\xfe")
        if at < 0:
            return None
        ms_hi, ms_lo, ls_hi, ls_lo = struct.unpack_from("<HHHH", blob, at + 8)
        return f"{ms_lo}.{ms_hi}.{ls_lo}.{ls_hi}"
    except (OSError, struct.error, IndexError):
        return None


def release_version(release):
    name = release.get("name", "")
    if "/versions/" in name:
        return name.split("/versions/")[1].split("/")[0]
    return ""


def current_version(api_platform, channel):
    """Highest version the channel is currently serving for this platform, or ""."""
    url = VERSION_API.format(platform=api_platform, channel=channel)
    try:
        with http_get(url, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError) as err:
        print(f"  warning: version lookup failed for {api_platform}/{channel}: {err}")
        return ""
    # A channel can serve several releases during a staged rollout, unordered;
    # take the highest version rather than trusting the first entry.
    versions = [
        v for v in (r.get("version") or release_version(r) for r in data.get("releases", [])) if v
    ]
    return max(versions, key=version_key) if versions else ""


def resolve_cft(version, cft_platform):
    """Resolve a pinned version to a CfT download for one platform.

    Returns (resolved_version, url, note) or None. Falls back to the newest
    archived build at or below the requested version when there is no exact one.
    """
    with http_get(CFT_ENDPOINT, timeout=60) as response:
        data = json.loads(response.read().decode("utf-8"))
    archive = {}
    for entry in data.get("versions", []):
        ver = entry.get("version", "")
        if not ver:
            continue
        archive[ver] = {
            item["platform"]: item["url"]
            for item in entry.get("downloads", {}).get("chrome", [])
            if item.get("platform") and item.get("url")
        }

    if version in archive and archive[version].get(cft_platform):
        return version, archive[version][cft_platform], "exact"

    wanted = version_key(version)
    usable = [
        v for v in archive
        if all(p.isdigit() for p in v.split("."))
        and version_key(v) <= wanted
        and archive[v].get(cft_platform)
    ]
    if not usable:
        return None
    nearest = max(usable, key=version_key)
    return nearest, archive[nearest][cft_platform], f"nearest (<= {version})"


def cft_current(cft_platform, channel):
    """Current Chrome for Testing version for a channel that publishes this
    platform, or "". Used for the mac platforms' default (latest) fetch."""
    try:
        with http_get(CFT_LAST_KNOWN, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError) as err:
        print(f"  warning: CfT current-version lookup failed: {err}")
        return ""
    chan = data.get("channels", {}).get(channel.capitalize())
    if not chan:
        return ""
    platforms = {d.get("platform") for d in chan.get("downloads", {}).get("chrome", [])}
    return chan.get("version", "") if cft_platform in platforms else ""


def human_size(num_bytes):
    for unit in ("B", "KB", "MB", "GB"):
        if num_bytes < 1024 or unit == "GB":
            return f"{num_bytes:.1f}{unit}" if unit != "B" else f"{num_bytes}B"
        num_bytes /= 1024


def _progress(done, total):
    if total > 0:
        sys.stdout.write(f"\r  {done * 100 // total:3d}%  {done >> 20}/{total >> 20} MiB")
    else:
        sys.stdout.write(f"\r  {done >> 20} MiB")
    sys.stdout.flush()


def download(url, dest):
    """Stream a URL to dest via a .part temp file, size-checked against
    Content-Length then atomically renamed into place. No resume: each call
    refetches from the start. Returns dest, or None on network error / truncated
    transfer."""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    part = dest + ".part"
    try:
        with http_get(url, timeout=180) as response:
            total = int(response.headers.get("Content-Length") or 0)
            done = 0
            with open(part, "wb") as handle:
                while True:
                    chunk = response.read(1 << 20)
                    if not chunk:
                        break
                    handle.write(chunk)
                    done += len(chunk)
                    _progress(done, total)
        print()
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as err:
        print(f"\n  download failed: {err}")
        if os.path.exists(part):
            os.remove(part)
        return None
    if total and os.path.getsize(part) != total:
        print(f"  download truncated ({os.path.getsize(part)} of {total} B)")
        os.remove(part)
        return None
    os.replace(part, dest)
    return dest


def find_seven_zip():
    """Locate 7-Zip, which unpacks the EXE/MSI/DEB installer chain."""
    found = shutil.which("7z") or shutil.which("7za")
    if found:
        return found
    for candidate in (
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
        "/usr/bin/7z",
        "/usr/bin/7za",
        "/usr/local/bin/7z",
    ):
        if os.path.exists(candidate):
            return candidate
    return None


# --- nested extraction ------------------------------------------------------
# Chrome installers wrap the payload several layers deep, so one 7-Zip pass
# leaves only containers. These rules drive the recursive unwrap; they mirror
# the set the original release fetcher used, minus the macOS pbzx handling.

# Intermediate containers worth opening but not keeping afterwards.
NESTED_SUFFIXES = (".tar.xz", ".tar.gz", ".tar.bz2", ".tar", ".7z", ".cpio", ".xz", ".gz")
NESTED_NAMES = ("payload", "updater.7z", "scripts")
NESTED_PATTERNS = ("_chrome_installer.exe",)

# The MSI stores the offline installer as a stream named
# "Binary.GoogleChromeInstaller" -- no extension, so it is caught by magic
# bytes. Restricted to extensionless files so a real chrome.dll/chrome is never
# mistaken for an archive and unpacked over.
CONTAINER_MAGIC = (
    b"MZ", b"MSCF", b"7z\xbc\xaf\x27\x1c", b"xar!",
    b"\xfd7zXZ", b"\x1f\x8b", b"PK\x03\x04",
)
KNOWN_CONTENT_EXTENSIONS = (
    ".exe", ".dll", ".sys", ".node", ".pak", ".dat", ".bin", ".so", ".dylib",
    ".png", ".jpg", ".svg", ".ico", ".icns", ".json", ".xml", ".txt", ".html",
    ".js", ".css", ".plist", ".strings", ".pb", ".manifest", ".msi", ".nib",
)


def has_container_magic(path):
    try:
        with open(path, "rb") as handle:
            head = handle.read(8)
    except OSError:
        return False
    return any(head.startswith(magic) for magic in CONTAINER_MAGIC)


def is_nested_container(path, filename):
    lowered = filename.lower()
    if (
        lowered.endswith(NESTED_SUFFIXES)
        or lowered in NESTED_NAMES
        or any(lowered.endswith(pattern) for pattern in NESTED_PATTERNS)
    ):
        return True
    if os.path.splitext(lowered)[1] not in KNOWN_CONTENT_EXTENSIONS:
        return has_container_magic(path)
    return False


def unpack_nested(root, seven_zip, max_rounds=10):
    """Open container files left behind by the first extraction pass.

    Each round opens one nesting level; the deepest chain (Windows EXE) is four,
    so the cap only stops a pathological archive from looping.
    """
    for _ in range(max_rounds):
        opened = False
        for current_dir, _dirs, files in os.walk(root):
            for filename in files:
                path = os.path.join(current_dir, filename)
                if not is_nested_container(path, filename):
                    continue
                target = os.path.join(current_dir, filename.split(".")[0] + "_contents")
                os.makedirs(target, exist_ok=True)
                subprocess.run(
                    [seven_zip, "x", path, f"-o{target}", "-y"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                # Judge by what landed on disk, not the exit code.
                if any(os.scandir(target)):
                    os.remove(path)
                    opened = True
                else:
                    shutil.rmtree(target, ignore_errors=True)
        if not opened:
            return


def extract(archive_path, workdir, seven_zip):
    """Unpack the installer fully. Returns the extraction root."""
    dest = os.path.join(workdir, "unpacked")
    os.makedirs(dest, exist_ok=True)
    subprocess.run(
        [seven_zip, "x", archive_path, f"-o{dest}", "-y"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    unpack_nested(dest, seven_zip)
    return dest


# --- locating the gate binary ----------------------------------------------
def _pe_optional_magic(path):
    """PE optional-header magic (0x20B PE32+ / 0x10B PE32), or None."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(0x40)
            if head[:2] != b"MZ" or len(head) < 0x40:
                return None
            e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
            handle.seek(e_lfanew)
            if handle.read(4) != b"PE\x00\x00":
                return None
            handle.seek(e_lfanew + 24)
            return struct.unpack("<H", handle.read(2))[0]
    except (OSError, struct.error):
        return None


def _pe_machine(path):
    """PE COFF machine field (0x8664 x64 / 0xAA64 arm64 / 0x14C x86), or None.
    Splits the two PE32+ builds (x64 vs arm64) that share optional-header magic."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(0x40)
            if head[:2] != b"MZ" or len(head) < 0x40:
                return None
            e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
            handle.seek(e_lfanew)
            if handle.read(4) != b"PE\x00\x00":
                return None
            return struct.unpack("<H", handle.read(2))[0]
    except (OSError, struct.error):
        return None


def _is_elf64(path):
    try:
        with open(path, "rb") as handle:
            head = handle.read(5)
    except OSError:
        return False
    return head[:4] == b"\x7fELF" and len(head) == 5 and head[4] == 2


def _elf_machine(path):
    """ELF e_machine (0x3E x86_64 / 0xB7 aarch64), or None. Splits the two ELF64
    `chrome` builds so a linux-arm64 fetch never grabs the x86_64 binary."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(0x14)
    except OSError:
        return None
    if head[:4] != b"\x7fELF" or len(head) < 0x14:
        return None
    return struct.unpack_from("<H", head, 0x12)[0]


def _macho_cputype(path):
    """cputype of a THIN little-endian 64-bit Mach-O (CfT ships per-arch, thin),
    or None. Used to pick the right slice's framework in a mac .app."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(8)
    except OSError:
        return None
    if len(head) < 8 or struct.unpack_from("<I", head, 0)[0] != 0xFEEDFACF:
        return None
    return struct.unpack_from("<I", head, 4)[0]


def locate_binary(root, spec):
    """Find the gate binary in an unpacked tree, matching name/kind AND arch.

    A shell-script launcher named `google-chrome` sits beside the Linux ELF, an
    installer can carry stub DLLs, and a mac .app carries several frameworks and
    helper Mach-Os; the magic/arch check skips the wrong ones. Picks the largest
    match, which is always the real ~200 MB browser binary / framework.
    """
    matches = []
    for current_dir, _dirs, files in os.walk(root):
        for filename in files:
            path = os.path.join(current_dir, filename)
            container = spec["container"]
            if container.startswith("macho"):
                # brand-agnostic: any "*Framework" Mach-O of this slice's cputype
                if "framework" in filename.lower() and _macho_cputype(path) == spec["cputype"]:
                    matches.append(path)
                continue
            if filename.lower() != spec["binary"]:
                continue
            if container.startswith("elf"):
                # ELF64 `chrome` of the spec's pinned machine (elf -> 0x3E x86_64,
                # elf-arm64 -> 0xB7) so a fetch never grabs the wrong-arch binary.
                if _is_elf64(path) and (not spec.get("machine") or _elf_machine(path) == spec["machine"]):
                    matches.append(path)
            elif _pe_optional_magic(path) == spec["pe_magic"]:
                # PE32+ x64 and arm64 share magic 0x20B; the machine field (when
                # the spec pins one) is what tells the arm64 dll from the x64 one.
                if spec.get("machine") and _pe_machine(path) != spec["machine"]:
                    continue
                matches.append(path)
    return max(matches, key=os.path.getsize) if matches else None


# ---------------------------------------------------------------------------
def list_current():
    print(f"{'Platform':<10} {'Container':<10} {'Stable':<18} {'Beta':<18}")
    print("-" * 56)
    for key, spec in PLATFORMS.items():
        cells = [current_version(spec["api"], ch) or "-" for ch in CHANNELS]
        print(f"{key:<10} {spec['container']:<10} {cells[0]:<18} {cells[1]:<18}")


def fetch(platform, channel, version, out_dir, keep, url_override=None):
    spec = PLATFORMS[platform]
    seven_zip = find_seven_zip()
    if not seven_zip:
        print("error: 7-Zip not found (install it, or put 7z on PATH).", file=sys.stderr)
        return 1

    latest = "" if spec.get("cft_only") else current_version(spec["api"], channel)
    if latest:
        print(f"Current {channel} for {platform}: {latest}")

    # Decide the source: an explicit --url (needed only to pin an OLD win-arm64
    # build, which has no CfT fallback), the channel's live installer for the
    # current build, or the Chrome for Testing archive for a pinned older version
    # -- and always CfT for mac.
    if url_override:
        url = url_override
        fetch_version = version or "custom"
        source = "explicit --url"
    elif spec.get("cft_only"):
        want = version or cft_current(spec["cft"], channel)
        if not want:
            print(f"error: could not determine a CfT {channel} version for {platform}.", file=sys.stderr)
            return 1
        resolved = resolve_cft(want, spec["cft"])
        if not resolved:
            print(f"error: no Chrome for Testing build at or below {want} for {platform}.", file=sys.stderr)
            return 1
        fetch_version, url, note = resolved
        source = f"Chrome for Testing ({note})"
        print(f"macOS via CfT: {want} -> {fetch_version}")
        print("  note: CfT is UNBRANDED; re-verify the derived table against a real Google Chrome.app.")
    elif version and version != latest:
        if not spec.get("cft"):
            # win-arm64 has no Chrome for Testing build to pin against.
            print(f"error: --platform {platform} cannot pin --version (no Chrome for Testing arm64 "
                  f"build). Fetch the current build without --version, or pass --url <installer> "
                  f"(a per-build https://dl.google.com/release2/chrome/<hash>_<ver>/... installer).",
                  file=sys.stderr)
            return 1
        resolved = resolve_cft(version, spec["cft"])
        if not resolved:
            print(f"error: no Chrome for Testing build at or below {version} for {platform}.", file=sys.stderr)
            return 1
        fetch_version, url, note = resolved
        source = f"Chrome for Testing ({note})"
        print(f"Pinned {version} -> CfT {fetch_version}")
        print("  note: CfT is an UNBRANDED build; re-verify any derived table against the real install.")
    else:
        url = INSTALLERS[channel][platform]
        fetch_version = latest or (version or "current")
        source = f"{channel} installer"

    print(f"Source: {source}\n        {url}")

    workdir = os.path.join(out_dir, "_fetch_tmp")
    if os.path.isdir(workdir):
        shutil.rmtree(workdir, ignore_errors=True)
    os.makedirs(workdir, exist_ok=True)

    archive = os.path.join(workdir, os.path.basename(url.split("?")[0]))
    print(f"\nDownloading into {os.path.relpath(workdir)}/ ...")
    if not download(url, archive):
        shutil.rmtree(workdir, ignore_errors=True)
        return 1

    print(f"Extracting {os.path.basename(archive)} ...")
    tree = extract(archive, workdir, seven_zip)
    binary = locate_binary(tree, spec)
    if not binary:
        print(f"error: no {spec['binary']} ({spec['container']}) found in the extracted tree.", file=sys.stderr)
        if not keep:
            shutil.rmtree(workdir, ignore_errors=True)
        return 1

    # Name the file after the version the BINARY reports, not the one the release
    # feed advertised. They disagree in practice: the stable win-arm64 enterprise
    # MSI has shipped a chrome.dll whose VS_VERSION_INFO reads 152.0.7977.76 while
    # the feed called the download 153.0.8010.12. A file named for the feed sends
    # the whole derivation - and the milestone name - to the wrong version.
    real_version = binary_version(binary) or fetch_version
    if real_version != fetch_version:
        print(f"\nnote: the feed advertised {fetch_version}, but this binary reports "
              f"{real_version}; naming it for the binary.")
    dest = os.path.join(out_dir, f"chrome-{real_version}-{spec['tag']}{spec['suffix']}")
    shutil.copy2(binary, dest)
    size = os.path.getsize(dest)
    if not keep:
        shutil.rmtree(workdir, ignore_errors=True)

    print(f"\nSaved {spec['container']} binary ({human_size(size)}):")
    print(f"  {os.path.relpath(dest)}")
    print("\nNext:")
    if spec["container"].startswith("macho"):
        print(f"  python scripts/derive_milestone.py {os.path.relpath(dest)} --name <ver> --json")
        print("  # mac symbols are not published for CfT: the x64 slice cross-checks against")
        print("  # the Linux x64 table; arm64 is located structurally (eyeball the gate).")
    elif spec["container"] == "elf-arm64":
        print(f"  python scripts/derive_milestone.py {os.path.relpath(dest)} --name <ver> --json")
        print("  # no arm64 Linux debug-info zip is published: the arm64 gates are located")
        print("  # structurally and cross-checked against the macos-arm64 / win-arm64 tables.")
    else:
        print(f"  python scripts/fetch_symbols.py {os.path.relpath(dest)}")
        if spec["container"] == "elf":
            print("  python scripts/symbols_from_elf.py _scratch/chrome.debug _scratch/syms.txt")
        else:
            print(f"  python scripts/symbols_from_pdb.py {os.path.relpath(dest)} --symdir _scratch --json _scratch/syms.json")
        print(f"  python scripts/derive_milestone.py {os.path.relpath(dest)} --symbols _scratch/syms.* --name <ver> --json")
    return 0


def _macho_arch_slice(data, cputype):
    """Carve one arch slice out of a fat Mach-O (CAFEBABE/CAFEBABF), or return
    `data` unchanged when it is already a thin Mach-O. None if the slice is absent."""
    if len(data) < 8:
        return None
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic in (0xFEEDFACF, 0xFEEDFACE):
        return data                       # already thin
    if magic not in (0xCAFEBABE, 0xCAFEBABF):
        return None
    wide = magic == 0xCAFEBABF
    n = struct.unpack_from(">I", data, 4)[0]
    off = 8
    for _ in range(n):
        if wide:
            cput, _cs, o, size = struct.unpack_from(">IIQQ", data, off)[:4]
            off += 32
        else:
            cput, _cs, o, size, _al = struct.unpack_from(">IIIII", data, off)
            off += 20
        if cput == cputype:
            return data[o:o + size]
    return None


def fetch_branded_mac(platform, channel, out_dir, keep):
    """Fetch the BRANDED macOS universal DMG and carve this platform's framework
    slice (arm64). Unlike the default CfT path, the branded framework carries the
    InstallVerifier ENFORCE inline, so gates behind #if GOOGLE_CHROME_BRANDING can
    be derived. Needs 7-Zip; the dSYM (fetch_symbols.py --chrome-version) then
    names the gate functions."""
    spec = PLATFORMS[platform]
    cputype = spec.get("cputype")
    if not cputype:
        print(f"error: --branded is macOS-only (got {platform}).", file=sys.stderr)
        return 1
    seven_zip = find_seven_zip()
    if not seven_zip:
        print("error: 7-Zip not found (install it, or put 7z on PATH).", file=sys.stderr)
        return 1
    url = MAC_DMG.get(channel)
    if not url:
        print(f"error: no branded mac DMG for channel {channel}.", file=sys.stderr)
        return 1
    print(f"Source: branded macOS universal DMG ({channel})\n        {url}")
    print("  note: this is CONSUMER Chrome (branded) - the InstallVerifier ENFORCE")
    print("        inline is present here but DCE'd out of Chrome for Testing.")

    workdir = os.path.join(out_dir, "_dmg_tmp")
    shutil.rmtree(workdir, ignore_errors=True)
    os.makedirs(workdir, exist_ok=True)
    archive = os.path.join(workdir, "googlechrome.dmg")
    print(f"\nDownloading into {os.path.relpath(workdir)}/ ...")
    if not download(url, archive):
        shutil.rmtree(workdir, ignore_errors=True)
        return 1

    print("Extracting the DMG (a recent 7-Zip reads Chrome's DMG directly) ...")
    dest = os.path.join(workdir, "unpacked")
    os.makedirs(dest, exist_ok=True)
    subprocess.run([seven_zip, "x", archive, f"-o{dest}", "-y"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # The framework Mach-O is the largest extensionless file named "*Framework".
    framework, version = None, ""
    for current_dir, _dirs, files in os.walk(dest):
        for filename in files:
            if "framework" not in filename.lower() or os.path.splitext(filename)[1]:
                continue
            path = os.path.join(current_dir, filename)
            if framework is None or os.path.getsize(path) > os.path.getsize(framework):
                framework = path
                parts = current_dir.replace("\\", "/").split("/")
                if "Versions" in parts and parts.index("Versions") + 1 < len(parts):
                    version = parts[parts.index("Versions") + 1]
    if not framework:
        print("error: no 'Google Chrome Framework' Mach-O found in the DMG.", file=sys.stderr)
        if not keep:
            shutil.rmtree(workdir, ignore_errors=True)
        return 1

    sliced = _macho_arch_slice(open(framework, "rb").read(), cputype)
    if sliced is None:
        print(f"error: framework has no cputype 0x{cputype:08X} slice.", file=sys.stderr)
        if not keep:
            shutil.rmtree(workdir, ignore_errors=True)
        return 1

    real_version = version or "current"
    dest_file = os.path.join(out_dir, f"chrome-{real_version}-{spec['tag']}{spec['suffix']}")
    with open(dest_file, "wb") as handle:
        handle.write(sliced)
    size = os.path.getsize(dest_file)
    if not keep:
        shutil.rmtree(workdir, ignore_errors=True)

    print(f"\nSaved BRANDED {spec['container']} slice ({human_size(size)}):")
    print(f"  {os.path.relpath(dest_file)}")
    print("\nNext (consumer dSYM is UUID-matched to this DMG):")
    print(f"  python scripts/fetch_symbols.py {os.path.relpath(dest_file)} --chrome-version {real_version}")
    print(f"  python scripts/derive_milestone.py {os.path.relpath(dest_file)} --symbols _scratch/mac-arm64-syms.txt --name <ver> --json")
    return 0


def default_platform():
    if sys.platform.startswith("win"):
        return "win64"
    if sys.platform.startswith("linux"):
        return "linux"
    return None  # macOS / other host: force an explicit --platform


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Fetch the stock gate-bearing Chrome binary (chrome.dll / chrome ELF) for MV2 derivation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--platform", choices=sorted(PLATFORMS), default=default_platform(),
        help="which gate binary to fetch (default: this host's)",
    )
    parser.add_argument(
        "--channel", choices=CHANNELS, default="stable",
        help="release channel (default: stable)",
    )
    parser.add_argument(
        "--version", metavar="X.Y.Z.W",
        help="pin a version; falls back to the Chrome for Testing archive when "
             "Google no longer serves that build as an installer",
    )
    parser.add_argument(
        "--url", metavar="INSTALLER_URL",
        help="download this installer directly instead of resolving a source; "
             "use it to pin an older win-arm64 build (which has no CfT fallback)",
    )
    parser.add_argument(
        "--branded", action="store_true",
        help="macOS only: fetch the BRANDED universal .dmg and carve the framework "
             "slice (needed for #if GOOGLE_CHROME_BRANDING gates like the Route A "
             "InstallVerifier gate; Chrome for Testing is unbranded). Needs 7-Zip.",
    )
    parser.add_argument(
        "--out", metavar="DIR", default=str(DEFAULT_OUT),
        help="output directory (default: _scratch/)",
    )
    parser.add_argument(
        "--keep", action="store_true",
        help="keep the downloaded installer and extraction tree (default: remove, leave only the binary)",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="print the current version of every platform/channel and exit",
    )
    args = parser.parse_args(argv)
    if not args.list:
        if args.platform is None:
            parser.error("no default platform for this host; pass --platform win64|win|linux")
        if args.version and not all(p.isdigit() for p in args.version.split(".")):
            parser.error(f"--version expects a dotted numeric version, got {args.version!r}")
    return args


def main(argv=None):
    args = parse_args(argv)
    if args.list:
        list_current()
        return 0
    os.makedirs(args.out, exist_ok=True)
    if args.branded:
        if not args.platform or not args.platform.startswith("mac"):
            print("error: --branded is only for mac platforms.", file=sys.stderr)
            return 1
        return fetch_branded_mac(args.platform, args.channel, args.out, args.keep)
    return fetch(args.platform, args.channel, args.version, args.out, args.keep, args.url)


if __name__ == "__main__":
    sys.exit(main())
