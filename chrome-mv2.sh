#!/usr/bin/env bash
# ============================================================================
# Google Chrome Manifest V2 Patcher - cross-platform bash script (Linux + macOS)
#
# One self-contained script for BOTH Unix targets. It re-enables Manifest V2
# extension support by flipping the inlined IsExtensionAffected manifest-version
# checks, dispatching on the target binary's container:
#
#   - ELF (Linux): the `chrome` binary. x86_64 uses the x86 cmp/jg flip.
#       JG_SHORT  0x7F disp8       -> 0xEB disp8        (jmp short, same disp8)
#       JG_NEAR   0x0F 0x8F disp32 -> 0x90 0xE9 disp32  (nop ; jmp near, same disp32)
#       arm64 (aarch64) has no cmp/jg - the gate is cmp w,#2 ; b.gt and the flip
#       rewrites ONLY the B.cond condition GT(0xC) -> AL(0xE), same bcond flip as
#       macOS/Windows arm64.
#   - Mach-O (macOS): the universal (fat) "Google Chrome Framework" inside
#       Google Chrome.app. Only the slice matching this Mac's CPU is patched.
#       x86_64 uses the same short/near flip; arm64 (Apple Silicon) has no
#       cmp/jg - the mv>=3 early-out is a cmp w,#2 ; b.gt, and the flip rewrites
#       ONLY the branch condition GT(0xC) -> AL(0xE), one byte, preserving imm19.
#
# The container is detected from the file magic (ELF vs Mach-O), so the ELF and
# Mach-O flows run wherever bash does; only default install discovery is chosen
# by the host OS. It declines rather than guesses on any layout mismatch.
#
# CODE SIGNING (macOS only): any byte edit invalidates the Mach-O signature; on
# Apple Silicon an invalid/absent signature is killed on launch. After flipping
# a real .app this ad-hoc re-signs INSIDE-OUT, signing every nested bundle and
# Mach-O individually (deepest first, .app last) with
# --preserve-metadata=entitlements,flags so each keeps its own entitlements -
# crucially the Renderer helper's com.apple.security.cs.allow-jit (codesign
# --deep would strip it). The .bak lives OUTSIDE the bundle, in the app-data dir
# keyed by the build UUID; ELF backups are "<file>.bak" keyed by GNU build-id.
#
# CARDINAL RULE: never delete or blank a call and never invent control flow -
# only flip the direction of an existing branch to its EXISTING target.
#
# Usage:
#   Linux:  sudo bash chrome-mv2.sh [patch|restore|check] [path] [--yes] [--quiet]
#   macOS:  bash chrome-mv2.sh [patch|restore|check] [path] [--yes] [--quiet]
#
# Requirements: bash 3.2+ (stock macOS), python3 ONLY for --signatures JSON,
#   od, dd, grep, head, mktemp, cp, mv, awk, sync, plus sha256sum (Linux) or
#   shasum (macOS); codesign (built into macOS) for a launchable .app patch.
# ============================================================================

set -euo pipefail

readonly APP_VERSION="1.4.0"

# ============================================================================
# Embedded signature tables (pre-tokenized so the default path needs no python3
# or JSON parser - stock macOS ships neither a usable python3 nor jq).
#
# Records, one per line, pipe-delimited:
#   M|<milestone name>|<container>
#   S|<site name>|<kind>|<jgRVA>|<jgOff>|<expectedMatches>|<sig hex>
# container: elf | elf-arm64 | macho-x64 | macho-arm64
# kind: short (7F->EB) | near (0F8F->90E9) | bcond (arm64 B.cond GT->AL)
# jgRVA: hex RVA of the jg/b.cond opcode in the reference build (fast-path probe)
# jgOff: byte index of the jump opcode within sig
# sig: hex bytes, jump opcode included at jgOff
#
# Keep in sync with signatures.json (the canonical table). See mv2-reversing.md.
# ============================================================================
readonly EMBEDDED_SIGNATURES='
M|151-linux|elf
S|MV2DeprecationImpactChecker::IsExtensionAffected (shared predicate)|short|0x041900D4|4|1|837E50027F2F554889E5488B8E280200008B413080BE080200
S|ManifestV2Handler::ShouldBlockExtensionInstallation|short|0x09972677|3|1|83FE027F1F83FA01751083F9050F95C283F90A0F95C020D05D
S|ManifestV2Handler::ShouldBlockExtensionEnable|short|0x099726BD|3|1|83FA027F298B493083F801751783F9050F95C283F90A0F95C0
S|StandardManagementPolicyProvider::UserMayInstall (inlined, near jg)|near|0x0A3B7893|3|1|83FA020F8FBE0000008B493083F8010F856402000083F9050F84A900
S|StandardManagementPolicyProvider::MustRemainDisabled (inlined)|short|0x05572994|3|1|83FA027F7A8B493083F80175684531F683F905740583F90A75
E
M|152-linux|elf
S|manifest_v2_util::IsExtensionAffected (free predicate)|short|0x0985B449|3|1|83FF027F1D83FE087718B90A0100000FA3F1730E83FA050F95
S|ManifestV2Handler::IsExtensionAffected / ShouldBlockExtensionEnable (shared body)|short|0x0985B0F4|4|1|837E50027F2F554889E5488B8E280200008B413080BE080200
S|ManifestV2Handler::MaybeReEnableExtension (inlined)|short|0x0985B238|4|1|837B50027F30488B8B280200008B413080BB08020000007508
S|StandardManagementPolicyProvider::UserMayInstall (inlined, near jg)|near|0x0A256BAA|4|1|837B50020F8FD1000000488B8B280200008B413080BB080200000075
S|StandardManagementPolicyProvider::MustRemainDisabled (inlined, near jg)|near|0x0599A69A|4|1|837E50020F8F8E000000498B8E280200008B41304180BE0802000000
E
M|151-linux-arm64|elf-arm64
S|ManifestV2Handler::ShouldBlockExtensionInstallation|bcond|0x05E6C0CC|4|1|3F0800716C0100545F040071A10000547F14007164184A7AE0079F1AC0035FD6
S|StandardManagementPolicyProvider::UserMayInstall (inlined)|bcond|0x06086804|4|1|5F0900710C010054293140B91F050071611300543F150071600000543F290071
S|StandardManagementPolicyProvider::UserMayInstall (inlined, 2nd call site)|bcond|0x06A71584|4|1|5F0900710C010054293140B91F050071A11300543F150071600000543F290071
S|MV2DeprecationImpactChecker::IsExtensionAffected (shared predicate; OnExtensionSystemReady / MaybeReEnableExtension / ShouldBlockExtensionEnable call it out-of-line)|bcond|0x0A525764|4|1|1F0900710C020054291441F92A204839283140B98A000037296940B93F050071
S|StandardManagementPolicyProvider::MustRemainDisabled (inlined)|bcond|0x0A69570C|4|1|5F090071EC030054293140B91F050071010300543F150071F4031F2A60000054
E
M|152-linux-arm64|elf-arm64
S|ManifestV2Handler::MaybeReEnableExtension (shared body)|bcond|0x05D64DD8|4|2|1F0900712C020054691641F96A224839283140B98A000037296940B93F050071
S|ManifestV2Handler::IsExtensionAffected / ShouldBlockExtensionEnable (shared body)|bcond|0x05D64F9C|4|1|1F0900710C020054091441F90A204839283140B98A000037296940B93F050071
S|StandardManagementPolicyProvider::MustRemainDisabled / UserMayInstall (shared body)|bcond|0x05F78874|4|2|1F0900718C010054891641F98A224839283140B98A000037296940B93F050071
S|ManifestV2Handler::OnExtensionSystemReady (shared body)|bcond|0x0696E3C8|4|2|3F090071EC4A0054091541F90A214839283140B98A000037296940B93F050071
E
M|151-macos-x64|macho-x64
S|StandardManagementPolicyProvider::MustRemainDisabled|short|0x01B652F7|3|1|83FA027F5B8B493083F80175494531F683F905740583F90A75
S|ManifestV2Handler::OnExtensionSystemReady|short|0x030822AA|4|1|837950027F2D488B91280200008B423080B90802000000750C
S|ManifestV2Handler::ShouldBlockExtensionEnable|short|0x04727A9D|3|1|83FA027F298B493083F801751783F9050F95C283F90A0F95C0
S|ManifestV2Handler::IsExtensionAffected|short|0x071364A4|4|1|837E50027F2F554889E5488B8E280200008B413080BE080200
S|ManifestV2Handler::ShouldBlockExtensionInstallation|short|0x071364F7|3|1|83FE027F1F83FA01751083F9050F95C283F90A0F95C020D05D
S|ManifestV2Handler::MaybeReEnableExtension|short|0x07136608|4|1|837B50027F30488B8B280200008B413080BB08020000007508
S|StandardManagementPolicyProvider::UserMayInstall|near|0x07B4CFF9|3|1|83FA020F8FA40000008B493083F8010F850F02000083F9050F848F00
E
M|151-macos-arm64|macho-arm64
S|ManifestV2Handler::OnExtensionSystemReady|bcond|0x0178A5E8|4|1|1F090071AC0100542A1541F9483140B929214839C9000037496940B93F050071
S|StandardManagementPolicyProvider::MustRemainDisabled|bcond|0x021EFD80|4|1|5F0900716C040054293140B91F05007181030054140080523F15007160000054
S|ManifestV2Handler::ShouldBlockExtensionEnable|bcond|0x03ED7910|4|1|5F090071CC010054293140B91F050071E10000543F15007124194A7AE0079F1A
S|ManifestV2Handler::IsExtensionAffected|bcond|0x0642852C|4|1|1F090071CC010054291441F9283140B92A204839CA000037296940B93F050071
S|ManifestV2Handler::ShouldBlockExtensionInstallation|bcond|0x06428570|4|1|3F0800716C0100545F040071A10000547F14007164184A7AE0079F1AC0035FD6
S|ManifestV2Handler::MaybeReEnableExtension|bcond|0x064286A8|4|1|1F090071AC010054691641F9283140B96A224839CA000037296940B93F050071
S|StandardManagementPolicyProvider::UserMayInstall|bcond|0x06DB8584|4|1|5F090071EC000054293140B91F050071210F00543F15007124194A7AC1060054
E
M|152-macos-x64|macho-x64
S|StandardManagementPolicyProvider::MustRemainDisabled|short|0x01BA0A91|4|1|837E50027F6F498B8E280200008B41304180BE080200000075
S|ManifestV2Handler::OnExtensionSystemReady|short|0x0312B1FA|4|1|837950027F2D488B91280200008B423080B90802000000750C
S|ManifestV2Handler::IsExtensionAffected|short|0x048BB6E4|4|1|837E50027F2F554889E5488B8E280200008B413080BE080200
S|ManifestV2Handler::ShouldBlockExtensionInstallation|short|0x075489B8|4|1|837B50027F30488B8B280200008B413080BB08020000007508
S|ManifestV2Handler::ShouldBlockExtensionInstallation (2)|short|0x07548BB9|3|1|83FF027F1D83FE087718B90A0100000FA3F1730E83FA050F95
S|StandardManagementPolicyProvider::UserMayInstall|near|0x07F56A10|4|1|837B50020F8FB7000000488B8B280200008B413080BB080200000075
E
M|152-macos-arm64|macho-arm64
S|StandardManagementPolicyProvider::MustRemainDisabled|bcond|0x02218740|4|1|1F090071EC040054891641F9283140B98A2248398A000037296940B93F050071
S|ManifestV2Handler::OnExtensionSystemReady|bcond|0x0320635C|4|1|1F090071AC0100542A1541F9483140B929214839C9000037496940B93F050071
S|ManifestV2Handler::IsExtensionAffected|bcond|0x03FFBD84|4|1|1F090071CC010054291441F9283140B92A204839CA000037296940B93F050071
S|ManifestV2Handler::ShouldBlockExtensionInstallation / StandardManagementPolicyProvider::UserMayInstall (shared body)|bcond|0x066F0E38|4|2|1F090071AC010054691641F9283140B96A224839CA000037296940B93F050071
E
'

# Runtime tables (parallel indexed arrays; bash-3.2 safe - no assoc arrays or
# namerefs). ALL_SITES holds every site prefixed with its milestone index so a
# milestone's sites are recovered by filtering, avoiding dynamic array names.
MILESTONE_NAMES=()
MILESTONE_CONTAINERS=()
ALL_SITES=()          # "idx|name|kind|jgRVA|jgOff|expectedMatches|sig"
NUM_MILESTONES=0

# ============================================================================
# Console colour + tags
# ============================================================================
C_RESET="" C_RED="" C_GRN="" C_YEL="" C_CYN="" C_DIM="" C_BOLD=""
TAG_OK="" TAG_ERR="" TAG_INFO="" TAG_WARN="" TAG_SUCCESS="" TAG_WARNING=""

init_colors() {
    local vt=false
    if [[ -t 1 ]]; then vt=true; fi
    if [[ -n "${FORCE_COLOR:-}" ]]; then vt=true; fi
    if [[ -n "${NO_COLOR:-}" ]]; then vt=false; fi
    if $vt; then
        C_RESET=$'\e[0m'  C_RED=$'\e[91m'  C_GRN=$'\e[92m'
        C_YEL=$'\e[93m'   C_CYN=$'\e[96m'  C_DIM=$'\e[90m'  C_BOLD=$'\e[1m'
    fi
    TAG_OK="${C_GRN}[+]${C_RESET}"
    TAG_ERR="${C_RED}[-]${C_RESET}"
    TAG_INFO="${C_CYN}[*]${C_RESET}"
    TAG_WARN="${C_YEL}[!]${C_RESET}"
    TAG_SUCCESS="${C_BOLD}${C_GRN}[SUCCESS]${C_RESET}"
    TAG_WARNING="${C_BOLD}${C_YEL}[WARNING]${C_RESET}"
}

infof()    { echo "${TAG_INFO} $*"; }
okf()      { echo "${TAG_OK} $*"; }
warnf()    { echo "${TAG_WARN} $*"; }
errf()     { echo "${TAG_ERR} $*"; }
successf() { echo "${TAG_SUCCESS} $*"; }
rule()     { echo "${C_CYN}==========================================================${C_RESET}"; }

banner() {
    rule
    echo "${C_BOLD}      Google Chrome Manifest V2 Patcher (bash, Unix)       ${C_RESET}"
    echo "${C_DIM}                    v${APP_VERSION}                       ${C_RESET}"
    rule
}

# ============================================================================
# Binary read helpers - LE/BE integers and hex from a file at an offset.
#
# Each od/tr launch costs ~100 ms under Windows git-bash (fork emulation), and a
# single parse issues hundreds of reads, so a file that fits is slurped ONCE into
# an uppercase-hex cache (_HC_HEX) and every read slices that string in pure bash.
# Files larger than HEXCACHE_CAP (the ~200 MB real Chrome binary) keep the
# streaming od path, which never materializes the whole file.
#
# The cache MUST be primed by _hexcache_load in PARENT scope (read helpers run
# inside $(...) command-substitution subshells, whose variable writes are lost);
# subshells then inherit and slice _HC_HEX read-only. Read-heavy functions call
# _hexcache_load at their top; any writer calls _hexcache_flush so a stale slice
# is never returned. An un-primed or big-file read falls back to a single od.
# ============================================================================
HEXCACHE_CAP=$(( 16 * 1024 * 1024 ))
_HC_FILE=""; _HC_HEX=""; _HC_BIG=0
_hexcache_flush() { _HC_FILE=""; _HC_HEX=""; _HC_BIG=0; }
_hexcache_load() {
    local file="$1"
    [[ "$file" == "$_HC_FILE" ]] && return 0
    local sz; sz=$(file_size "$file")
    _HC_FILE="$file"; _HC_HEX=""; _HC_BIG=0
    if (( sz > 0 && sz <= HEXCACHE_CAP )); then
        _HC_HEX=$(od -A n -v -t x1 "$file" | tr -d ' \n' | tr 'a-f' 'A-F')
    else
        _HC_BIG=1
    fi
    return 0
}
# Uppercase hex for N bytes at OFF: slice the primed cache, else a single od read.
# Never primes the cache (that must happen in parent scope - see above).
_read_hex() {
    if [[ "$1" == "$_HC_FILE" && "$_HC_BIG" == "0" ]]; then
        printf '%s' "${_HC_HEX:$(( $2 * 2 )):$(( $3 * 2 ))}"
    else
        od -A n -v -t x1 -j "$2" -N "$3" "$1" | tr -d ' \n' | tr 'a-f' 'A-F'
    fi
}
read_bytes_hex() { _read_hex "$1" "$2" "$3"; }
read_byte()   { local b; b=$(_read_hex "$1" "$2" 1); echo $(( 16#$b )); }
read_u16_le() { local b; b=$(_read_hex "$1" "$2" 2); echo $(( 16#${b:2:2}${b:0:2} )); }
read_u32_le() { local b; b=$(_read_hex "$1" "$2" 4); echo $(( 16#${b:6:2}${b:4:2}${b:2:2}${b:0:2} )); }
read_u32_be() { local b; b=$(_read_hex "$1" "$2" 4); echo $(( 16#${b:0:2}${b:2:2}${b:4:2}${b:6:2} )); }
read_u64_le() { local b; b=$(_read_hex "$1" "$2" 8); echo $(( 16#${b:14:2}${b:12:2}${b:10:2}${b:8:2}${b:6:2}${b:4:2}${b:2:2}${b:0:2} )); }
read_u64_be() { local b; b=$(_read_hex "$1" "$2" 8); echo $(( 16#${b:0:2}${b:2:2}${b:4:2}${b:6:2}${b:8:2}${b:10:2}${b:12:2}${b:14:2} )); }

# GNU coreutils (Linux + Windows git-bash) answer `stat -c%s` first, so try it
# first to spend one process instead of two; macOS BSD stat falls through to -f%z.
file_size() { stat -c%s "$1" 2>/dev/null || stat -f%z "$1" 2>/dev/null; }
# GNU/BSD checksum tools prefix the line with '\' when the path contains a
# backslash; strip it so hash comparisons hold for Windows-style paths too.
# Parse the first field in-shell (no awk) to spend one process, not two.
file_sha256() { local out; out=$(shasum -a 256 -- "$1" 2>/dev/null) || out=$(sha256sum -- "$1"); out="${out%% *}"; echo "${out#\\}"; }

range_within_file() {
    local offset="$1" count="$2" size="$3"
    (( offset >= 0 && count >= 0 && offset <= size && count <= size - offset ))
}

# Container of a file from its magic: "elf", "macho" (thin or fat), or "".
detect_container_kind() {
    local m; m=$(od -A n -t x1 -N 4 -- "$1" 2>/dev/null | tr -d ' \n' | tr 'A-F' 'a-f')
    case "$m" in
        7f454c46) echo "elf" ;;
        cffaedfe|cefaedfe|feedfacf|feedface|cafebabe|cafebabf|bebafeca|bfbafeca) echo "macho" ;;
        *) echo "" ;;
    esac
}

# True if $1 begins with a Mach-O (thin or fat) magic. Used to skip non-code
# files when enumerating re-sign targets, so codesign is never handed a blob.
is_macho() { [[ "$(detect_container_kind "$1")" == "macho" ]]; }

# ============================================================================
# Signature loading. Default: the pre-tokenized EMBEDDED_SIGNATURES (no python3
# or JSON parser needed). An explicit --signatures FILE, or a signatures.json
# beside the script, is JSON and is tokenized via python3 into the same records.
# ============================================================================
readonly SIGNATURES_FILE="signatures.json"
SIGNATURES_OVERRIDE=""

get_signatures_path() {
    if [[ -n "$SIGNATURES_OVERRIDE" ]]; then
        if [[ ! -f "$SIGNATURES_OVERRIDE" ]]; then return 2; fi
        echo "$SIGNATURES_OVERRIDE"; return 0
    fi
    local script_dir
    script_dir=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
    if [[ -f "${script_dir}/${SIGNATURES_FILE}" ]]; then
        echo "${script_dir}/${SIGNATURES_FILE}"; return 0
    fi
    return 1
}

# JSON -> pipe-tokenized records (M|.. / S|..). Keeps only the containers THIS
# script patches (elf + elf-arm64 + macho-x64/arm64), skipping the shared table's
# pe/pe32/pe-arm64 Windows milestones. Validates kinds and the stock opcode at jgOff.
# Requires python3.
json_to_tokens() {
    python3 -c '
import json, re, sys
def clean(v, label):
    if not isinstance(v, str) or not v.strip() or any(c in v for c in "\r\n\t|"):
        raise ValueError(label + " empty or has a reserved character")
    return v
doc = json.load(sys.stdin)
ms = doc.get("milestones")
if not isinstance(ms, list) or not ms:
    raise ValueError("no milestones")
seen = set()
for m in ms:
    name = clean(m.get("name"), "milestone name")
    if name in seen: raise ValueError("duplicate milestone " + name)
    seen.add(name)
    container = m.get("container")
    if container not in ("elf", "elf-arm64", "macho-x64", "macho-arm64"):
        continue  # this script patches ELF + Mach-O; skip pe/pe32/pe-arm64
    sites = m.get("sites")
    if not isinstance(sites, list) or not sites:
        raise ValueError("milestone %s has no sites" % name)
    print("M|%s|%s" % (name, container))
    sn = set()
    for s in sites:
        snm = clean(s.get("name"), "site name")
        if snm in sn: raise ValueError("dup site %s in %s" % (snm, name))
        sn.add(snm)
        kind = s.get("kind")
        if kind not in ("short", "near", "bcond"):
            raise ValueError("bad kind in %s/%s" % (name, snm))
        # x86_64 gates (elf, macho-x64) are cmp/jg (short/near); the arm64 gates
        # (elf-arm64, macho-arm64) are the cmp w,#2 ; b.gt bcond flip. Reject a
        # kind that does not match the container architecture.
        if kind == "bcond" and container in ("elf", "macho-x64"):
            raise ValueError("x86_64 milestone %s has an arm64 bcond site %s" % (name, snm))
        if kind != "bcond" and container in ("elf-arm64", "macho-arm64"):
            raise ValueError("arm64 milestone %s has a non-bcond site %s" % (name, snm))
        rva = s.get("jgRVA")
        if not isinstance(rva, str) or not re.fullmatch(r"0[xX][0-9A-Fa-f]+", rva):
            raise ValueError("bad jgRVA in %s/%s" % (name, snm))
        off = s.get("jgOff"); exp = s.get("expectedMatches"); sig = s.get("sig")
        if not isinstance(off, int) or isinstance(off, bool) or off < 0:
            raise ValueError("bad jgOff in %s/%s" % (name, snm))
        if not isinstance(exp, int) or isinstance(exp, bool) or exp < 1:
            raise ValueError("bad expectedMatches in %s/%s" % (name, snm))
        if not isinstance(sig, str) or not sig or len(sig) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", sig):
            raise ValueError("bad sig in %s/%s" % (name, snm))
        raw = bytes.fromhex(sig)
        need = {"short": 2, "near": 6, "bcond": 4}[kind]
        if off + need > len(raw):
            raise ValueError("jump past sig in %s/%s" % (name, snm))
        if kind == "short" and raw[off] != 0x7F:
            raise ValueError("jgOff not 7F in %s/%s" % (name, snm))
        if kind == "near" and raw[off:off+2] != b"\x0f\x8f":
            raise ValueError("jgOff not 0F8F in %s/%s" % (name, snm))
        if kind == "bcond":
            w = int.from_bytes(raw[off:off+4], "little")
            if (w & 0xFF000010) != 0x54000000 or (w & 0xF) != 0x0C:
                raise ValueError("jgOff not a stock b.gt (GT) in %s/%s" % (name, snm))
        print("S|%s|%s|%s|%d|%d|%s" % (snm, kind, rva, off, exp, sig.upper()))
    print("E")
' 2>&1
}

populate_from_tokens() {
    MILESTONE_NAMES=(); MILESTONE_CONTAINERS=(); ALL_SITES=(); NUM_MILESTONES=0
    local idx=-1 rec f1 f2 f3 f4 f5 f6
    while IFS='|' read -r rec f1 f2 f3 f4 f5 f6; do
        # Strip any trailing CR from every field: a JSON stream tokenized by a
        # Windows python emits CRLF, and a stray \r would corrupt a container or
        # sig comparison. A no-op on the LF embedded tables / on Unix hosts.
        rec="${rec%$'\r'}"; f1="${f1%$'\r'}"; f2="${f2%$'\r'}"
        f3="${f3%$'\r'}"; f4="${f4%$'\r'}"; f5="${f5%$'\r'}"; f6="${f6%$'\r'}"
        case "$rec" in
            M)
                idx=$(( idx + 1 ))
                MILESTONE_NAMES+=("$f1")
                MILESTONE_CONTAINERS+=("$f2")
                ;;
            S)
                # store "idx|name|kind|jgRVA|jgOff|expected|sig"
                ALL_SITES+=("${idx}|${f1}|${f2}|${f3}|${f4}|${f5}|${f6}")
                ;;
        esac
    done
    NUM_MILESTONES=$(( idx + 1 ))
    (( NUM_MILESTONES > 0 ))
}

load_milestones() {
    local sig_path sig_status=0 tokens src_label
    if sig_path=$(get_signatures_path); then
        if [[ ! -r "$sig_path" ]]; then errf "Signature file is not readable: ${sig_path}"; return 1; fi
        if ! command -v python3 >/dev/null 2>&1; then
            errf "An external signatures.json needs python3, which was not found."
            echo "    Remove ${sig_path} to use the built-in tables, or install python3."
            return 1
        fi
        if ! tokens=$(json_to_tokens < "$sig_path"); then
            errf "Failed to parse ${sig_path}:"; printf '    %s\n' "$tokens"; return 1
        fi
        src_label="$sig_path"
    else
        sig_status=$?
        if (( sig_status == 2 )); then
            errf "Signature file does not exist: ${SIGNATURES_OVERRIDE}"; return 1
        fi
        tokens="$EMBEDDED_SIGNATURES"
        src_label="embedded tables"
    fi

    # Feed tokens via a here-string so populate runs in THIS shell (a pipe would
    # run it in a subshell and lose the arrays).
    if ! populate_from_tokens <<< "$tokens"; then
        errf "No usable ELF/Mach-O milestones from ${src_label}."
        return 1
    fi
    okf "Loaded ${NUM_MILESTONES} known Chrome version(s)."
    return 0
}

# Sites of milestone index $1 -> "name|kind|jgRVA|jgOff|expected|sig" per line.
sites_of() {
    local want="$1" spec
    for spec in "${ALL_SITES[@]}"; do
        if [[ "${spec%%|*}" == "$want" ]]; then echo "${spec#*|}"; fi
    done
}

# ============================================================================
# Binary parsers. Both containers populate the SAME per-"slice" parallel arrays
# so the matching engine is container-agnostic:
#   - Mach-O: one SLICE_* entry per CPU slice (x86_64 / arm64).
#   - ELF: a single SLICE_* entry with container "elf".
# section_64.offset is ALREADY the slice-relative file offset for Mach-O (NO
# vmaddr delta - the opposite of ELF, whose sh_offset is an absolute file off).
# ============================================================================
MH_MAGIC_64=4277009103          # 0xFEEDFACF (thin 64-bit, little-endian on disk)
FAT_MAGIC=3405691582            # 0xCAFEBABE (fat, big-endian, 32-bit fat_arch)
FAT_MAGIC_64=3405691583         # 0xCAFEBABF (fat, big-endian, 64-bit fat_arch)
CPU_X86_64=16777223             # 0x01000007
CPU_ARM64=16777228              # 0x0100000C
LC_SEGMENT_64=25                # 0x19
LC_UUID=27                      # 0x1B

SLICE_CONTAINER=()
SLICE_BASE=()
SLICE_SIZE=()
SLICE_TVADDR=()
SLICE_TRAW=()
SLICE_TSIZE=()
SLICE_UUID=()
NUM_SLICES=0
TARGET_CONTAINER=""             # "elf" | "macho", set by parse_target

# Parse one thin Mach-O slice at file offset $2; append to SLICE_* on success.
parse_thin_slice() {
    local file="$1" base="$2" declared_size="${3:-0}"
    local fsize; fsize=$(file_size "$file")
    if ! range_within_file "$base" 32 "$fsize"; then return 1; fi
    local magic; magic=$(read_u32_le "$file" "$base")
    if (( magic != MH_MAGIC_64 )); then return 1; fi   # skip 32-bit / foreign slice

    local cputype ncmds container
    cputype=$(read_u32_le "$file" $(( base + 4 )))
    ncmds=$(read_u32_le "$file" $(( base + 16 )))
    if (( cputype == CPU_X86_64 )); then container="macho-x64"
    elif (( cputype == CPU_ARM64 )); then container="macho-arm64"
    else return 1; fi

    local p=$(( base + 32 )) i cmd cmdsize
    local t_addr="" t_off="" t_size="" uuid=""
    for (( i = 0; i < ncmds; i++ )); do
        if ! range_within_file "$p" 8 "$fsize"; then return 1; fi
        cmd=$(read_u32_le "$file" "$p")
        cmdsize=$(read_u32_le "$file" $(( p + 4 )))
        if (( cmdsize < 8 )) || ! range_within_file "$p" "$cmdsize" "$fsize"; then return 1; fi
        if (( cmd == LC_SEGMENT_64 )); then
            local segname7; segname7=$(read_bytes_hex "$file" $(( p + 8 )) 7)
            if [[ "$segname7" == "5F5F5445585400" ]]; then   # "__TEXT\0"
                local nsects; nsects=$(read_u32_le "$file" $(( p + 64 )))
                local sec=$(( p + 72 )) s sname7
                for (( s = 0; s < nsects; s++ )); do
                    sname7=$(read_bytes_hex "$file" "$sec" 7)
                    if [[ "$sname7" == "5F5F7465787400" ]]; then   # "__text\0"
                        t_addr=$(read_u64_le "$file" $(( sec + 32 )))
                        t_size=$(read_u64_le "$file" $(( sec + 40 )))
                        t_off=$(read_u32_le "$file" $(( sec + 48 )))
                    fi
                    sec=$(( sec + 80 ))
                done
            fi
        elif (( cmd == LC_UUID )); then
            uuid=$(read_bytes_hex "$file" $(( p + 8 )) 16)
        fi
        p=$(( p + cmdsize ))
    done

    if [[ -z "$t_addr" ]]; then return 1; fi
    local raw=$(( base + t_off ))
    if ! range_within_file "$raw" "$t_size" "$fsize"; then return 1; fi

    SLICE_CONTAINER+=("$container")
    SLICE_BASE+=("$base")
    SLICE_SIZE+=("$declared_size")
    SLICE_TVADDR+=("$t_addr")
    SLICE_TRAW+=("$raw")
    SLICE_TSIZE+=("$t_size")
    SLICE_UUID+=("$uuid")
    NUM_SLICES=$(( NUM_SLICES + 1 ))
    return 0
}

parse_macho() {
    local file="$1"
    _hexcache_load "$file"   # prime the byte cache (big frameworks fall back to od)
    SLICE_CONTAINER=(); SLICE_BASE=(); SLICE_SIZE=()
    SLICE_TVADDR=(); SLICE_TRAW=(); SLICE_TSIZE=(); SLICE_UUID=()
    NUM_SLICES=0

    local fsize; fsize=$(file_size "$file")
    if (( fsize < 32 )); then errf "That doesn't look like a Chrome app file."; return 1; fi

    local be le
    be=$(read_u32_be "$file" 0)
    le=$(read_u32_le "$file" 0)

    if (( be == FAT_MAGIC || be == FAT_MAGIC_64 )); then
        local is64=0; (( be == FAT_MAGIC_64 )) && is64=1
        local nfat; nfat=$(read_u32_be "$file" 4)
        if (( nfat < 1 || nfat > 32 )); then errf "That doesn't look like a valid Chrome app file."; return 1; fi
        local entry off i soff ssize
        (( is64 )) && entry=32 || entry=20
        off=8
        for (( i = 0; i < nfat; i++ )); do
            if ! range_within_file "$off" "$entry" "$fsize"; then break; fi
            if (( is64 )); then
                soff=$(read_u64_be "$file" $(( off + 8 )))
                ssize=$(read_u64_be "$file" $(( off + 16 )))
            else
                soff=$(read_u32_be "$file" $(( off + 8 )))
                ssize=$(read_u32_be "$file" $(( off + 12 )))
            fi
            off=$(( off + entry ))
            parse_thin_slice "$file" "$soff" "$ssize" || true   # skip slices we do not handle
        done
    elif (( le == MH_MAGIC_64 )); then
        parse_thin_slice "$file" 0 "$fsize" || true
    else
        errf "That doesn't look like a Chrome app file."
        return 1
    fi

    if (( NUM_SLICES == 0 )); then
        errf "This Chrome app isn't a supported type."
        return 1
    fi

    okf "Read the Chrome app."
    return 0
}

# ---- ELF64 -----------------------------------------------------------------
# parse_elf locates .text and also synthesizes a single SLICE_* entry (container
# "elf" for x86_64, "elf-arm64" for aarch64, chosen from e_machine) so the shared
# slice engine can probe/flip it. get_elf_build_id reads the GNU build-id (the ELF
# backup identity, stable across the flip).
ELF_SHOFF=0 ELF_SHENTSIZE=0 ELF_SHNUM=0 ELF_SHSTRNDX=0 ELF_STROFF=0 ELF_STRSIZE=0
TEXT_VADDR=0 TEXT_RAW=0 TEXT_SIZE=0

validate_elf_section_table() {
    local file="$1" fsize="$2"
    ELF_SHOFF=$(read_u64_le "$file" $((0x28)))
    ELF_SHENTSIZE=$(read_u16_le "$file" $((0x3A)))
    ELF_SHNUM=$(read_u16_le "$file" $((0x3C)))
    ELF_SHSTRNDX=$(read_u16_le "$file" $((0x3E)))
    # Chrome uses normal ELF64 section counts. Decline the extended-index forms.
    if (( ELF_SHOFF < 64 || ELF_SHOFF > fsize || ELF_SHNUM == 0 || ELF_SHSTRNDX == 0xFFFF )); then return 1; fi
    if (( ELF_SHENTSIZE < 64 || ELF_SHSTRNDX >= ELF_SHNUM )); then return 1; fi
    if (( ELF_SHNUM > (fsize - ELF_SHOFF) / ELF_SHENTSIZE )); then return 1; fi
    local strhdr_off=$(( ELF_SHOFF + ELF_SHSTRNDX * ELF_SHENTSIZE ))
    ELF_STROFF=$(read_u64_le "$file" $(( strhdr_off + 0x18 )))
    ELF_STRSIZE=$(read_u64_le "$file" $(( strhdr_off + 0x20 )))
    range_within_file "$ELF_STROFF" "$ELF_STRSIZE" "$fsize"
}

get_elf_build_id() {
    local file="$1" fsize
    _hexcache_load "$file"   # prime the byte cache for the reads below
    fsize=$(file_size "$file")
    if (( fsize < 64 )); then echo ""; return 1; fi
    local magic; magic=$(read_bytes_hex "$file" 0 4)
    if [[ "$magic" != "7F454C46" ]]; then echo ""; return 1; fi
    local ei_class ei_data
    ei_class=$(read_byte "$file" 4); ei_data=$(read_byte "$file" 5)
    if (( ei_class != 2 || ei_data != 1 )); then echo ""; return 1; fi
    if ! validate_elf_section_table "$file" "$fsize"; then echo ""; return 1; fi

    local i sh_off name_off sec_name sec_off sec_size
    for (( i = 0; i < ELF_SHNUM; i++ )); do
        sh_off=$(( ELF_SHOFF + i * ELF_SHENTSIZE ))
        name_off=$(read_u32_le "$file" "$sh_off")
        (( name_off < ELF_STRSIZE )) || continue
        # section name via the byte cache (no dd/tr/head): read a window, keep the
        # bytes up to the NUL terminator, compare to the hex of ".note.gnu.build-id".
        sec_name=$(read_bytes_hex "$file" $(( ELF_STROFF + name_off )) 24); sec_name="${sec_name%%00*}"
        if [[ "$sec_name" == "2E6E6F74652E676E752E6275696C642D6964" ]]; then
            sec_off=$(read_u64_le "$file" $(( sh_off + 0x18 )))
            sec_size=$(read_u64_le "$file" $(( sh_off + 0x20 )))
            if (( sec_size < 16 )) || ! range_within_file "$sec_off" "$sec_size" "$fsize"; then echo ""; return 1; fi
            local namesz descsz note_type
            namesz=$(read_u32_le "$file" "$sec_off")
            descsz=$(read_u32_le "$file" $(( sec_off + 4 )))
            note_type=$(read_u32_le "$file" $(( sec_off + 8 )))
            if (( note_type == 3 && namesz == 4 && descsz > 0 && descsz <= 64 )); then
                local note_name; note_name=$(read_bytes_hex "$file" $(( sec_off + 12 )) 4)
                [[ "$note_name" == "474E5500" ]] || break
                local name_padded=$(( (namesz + 3) / 4 * 4 ))
                local desc_off=$(( sec_off + 12 + name_padded ))
                if ! range_within_file "$desc_off" "$descsz" "$fsize" || (( desc_off + descsz > sec_off + sec_size )); then echo ""; return 1; fi
                read_bytes_hex "$file" "$desc_off" "$descsz"; return 0
            fi
            break
        fi
    done
    echo ""; return 1
}

parse_elf() {
    local file="$1" fsize
    _hexcache_load "$file"   # prime the byte cache for the reads below
    fsize=$(file_size "$file")
    if (( fsize < 64 )); then errf "That doesn't look like a Chrome file."; return 1; fi
    local magic; magic=$(read_bytes_hex "$file" 0 4)
    if [[ "$magic" != "7F454C46" ]]; then errf "That doesn't look like a Chrome file."; return 1; fi
    local ei_class ei_data
    ei_class=$(read_byte "$file" 4); ei_data=$(read_byte "$file" 5)
    if (( ei_class != 2 )); then errf "That's not a 64-bit Chrome file."; return 1; fi
    if (( ei_data != 1 )); then errf "That doesn't look like a valid Chrome file."; return 1; fi
    # e_machine (0x12, u16): 0x3E x86_64 (cmp/jg gates, container "elf") vs 0xB7
    # aarch64 (cmp w,#2 ; b.gt gates, container "elf-arm64"). The tag routes the
    # slice to the right milestone table; the flip engine dispatches on site kind.
    local e_machine slice_container="elf"
    e_machine=$(read_u16_le "$file" $((0x12)))
    if (( e_machine == 0xB7 )); then slice_container="elf-arm64"; fi
    if ! validate_elf_section_table "$file" "$fsize"; then
        errf "That doesn't look like a valid Chrome file."; return 1
    fi

    local i sh_off name_off sec_name
    TEXT_VADDR=0; TEXT_RAW=0; TEXT_SIZE=0
    for (( i = 0; i < ELF_SHNUM; i++ )); do
        sh_off=$(( ELF_SHOFF + i * ELF_SHENTSIZE ))
        name_off=$(read_u32_le "$file" "$sh_off")
        (( name_off < ELF_STRSIZE )) || continue
        # section name via the byte cache (no dd/tr/head): keep bytes up to the NUL
        # terminator and compare to the hex of ".text".
        sec_name=$(read_bytes_hex "$file" $(( ELF_STROFF + name_off )) 8); sec_name="${sec_name%%00*}"
        if [[ "$sec_name" == "2E74657874" ]]; then
            TEXT_VADDR=$(read_u64_le "$file" $(( sh_off + 0x10 )))
            TEXT_RAW=$(read_u64_le "$file" $(( sh_off + 0x18 )))
            TEXT_SIZE=$(read_u64_le "$file" $(( sh_off + 0x20 )))
            break
        fi
    done
    if (( TEXT_SIZE == 0 )); then errf "That doesn't look like a valid Chrome file (missing code section)."; return 1; fi
    if ! range_within_file "$TEXT_RAW" "$TEXT_SIZE" "$fsize"; then
        errf "That doesn't look like a valid Chrome file."; return 1
    fi

    # Model the ELF as a single "slice" so the shared engine drives it.
    SLICE_CONTAINER=("$slice_container"); SLICE_BASE=(0); SLICE_SIZE=("$fsize")
    SLICE_TVADDR=("$TEXT_VADDR"); SLICE_TRAW=("$TEXT_RAW"); SLICE_TSIZE=("$TEXT_SIZE")
    SLICE_UUID=(""); NUM_SLICES=1

    okf "Read the Chrome file."
    return 0
}

# Dispatch by file magic; sets TARGET_CONTAINER and fills SLICE_*.
parse_target() {
    local file="$1" kind
    kind=$(detect_container_kind "$file")
    case "$kind" in
        elf)   TARGET_CONTAINER="elf";   parse_elf "$file" ;;
        macho) TARGET_CONTAINER="macho"; parse_macho "$file" ;;
        *)     errf "That doesn't look like a Chrome file: ${file}"; return 1 ;;
    esac
}

# ============================================================================
# Signature matching engine. Exact on every byte except the masked jump:
#   short : jg_off in {7F,EB}; jg_off+1 (disp8) wild
#   near  : jg_off,+1 the pair {0F 8F | 90 E9}; +2..+5 (disp32) wild
#   bcond : the 4-byte LE word at jg_off - opcode 0x54 + bit4=0 fixed, cond in
#           {0xC stock, 0xE patched}, imm19 wild (bit-level, not byte-level)
# ============================================================================
sig_matches_at() {
    local file="$1" file_offset="$2" sig_hex="$3" kind="$4" jg_off="$5"
    local sig_len=$(( ${#sig_hex} / 2 ))
    local actual; actual=$(read_bytes_hex "$file" "$file_offset" "$sig_len")
    local sig_upper; sig_upper=$(echo "$sig_hex" | tr 'a-f' 'A-F')

    if [[ "$kind" == "bcond" ]]; then
        # validate the whole branch word first (little-endian)
        local b0 b1 b2 b3 word cond
        b0=$(( 16#${actual:$(( jg_off*2 )):2} ))
        b1=$(( 16#${actual:$(( (jg_off+1)*2 )):2} ))
        b2=$(( 16#${actual:$(( (jg_off+2)*2 )):2} ))
        b3=$(( 16#${actual:$(( (jg_off+3)*2 )):2} ))
        word=$(( b0 | (b1<<8) | (b2<<16) | (b3<<24) ))
        if (( (word & 0xFF000010) != 0x54000000 )); then return 1; fi
        cond=$(( word & 0xF ))
        if (( cond != 0x0C && cond != 0x0E )); then return 1; fi
    fi

    local i byte_idx sig_byte act_byte act_pair
    for (( i = 0; i < ${#sig_upper}; i += 2 )); do
        byte_idx=$(( i / 2 ))
        sig_byte="${sig_upper:$i:2}"
        act_byte="${actual:$i:2}"
        if [[ "$kind" == "short" ]]; then
            if (( byte_idx == jg_off )); then
                if [[ "$act_byte" != "7F" && "$act_byte" != "EB" ]]; then return 1; fi
                continue
            elif (( byte_idx == jg_off + 1 )); then continue; fi
        elif [[ "$kind" == "near" ]]; then
            if (( byte_idx == jg_off )); then
                act_pair="${actual:$i:4}"
                if [[ "$act_pair" != "0F8F" && "$act_pair" != "90E9" ]]; then return 1; fi
                continue
            elif (( byte_idx >= jg_off + 1 && byte_idx <= jg_off + 5 )); then continue; fi
        else  # bcond: the 4 word bytes are handled above
            if (( byte_idx >= jg_off && byte_idx <= jg_off + 3 )); then continue; fi
        fi
        if [[ "$sig_byte" != "$act_byte" ]]; then return 1; fi
    done
    return 0
}

# Longest fixed (unmasked, grep-safe) run in the signature -> a raw anchor.
BINARY_ANCHOR_HEX=""; BINARY_ANCHOR_OFF=0
build_binary_anchor() {
    local sig; sig=$(echo "$1" | tr 'A-F' 'a-f')
    local kind="$2" jg_off="$3"
    local sig_bytes=$(( ${#sig} / 2 )) mask_len
    case "$kind" in short) mask_len=2 ;; near) mask_len=6 ;; bcond) mask_len=4 ;; esac
    local mask_end=$(( jg_off + mask_len ))
    BINARY_ANCHOR_HEX=""; BINARY_ANCHOR_OFF=0
    local best_len=0 best_start=0 start end byte run_len
    for (( start = 0; start < sig_bytes; start++ )); do
        run_len=0
        for (( end = start; end < sig_bytes; end++ )); do
            if (( end >= jg_off && end < mask_end )); then break; fi
            byte="${sig:$(( end*2 )):2}"
            if [[ "$byte" == "00" || "$byte" == "0a" || "$byte" == "3a" ]]; then break; fi
            run_len=$(( run_len + 1 ))
        done
        if (( run_len > best_len )); then best_len=$run_len; best_start=$start; fi
    done
    if (( best_len >= 4 )); then
        BINARY_ANCHOR_HEX="${sig:$(( best_start*2 )):$(( best_len*2 ))}"
        BINARY_ANCHOR_OFF=$best_start
    fi
}

# Resolve a Python 3 interpreter ONCE (memoised in MV2_PYTHON): prefer `python3`,
# then accept a bare `python` only if it is actually Python 3 (a py2 `python`
# would choke on the scanner, and we must know that BEFORE taking the python
# branch so the grep fallback can still run). MV2_PYTHON stays "" when no usable
# python exists - the scan then falls back to grep, and the default RVA fast path
# needs no interpreter at all. The `python` probe only runs when `python3` is
# absent, so it never disturbs the common case.
MV2_PYTHON=""; MV2_PYTHON_RESOLVED=false
resolve_python() {
    $MV2_PYTHON_RESOLVED && return 0
    MV2_PYTHON_RESOLVED=true
    if command -v python3 >/dev/null 2>&1; then MV2_PYTHON="python3"; return 0; fi
    if command -v python >/dev/null 2>&1 \
       && python -c 'import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)' >/dev/null 2>&1; then
        MV2_PYTHON="python"; return 0
    fi
    MV2_PYTHON=""
}

# Optional python3 accelerator for the relocated-gate scan. Reads ONE site's
# .text region once - FROM STDIN, which the caller redirects the target file into,
# so python never has to interpret a shell path (this dodges MSYS/cygwin/WSL
# path-format mismatches when python3 is a native-Windows build) - and does the
# anchor find + full masked match in-process, printing the ABSOLUTE file offset
# of each jump opcode (exact parity with sig_matches_at). Faster and far more
# reliable than grep-on-binary, whose long-line/NUL handling misses anchors in
# the ~285 MB Chrome .text on some builds (notably WSL's GNU grep 3.11 - see
# mv2-sh-grep-slowpath-wsl). Prints nothing on any error so the caller fails
# closed; grep stays the fallback when python3 is absent (keeps the default
# no-python path, e.g. stock macOS, intact).
# Stdin: the target file.  Args: traw tsize sig_hex kind jg_off expected anchor_hex anchor_off
python_scan_site() {
    "$MV2_PYTHON" -c '
import sys
try:
    a = sys.argv
    traw = int(a[1]); tsize = int(a[2])
    sig  = bytes.fromhex(a[3]); kind = a[4]; jg = int(a[5]); expected = int(a[6])
    anchor = bytes.fromhex(a[7]); aoff = int(a[8])
    if not anchor:
        sys.exit(0)
    f = sys.stdin.buffer
    try:
        f.seek(traw); data = f.read(tsize)
    except Exception:
        data = f.read()[traw:traw + tsize]
    n = len(data); L = len(sig)
    def ok(s):
        if s < 0 or s + L > n:
            return False
        if kind == "bcond":
            w = data[s+jg] | (data[s+jg+1] << 8) | (data[s+jg+2] << 16) | (data[s+jg+3] << 24)
            if (w & 0xFF000010) != 0x54000000:
                return False
            c = w & 0xF
            if c != 0x0C and c != 0x0E:
                return False
        for k in range(L):
            p = data[s+k]
            if kind == "short":
                if k == jg:
                    if p != 0x7F and p != 0xEB:
                        return False
                elif k == jg + 1:
                    pass
                elif p != sig[k]:
                    return False
            elif kind == "near":
                if k == jg:
                    if not ((p == 0x0F and data[s+jg+1] == 0x8F) or (p == 0x90 and data[s+jg+1] == 0xE9)):
                        return False
                elif k == jg + 1:
                    pass
                elif jg + 2 <= k <= jg + 5:
                    pass
                elif p != sig[k]:
                    return False
            else:  # bcond: the 4-byte branch word was validated above
                if jg <= k <= jg + 3:
                    pass
                elif p != sig[k]:
                    return False
        return True

    seen = set(); out = []; pos = 0
    while True:
        i = data.find(anchor, pos)
        if i < 0:
            break
        pos = i + 1
        s = i - aoff
        if ok(s):
            off = traw + s + jg
            if off not in seen:
                seen.add(off); out.append(off)
                if len(out) > expected + 1:
                    break
    sys.stdout.buffer.write("".join("%d\n" % o for o in out).encode())
except Exception:
    sys.exit(0)
' "$@" 2>/dev/null || true
}

# find_site_matches <file> <base> <traw> <tvaddr> <tsize> <spec> -> FOUND_OFFSETS, RELOCATED

# spec is "name|kind|jgRVA|jgOff|expectedMatches|sig". FOUND_OFFSETS holds
# ABSOLUTE file offsets of the jump opcode within this slice. Fast path probes
# the recorded RVA; a miss falls back to one raw fixed-string grep for the site.
FOUND_OFFSETS=(); RELOCATED=false; FAST_PROBE_ONLY=false
find_site_matches() {
    local file="$1" base="$2" traw="$3" tvaddr="$4" tsize="$5" spec="$6"
    local name kind jg_rva_hex jg_off expected sig_hex
    IFS='|' read -r name kind jg_rva_hex jg_off expected sig_hex <<< "$spec"
    local jg_rva=$(( jg_rva_hex )) sig_len=$(( ${#sig_hex} / 2 ))
    FOUND_OFFSETS=(); RELOCATED=false

    # Fast path: probe the recorded RVA (only when expectedMatches == 1).
    if (( expected == 1 && jg_rva >= tvaddr )); then
        local rva_in_text=$(( jg_rva - tvaddr ))
        if (( rva_in_text < tsize )); then
            local jg_raw=$(( traw + rva_in_text ))
            local sig_start=$(( jg_raw - jg_off ))
            if (( sig_start >= traw && sig_start + sig_len <= traw + tsize )) \
               && sig_matches_at "$file" "$sig_start" "$sig_hex" "$kind" "$jg_off"; then
                FOUND_OFFSETS=("$jg_raw"); RELOCATED=false; return 0
            fi
        fi
    fi
    if $FAST_PROBE_ONLY; then return 0; fi

    # Slow path: one raw fixed-string grep for this site's anchor, verified with
    # the full masked matcher. Tables are tiny, so a per-site scan is cheap and
    # only runs when the fast path missed (i.e. Chrome relocated the gate).
    build_binary_anchor "$sig_hex" "$kind" "$jg_off"
    local anchor_hex="$BINARY_ANCHOR_HEX"
    if [[ -z "$anchor_hex" ]]; then
        # No >=4-byte fixed run to grep for (signature too fragmented for a raw
        # scan). Report it and leave FOUND_OFFSETS empty so this site is counted
        # unsatisfied and the milestone is declined - fail closed. Returning
        # non-zero here would abort the whole run under `set -e`, because the
        # caller (probe_slice_pass) invokes us as a bare, untested statement.
        warnf "Couldn't search for one of the changes - skipping it."; return 0
    fi

    # Prefer the python3 accelerator when a usable interpreter is present: one
    # in-process pass over .text, no per-candidate od reads, and reliable where
    # grep-on-binary is not. grep is the fallback below when no python is found.
    resolve_python
    if [[ -n "$MV2_PYTHON" ]]; then
        local matches=() jg_file_offset
        while IFS= read -r jg_file_offset; do
            jg_file_offset="${jg_file_offset%$'\r'}"   # a Windows python3 may emit CRLF
            [[ "$jg_file_offset" =~ ^[0-9]+$ ]] || continue
            matches+=("$jg_file_offset")
        done < <(python_scan_site "$traw" "$tsize" "$sig_hex" "$kind" "$jg_off" "$expected" "$anchor_hex" "$BINARY_ANCHOR_OFF" < "$file")
        if (( ${#matches[@]} > 0 )); then
            FOUND_OFFSETS=("${matches[@]}"); RELOCATED=true
        fi
        return 0
    fi

    local anchor_bin="" ai abyte
    for (( ai = 0; ai < ${#anchor_hex}; ai += 2 )); do
        abyte="${anchor_hex:ai:2}"
        printf -v abyte '%b' "\\x${abyte}"
        anchor_bin+="$abyte"
    done

    local matches=() anchor_pos sig_start jg_file_offset
    while IFS=: read -r anchor_pos _rest; do
        [[ "$anchor_pos" =~ ^[0-9]+$ ]] || continue
        sig_start=$(( anchor_pos - BINARY_ANCHOR_OFF ))
        if (( sig_start < traw || sig_start + sig_len > traw + tsize )); then continue; fi
        if sig_matches_at "$file" "$sig_start" "$sig_hex" "$kind" "$jg_off"; then
            jg_file_offset=$(( sig_start + jg_off ))
            local seen=false m
            for m in "${matches[@]:-}"; do [[ "$m" == "$jg_file_offset" ]] && seen=true; done
            $seen || matches+=("$jg_file_offset")
            if (( ${#matches[@]} > expected + 1 )); then break; fi
        fi
    done < <(LC_ALL=C grep -a -o -b -F -- "$anchor_bin" "$file" 2>/dev/null || true)

    if (( ${#matches[@]} > 0 )); then
        FOUND_OFFSETS=("${matches[@]}"); RELOCATED=true
    fi
    return 0
}

# ============================================================================
# Per-slice milestone probing - pick the best unambiguous milestone for ONE
# slice, bounded to that slice's own container/.text. An ELF target is a single
# slice with container "elf"; a fat Mach-O has one slice per CPU.
# ============================================================================
BEST_MS_NAME=""; BEST_SATISFIED=0; BEST_TOTAL=0; BEST_FULL=false; BEST_TIES=0
FLIP_NAMES=(); FLIP_KINDS=(); FLIP_OFFSETS=(); FLIP_RELOCATED=()

reset_probe_results() {
    BEST_MS_NAME=""; BEST_SATISFIED=0; BEST_TOTAL=0; BEST_FULL=false; BEST_TIES=0
    FLIP_NAMES=(); FLIP_KINDS=(); FLIP_OFFSETS=(); FLIP_RELOCATED=()
}

probe_slice_pass() {
    local file="$1" base="$2" traw="$3" tvaddr="$4" tsize="$5" container="$6"
    local mi
    for (( mi = 0; mi < NUM_MILESTONES; mi++ )); do
        [[ "${MILESTONE_CONTAINERS[$mi]}" == "$container" ]] || continue
        local ms_name="${MILESTONE_NAMES[$mi]}"
        local satisfied=0 total=0
        local fn=() fk=() fo=() fr=()
        local spec s_name s_kind s_jgrva s_jgoff s_expected s_sig off
        while IFS= read -r spec; do
            [[ -n "$spec" ]] || continue
            total=$(( total + 1 ))
            IFS='|' read -r s_name s_kind s_jgrva s_jgoff s_expected s_sig <<< "$spec"
            find_site_matches "$file" "$base" "$traw" "$tvaddr" "$tsize" "$spec"
            if (( ${#FOUND_OFFSETS[@]} == s_expected )); then
                satisfied=$(( satisfied + 1 ))
                for off in "${FOUND_OFFSETS[@]}"; do
                    fn+=("$s_name"); fk+=("$s_kind"); fo+=("$off"); fr+=("$RELOCATED")
                done
            fi
        done < <(sites_of "$mi")

        if (( satisfied > BEST_SATISFIED )); then
            BEST_MS_NAME="$ms_name"; BEST_SATISFIED=$satisfied; BEST_TOTAL=$total
            FLIP_NAMES=("${fn[@]:-}"); FLIP_KINDS=("${fk[@]:-}")
            FLIP_OFFSETS=("${fo[@]:-}"); FLIP_RELOCATED=("${fr[@]:-}")
            BEST_TIES=1
            (( satisfied == total )) && break
        elif (( satisfied == BEST_SATISFIED && satisfied > 0 )); then
            BEST_TIES=$(( BEST_TIES + 1 ))
        fi
    done
    if (( BEST_SATISFIED == BEST_TOTAL && BEST_TOTAL > 0 )); then BEST_FULL=true; else BEST_FULL=false; fi
}

probe_slice() {
    local idx="$1" file="$2"
    _hexcache_load "$file"   # prime the byte cache for both probe passes
    local base="${SLICE_BASE[$idx]}" traw="${SLICE_TRAW[$idx]}"
    local tvaddr="${SLICE_TVADDR[$idx]}" tsize="${SLICE_TSIZE[$idx]}"
    local container="${SLICE_CONTAINER[$idx]}"
    reset_probe_results
    FAST_PROBE_ONLY=true
    probe_slice_pass "$file" "$base" "$traw" "$tvaddr" "$tsize" "$container"
    FAST_PROBE_ONLY=false
    if $BEST_FULL; then return 0; fi
    reset_probe_results
    probe_slice_pass "$file" "$base" "$traw" "$tvaddr" "$tsize" "$container"
    return 0
}

# ============================================================================
# Flip engine (operates on the FLIP_* set filled by probe_slice, in a work file).
#   short : 0x7F      -> 0xEB
#   near  : 0F 8F     -> 90 E9
#   bcond : B.cond word byte0 low nibble GT(0xC) -> AL(0xE); ONLY that nibble
#           changes (b0 = (b0 & 0xF0) | 0x0E), preserving opcode and imm19.
# ============================================================================
SLICE_FLIPS=0; SLICE_ALREADY=0
apply_flips_slice() {
    local file="$1" applied=0 already=0 i name kind offset cur o0 o1 nib newb
    _hexcache_load "$file"   # prime for the per-site reads; flushed after writing
    SLICE_FLIPS=0; SLICE_ALREADY=0
    for (( i = 0; i < ${#FLIP_OFFSETS[@]}; i++ )); do
        name="${FLIP_NAMES[$i]}"; kind="${FLIP_KINDS[$i]}"; offset="${FLIP_OFFSETS[$i]}"
        if [[ "$kind" == "short" ]]; then
            cur=$(read_byte "$file" "$offset")
            if (( cur == 0xEB )); then already=$(( already + 1 )); continue; fi
            if (( cur != 0x7F )); then
                warnf "    Skipped one change - it didn't look the way we expected."
                continue
            fi
            printf '\xEB' | dd of="$file" bs=1 seek="$offset" count=1 conv=notrunc 2>/dev/null
            applied=$(( applied + 1 ))
        elif [[ "$kind" == "near" ]]; then
            o0=$(read_byte "$file" "$offset"); o1=$(read_byte "$file" $(( offset + 1 )))
            if (( o0 == 0x90 && o1 == 0xE9 )); then already=$(( already + 1 )); continue; fi
            if ! (( o0 == 0x0F && o1 == 0x8F )); then
                warnf "    Skipped one change - it didn't look the way we expected."
                continue
            fi
            printf '\x90\xE9' | dd of="$file" bs=1 seek="$offset" count=2 conv=notrunc 2>/dev/null
            applied=$(( applied + 1 ))
        else  # bcond
            cur=$(read_byte "$file" "$offset")   # little-endian byte0 holds the condition
            nib=$(( cur & 0x0F ))
            if (( nib == 0x0E )); then already=$(( already + 1 )); continue; fi
            if (( nib != 0x0C )); then
                warnf "    Skipped one change - it didn't look the way we expected."
                continue
            fi
            newb=$(( (cur & 0xF0) | 0x0E ))
            printf "\\x$(printf '%02X' "$newb")" | dd of="$file" bs=1 seek="$offset" count=1 conv=notrunc 2>/dev/null
            applied=$(( applied + 1 ))
        fi
        okf "    Change ${applied} of ${#FLIP_OFFSETS[@]} applied."
    done
    SLICE_FLIPS=$applied; SLICE_ALREADY=$already
    _hexcache_flush   # the dd writes above dirtied the file; drop the stale slice
}

STATE_STOCK=0; STATE_PATCHED=0
classify_flip_states_slice() {
    local file="$1" i kind offset o0 o1 nib
    _hexcache_load "$file"   # prime the byte cache for the per-site reads
    STATE_STOCK=0; STATE_PATCHED=0
    for (( i = 0; i < ${#FLIP_OFFSETS[@]}; i++ )); do
        kind="${FLIP_KINDS[$i]}"; offset="${FLIP_OFFSETS[$i]}"
        o0=$(read_byte "$file" "$offset")
        if [[ "$kind" == "short" ]]; then
            if (( o0 == 0x7F )); then STATE_STOCK=$(( STATE_STOCK + 1 ))
            elif (( o0 == 0xEB )); then STATE_PATCHED=$(( STATE_PATCHED + 1 ))
            else return 1; fi
        elif [[ "$kind" == "near" ]]; then
            o1=$(read_byte "$file" $(( offset + 1 )))
            if (( o0 == 0x0F && o1 == 0x8F )); then STATE_STOCK=$(( STATE_STOCK + 1 ))
            elif (( o0 == 0x90 && o1 == 0xE9 )); then STATE_PATCHED=$(( STATE_PATCHED + 1 ))
            else return 1; fi
        else
            nib=$(( o0 & 0x0F ))
            if (( nib == 0x0C )); then STATE_STOCK=$(( STATE_STOCK + 1 ))
            elif (( nib == 0x0E )); then STATE_PATCHED=$(( STATE_PATCHED + 1 ))
            else return 1; fi
        fi
    done
}

# ============================================================================
# Report-only candidate scanner (ELF) - structural scan for cmp r/m32,2 ; jg.
# Purely informational on a no-match; never modifies anything.
# ============================================================================
report_layout_candidates() {
    local file="$1"
    if (( TEXT_SIZE < 8 )); then return; fi
    infof "This Chrome version isn't recognized yet. Looking for clues to help add support..."
    local total=0 shown=0 max_display=20 marker
    printf -v marker '%b' '\x02\x7f'
    local LC_ALL=C
    while IFS=: read -r marker_pos _match; do
        [[ "$marker_pos" =~ ^[0-9]+$ ]] || continue
        if (( marker_pos < TEXT_RAW + 2 || marker_pos + 2 > TEXT_RAW + TEXT_SIZE )); then continue; fi
        local valid=false cmp_back=0 ctx
        ctx=$(read_bytes_hex "$file" $(( marker_pos - 2 )) 2)
        if [[ "$ctx" =~ ^83F[89A-F]$ ]]; then valid=true; cmp_back=2; fi
        if ! $valid && (( marker_pos >= TEXT_RAW + 3 )); then
            ctx=$(read_bytes_hex "$file" $(( marker_pos - 3 )) 3)
            if [[ "$ctx" =~ ^837[89A-F][[:xdigit:]]{2}$ ]]; then valid=true; cmp_back=3; fi
        fi
        if ! $valid; then continue; fi
        local follow_start=$(( marker_pos + 2 )) follow_count=40
        if (( follow_start + follow_count > TEXT_RAW + TEXT_SIZE )); then
            follow_count=$(( TEXT_RAW + TEXT_SIZE - follow_start ))
        fi
        local follow_region=""
        if (( follow_count > 0 )); then follow_region=$(read_bytes_hex "$file" "$follow_start" "$follow_count"); fi
        local has_follow=false
        if [[ "$follow_region" =~ 83F[89A-F]0[15] ]]; then has_follow=true; fi
        if ! $has_follow && [[ "$follow_region" =~ 80B[89A-F][[:xdigit:]]{8}00 ]]; then has_follow=true; fi
        if ! $has_follow; then continue; fi
        total=$(( total + 1 ))
        if (( shown < max_display )); then
            local rva=$(( TEXT_VADDR + marker_pos - TEXT_RAW - cmp_back ))
            printf "    [candidate] RVA 0x%X\n" "$rva"
            shown=$(( shown + 1 ))
        fi
    done < <(LC_ALL=C grep -a -o -b -F -- "$marker" "$file" 2>/dev/null || true)
    local extra=""
    if (( total > shown )); then extra=" ($((total - shown)) not shown)"; fi
    infof "Found ${total} possible spot(s)${extra}. Nothing was changed - please share this and your Chrome version with the developer."
}

# ============================================================================
# Atomic write + backup. write_target does a dir-local atomic replace, verifying
# the copied bytes and (optionally) re-checking the target hash to close the
# inspect/write race. Backups and their .meta are container-specific:
#   - ELF   : "<file>.bak" beside the file, keyed by GNU build-id.
#   - Mach-O: for a real .app, in Application Support/<brand>/<uuid>/ (a stray
#             file inside a signed bundle breaks its seal and a Keystone update
#             wipes it); for a loose offline Mach-O, "<file>.bak" beside it.
# ============================================================================
WORK_FILE=""; WRITE_TMP=""; META_TMP=""; QUIET=false

write_target() {
    local target="$1" source="$2" expected_hash="${3:-}" known_source_hash="${4:-}"
    local dir; dir=$(dirname "$target")
    local tmp; tmp=$(mktemp "${dir}/.chrome-mv2-XXXXXX"); WRITE_TMP="$tmp"
    if [[ -e "$target" ]]; then cp -p -- "$target" "$tmp"; fi
    cp -- "$source" "$tmp"
    local shash thash chash
    # Trust a caller-supplied source hash (it was just computed) to avoid a second
    # full-file pass; the tmp copy is always hashed and compared, so the write is
    # still verified byte-for-byte.
    shash="${known_source_hash:-$(file_sha256 "$source")}"; thash=$(file_sha256 "$tmp")
    if [[ "$shash" != "$thash" ]]; then rm -f -- "$tmp"; WRITE_TMP=""; errf "Couldn't write the file safely - nothing was changed."; return 1; fi
    if [[ -n "$expected_hash" ]]; then
        chash=$(file_sha256 "$target")
        if [[ "$chash" != "$expected_hash" ]]; then rm -f -- "$tmp"; WRITE_TMP=""; errf "Chrome changed while we were working - nothing was changed. Try again."; return 1; fi
    fi
    mv -f -- "$tmp" "$target"; WRITE_TMP=""
    _hexcache_flush   # $target was just replaced; any cached slice is now stale
    sync 2>/dev/null || true
}

backup_meta_path() { printf '%s.meta\n' "$1"; }

# ---- Mach-O identity + backup location -------------------------------------
BACKUP_BRAND="chrome-mv2-patch"
TARGET_TOKEN=""
IDENTITY_UUIDS=""
APP_PATH=""; FRAMEWORK_BUNDLE=""; TARGET_FILE=""

support_base() {
    if [[ -w "/Library/Application Support" ]]; then printf '/Library/Application Support\n'
    else printf '%s/Library/Application Support\n' "${HOME:-/tmp}"; fi
}

format_uuid() {
    local h="$1"
    if [[ ${#h} -eq 32 ]]; then
        printf '%s-%s-%s-%s-%s\n' "${h:0:8}" "${h:8:4}" "${h:12:4}" "${h:16:4}" "${h:20:12}"
    else printf '%s\n' "$h"; fi
}

# The macho backup key: the LC_UUID of the slice that runs on THIS Mac.
identity_token() {
    local pair uuid="" IFS=,
    for pair in $IDENTITY_UUIDS; do
        case "$pair" in "$HOST_CONTAINER":*) uuid="${pair#*:}"; break ;; esac
    done
    [[ -n "$uuid" ]] || uuid="${IDENTITY_UUIDS##*:}"
    uuid=$(printf '%s' "$uuid" | tr -cd '0-9A-Fa-f')
    if [[ -z "$uuid" ]]; then
        uuid=$(printf '%s' "$IDENTITY_UUIDS" | { shasum -a 256 2>/dev/null || sha256sum; } | awk '{print $1}')
        uuid="${uuid:0:32}"
    fi
    format_uuid "$uuid"
}

compute_identity() {
    # requires parse_macho() to have populated SLICE_* for $1
    local file="$1" i pairs=""
    for (( i = 0; i < NUM_SLICES; i++ )); do
        pairs="${pairs}${pairs:+,}${SLICE_CONTAINER[$i]}:${SLICE_UUID[$i]}"
    done
    IDENTITY_UUIDS="$pairs"
}

# backup_dir/backup_path dispatch on the target container. ELF and loose Mach-O
# keep "<file>.bak" beside the file; a real .app keeps it under Application
# Support keyed by the framework build UUID.
backup_dir() {
    if [[ "$TARGET_CONTAINER" == "macho" && -n "$APP_PATH" ]]; then
        printf '%s/%s/%s\n' "$(support_base)" "$BACKUP_BRAND" "$TARGET_TOKEN"
    else
        printf '%s\n' "$(dirname "$TARGET_FILE")"
    fi
}
backup_path() {
    if [[ "$TARGET_CONTAINER" == "macho" && -n "$APP_PATH" ]]; then
        printf '%s/%s.bak\n' "$(backup_dir)" "$(basename "$TARGET_FILE")"
    else
        printf '%s.bak\n' "$TARGET_FILE"
    fi
}

BACKUP_BUILD_ID=""; BACKUP_IDENTITY=""; BACKUP_SIZE=0; BACKUP_HASH=""; BACKUP_LEGACY=false

# save_backup_snapshot <target> <backup> <source> <identity>
# identity = build-id (elf) or "macho-x64:HEX,macho-arm64:HEX" (macho).
save_backup_snapshot() {
    local target="$1" backup="$2" source="$3" identity="$4"
    mkdir -p -- "$(dirname "$backup")" || { errf "Couldn't create the backup folder."; return 1; }
    local prev=""; [[ -f "$backup" ]] && prev=$(file_sha256 "$backup")
    write_target "$backup" "$source" "$prev" || return 1
    local meta size hash container
    meta=$(backup_meta_path "$backup"); size=$(file_size "$backup"); hash=$(file_sha256 "$backup")
    if [[ "$TARGET_CONTAINER" == "elf" ]]; then container="elf"; else container="macho"; fi
    META_TMP="${meta}.tmp"
    if [[ "$container" == "elf" ]]; then
        printf 'schema=1\ncontainer=elf\nbuild_id=%s\nsize=%s\nsha256=%s\n' "$identity" "$size" "$hash" > "$META_TMP"
    else
        printf 'schema=1\ncontainer=macho\nidentity=%s\nsize=%s\nsha256=%s\n' "$identity" "$size" "$hash" > "$META_TMP"
    fi
    mv -f -- "$META_TMP" "$meta"; META_TMP=""
}

validate_backup_snapshot() {
    local backup="$1" meta
    [[ -f "$backup" ]] || return 1
    BACKUP_BUILD_ID=""; BACKUP_IDENTITY=""
    if [[ "$TARGET_CONTAINER" == "elf" ]]; then
        parse_elf "$backup" >/dev/null || return 1
        BACKUP_BUILD_ID=$(get_elf_build_id "$backup")
        [[ -n "$BACKUP_BUILD_ID" ]] || return 1
    else
        parse_macho "$backup" >/dev/null || return 1
        compute_identity "$backup"; BACKUP_IDENTITY="$IDENTITY_UUIDS"
        [[ -n "$BACKUP_IDENTITY" ]] || return 1
    fi
    BACKUP_SIZE=$(file_size "$backup"); BACKUP_HASH=$(file_sha256 "$backup")

    meta=$(backup_meta_path "$backup"); BACKUP_LEGACY=false
    if [[ ! -f "$meta" ]]; then BACKUP_LEGACY=true; return 0; fi
    local schema="" container="" build_id="" identity="" size="" sha256="" key value extra
    while IFS='=' read -r key value extra; do
        [[ -z "$extra" ]] || return 1
        case "$key" in
            schema) schema="$value" ;; container) container="$value" ;;
            build_id) build_id="$value" ;; identity) identity="$value" ;;
            size) size="$value" ;; sha256) sha256="$value" ;;
            *) return 1 ;;
        esac
    done < "$meta"
    if [[ "$TARGET_CONTAINER" == "elf" ]]; then
        [[ "$schema" == 1 && "$container" == elf && "$build_id" == "$BACKUP_BUILD_ID" \
           && "$size" == "$BACKUP_SIZE" && "$sha256" == "$BACKUP_HASH" ]]
    else
        [[ "$schema" == 1 && "$container" == macho && "$identity" == "$BACKUP_IDENTITY" \
           && "$size" == "$BACKUP_SIZE" && "$sha256" == "$BACKUP_HASH" ]]
    fi
}

# ============================================================================
# Code signing (macOS only). Any edit invalidates the Mach-O signature; on Apple
# Silicon the kernel refuses to launch an invalid/absent signature. We must NOT
# use `codesign --deep` (it drops each component's entitlements, stripping the
# Renderer helper's com.apple.security.cs.allow-jit -> renderer crashes). Instead
# we walk the bundle INSIDE-OUT and sign every nested bundle + Mach-O with
# --preserve-metadata=entitlements,flags; `requirements` is dropped so codesign
# regenerates an ad-hoc designated requirement.
# ============================================================================
have_codesign() { command -v codesign >/dev/null 2>&1; }

resign_one() {
    local comp="$1"
    # Explicitly carry the component's own entitlements across the re-sign. This
    # matters most for the Renderer helper's com.apple.security.cs.allow-jit:
    # --preserve-metadata alone has proven unreliable at carrying it on some
    # codesign versions, and the plain ad-hoc fallback drops it outright (the
    # renderer then dies with a JIT / library-validation kill). Dump -> re-apply
    # is authoritative. --xml keeps the dump a clean plist the signer re-accepts;
    # on older macOS without --xml the dump fails and we drop to the fallbacks.
    local ent; ent="$(mktemp 2>/dev/null)" || ent=""
    if [[ -n "$ent" ]] \
       && codesign -d --entitlements - --xml "$comp" >"$ent" 2>/dev/null \
       && [[ -s "$ent" ]]; then
        if codesign --force --sign - --entitlements "$ent" "$comp" 2>/dev/null; then
            rm -f "$ent"; return 0
        fi
    fi
    [[ -n "$ent" ]] && rm -f "$ent"
    # No entitlements to carry (or capture unsupported here): preserve, then plain.
    codesign --force --sign - --preserve-metadata=entitlements,flags "$comp" 2>/dev/null && return 0
    codesign --force --sign - "$comp" 2>/dev/null && return 0
    errf "Couldn't re-sign part of the app: ${comp}"; return 1
}

resign_inside_out() {
    local framework_bundle="$1" app_path="$2"   # framework_bundle kept for call-site compat
    if [[ -z "$app_path" || ! -d "$app_path" ]]; then
        errf "Couldn't find the app to re-sign: ${app_path}"; return 1
    fi
    infof "Re-signing the app so it opens normally..."
    local items=() line path rc=0
    while IFS= read -r line; do items+=("$line"); done < <(
        {
            find "$app_path" -type d \( -name '*.app' -o -name '*.framework' -o -name '*.xpc' \) -print
            find "$app_path" -type f \( -name '*.dylib' -o -name '*.so' \
                 -o -path '*/MacOS/*' -o -path '*/Helpers/*' -o -path '*/Libraries/*' \) -print
        } 2>/dev/null | awk -F/ '{ print NF"\t"$0 }' | sort -rn -k1,1
    )
    for line in "${items[@]}"; do
        path="${line#*$'\t'}"
        [[ "$path" == "$app_path" ]] && continue                 # outer app signed last
        if [[ -f "$path" ]] && ! is_macho "$path"; then continue; fi   # skip data blobs
        resign_one "$path" || rc=1
    done
    resign_one "$app_path" || rc=1                                 # top of the tree, last
    return $rc
}

verify_signature() {
    local app_path="$1"
    if [[ -n "$app_path" && -d "$app_path" ]]; then
        codesign --verify --deep --strict "$app_path" 2>/dev/null
        return $?
    fi
    return 0
}

# ============================================================================
# Host CPU (Mach-O only). The universal framework carries two slices but only
# ONE runs on this Mac; patching the other would edit code that never executes.
# ============================================================================
HOST_CONTAINER=""
detect_host_container() {
    case "${MV2_TEST_HOST_ARCH:-}" in
        arm64|aarch64)  HOST_CONTAINER="macho-arm64"; return ;;
        x86_64|amd64|x64) HOST_CONTAINER="macho-x64"; return ;;
    esac
    if command -v sysctl >/dev/null 2>&1 \
       && [[ "$(sysctl -n hw.optional.arm64 2>/dev/null)" == "1" ]]; then
        HOST_CONTAINER="macho-arm64"; return
    fi
    case "$(uname -m 2>/dev/null || echo)" in
        arm64|aarch64) HOST_CONTAINER="macho-arm64" ;;
        *)             HOST_CONTAINER="macho-x64" ;;
    esac
}

host_arch_label() {
    case "$HOST_CONTAINER" in
        macho-arm64) echo "Apple Silicon (arm64)" ;;
        *)           echo "Intel (x86_64)" ;;
    esac
}

# Should this slice be patched? Sets SKIP_REASON on decline. An ELF target is a
# single-arch file (elf / elf-arm64) and always eligible; a Mach-O slice is
# eligible only if it matches this Mac.
SKIP_REASON=""
slice_decision() {
    local container="$1" allow_partial="$2"
    SKIP_REASON=""
    if (( BEST_SATISFIED == 0 )); then SKIP_REASON="Chrome version not recognized"; return 1; fi
    if ! $BEST_FULL && (( BEST_TIES > 1 )); then SKIP_REASON="couldn't tell which Chrome version this is"; return 1; fi
    if [[ "$container" != "elf" && "$container" != "elf-arm64" && "$HOST_CONTAINER" != "$container" ]]; then
        SKIP_REASON="not the version your Mac runs"; return 1
    fi
    if ! $BEST_FULL && ! $allow_partial; then
        SKIP_REASON="only ${BEST_SATISFIED} of ${BEST_TOTAL} changes matched; needs --allow-partial"; return 1
    fi
    return 0
}

# ============================================================================
# macOS platform glue - .app discovery, framework resolution, process handling.
# ============================================================================
app_version() {
    local app="$1" plist="$1/Contents/Info.plist"
    [[ -f "$plist" ]] || { echo ""; return; }
    if command -v defaults >/dev/null 2>&1; then
        defaults read "${app}/Contents/Info" CFBundleShortVersionString 2>/dev/null && return
    fi
    if command -v plutil >/dev/null 2>&1; then
        plutil -extract CFBundleShortVersionString raw -o - "$plist" 2>/dev/null && return
    fi
    echo ""
}

# From a .app dir, set FRAMEWORK_BUNDLE + TARGET_FILE (the real versioned Mach-O).
resolve_framework_from_app() {
    local app="$1" fw=""
    local d
    for d in "$app"/Contents/Frameworks/*Framework.framework; do
        [[ -d "$d" ]] && { fw="$d"; break; }
    done
    [[ -n "$fw" ]] || return 1
    FRAMEWORK_BUNDLE="$fw"
    local base; base=$(basename "$fw" .framework)
    local versions="$fw/Versions" v vdir=""
    if [[ -d "$versions" ]]; then
        for v in "$versions"/*; do
            [[ -d "$v" && ! -L "$v" ]] || continue
            [[ "$(basename "$v")" == "Current" ]] && continue
            vdir="$v"   # last real version dir; installs keep exactly one
        done
    fi
    if [[ -n "$vdir" && -f "$vdir/$base" ]]; then
        TARGET_FILE="$vdir/$base"
    elif [[ -f "$versions/Current/$base" ]]; then
        TARGET_FILE="$versions/Current/$base"
    else
        return 1
    fi
    return 0
}

# Normalize a macOS path (.app / .framework / loose Mach-O) into APP_PATH /
# FRAMEWORK_BUNDLE / TARGET_FILE.
resolve_macho_target() {
    local path="$1"
    APP_PATH=""; FRAMEWORK_BUNDLE=""; TARGET_FILE=""
    if [[ -d "$path" && "$path" == *.app ]]; then
        APP_PATH="$path"
        resolve_framework_from_app "$path" || { errf "Couldn't find Chrome inside ${path}"; return 1; }
    elif [[ -d "$path" && "$path" == *.framework ]]; then
        FRAMEWORK_BUNDLE="$path"
        local base; base=$(basename "$path" .framework)
        if [[ -f "$path/Versions/Current/$base" ]]; then TARGET_FILE="$path/Versions/Current/$base"
        else errf "Couldn't find Chrome inside ${path}"; return 1; fi
    elif [[ -f "$path" ]]; then
        TARGET_FILE="$path"        # a loose Mach-O (offline scratch copy)
    else
        errf "That's not a Chrome app or file: ${path}"; return 1
    fi
    return 0
}

CHROME_APPS=("Google Chrome.app" "Google Chrome Beta.app" "Google Chrome Dev.app" "Google Chrome Canary.app")
CHROME_LABELS=("Stable" "Beta" "Dev" "Canary")
MAC_LABELS=(); MAC_APPS=(); MAC_VERSIONS=(); MAC_RUNNING=()

enumerate_macos_installs() {
    MAC_LABELS=(); MAC_APPS=(); MAC_VERSIONS=(); MAC_RUNNING=()
    local roots=("/Applications" "$HOME/Applications") root i app ver running
    for root in "${roots[@]}"; do
        for (( i = 0; i < ${#CHROME_APPS[@]}; i++ )); do
            app="$root/${CHROME_APPS[$i]}"
            [[ -d "$app" ]] || continue
            ver=$(app_version "$app")
            running=false
            if command -v pgrep >/dev/null 2>&1 && pgrep -f "$app/Contents/MacOS/" >/dev/null 2>&1; then running=true; fi
            MAC_LABELS+=("${CHROME_LABELS[$i]}"); MAC_APPS+=("$app")
            MAC_VERSIONS+=("$ver"); MAC_RUNNING+=("$running")
        done
    done
}

proc_holders_app() {
    local app="$1"
    if command -v pgrep >/dev/null 2>&1; then pgrep -f "$app/Contents/MacOS/" 2>/dev/null | wc -l | tr -d ' '; else echo 0; fi
}

quit_chrome() {
    local app="$1" assume_yes="$2"
    (( $(proc_holders_app "$app") == 0 )) && return 0
    if ! $assume_yes && ! $QUIET; then
        echo -n "${C_BOLD}Chrome ($(basename "$app")) is open. Close it to continue? [y/N]: ${C_RESET}"
        local line; read -r line || return 1
        case "$line" in y|Y) ;; *) infof "Cancelled - nothing was changed."; return 1 ;; esac
    fi
    command -v osascript >/dev/null 2>&1 && osascript -e "quit app \"$app\"" 2>/dev/null || true
    local i
    for (( i = 0; i < 20; i++ )); do (( $(proc_holders_app "$app") == 0 )) && return 0; sleep 0.25; done
    command -v pkill >/dev/null 2>&1 && pkill -f "$app/Contents/MacOS/" 2>/dev/null || true
    for (( i = 0; i < 20; i++ )); do (( $(proc_holders_app "$app") == 0 )) && return 0; sleep 0.25; done
    errf "Chrome is still open - close it and try again."; return 1
}

# ============================================================================
# Linux platform glue - channel discovery, version, process handling (/proc).
# ============================================================================
LINUX_CHANNELS=("Stable" "Beta" "Dev")
LINUX_DIRS=("/opt/google/chrome" "/opt/google/chrome-beta" "/opt/google/chrome-unstable")

chrome_version() {
    local bin="$1" pkg=""
    case "$bin" in
        /opt/google/chrome/chrome) pkg="google-chrome-stable" ;;
        /opt/google/chrome-beta/chrome) pkg="google-chrome-beta" ;;
        /opt/google/chrome-unstable/chrome) pkg="google-chrome-unstable" ;;
    esac
    if [[ -n "$pkg" ]] && command -v dpkg-query >/dev/null 2>&1; then
        dpkg-query -W -f='${Version}\n' "$pkg" 2>/dev/null | grep -o -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true
    elif [[ -n "$pkg" ]] && command -v rpm >/dev/null 2>&1; then
        rpm -q --qf '%{VERSION}\n' "$pkg" 2>/dev/null | grep -o -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true
    fi
}

proc_holders() {
    local bin="$1" want
    want=$(readlink -f "$bin" 2>/dev/null || echo "$bin")
    local count=0 pid_dir target
    for pid_dir in /proc/[0-9]*/exe; do
        target=$(readlink "$pid_dir" 2>/dev/null || true)
        if [[ -z "$target" ]]; then continue; fi
        if [[ "$target" == "$want" || "$target" == "$bin" || "$target" == "${want} (deleted)" || "$target" == "${bin} (deleted)" ]]; then
            count=$(( count + 1 ))
        fi
    done
    echo "$count"
}

kill_chrome_processes() {
    local bin="$1" want
    want=$(readlink -f "$bin" 2>/dev/null || echo "$bin")
    local pid_dir target pid
    for pid_dir in /proc/[0-9]*/exe; do
        target=$(readlink "$pid_dir" 2>/dev/null || true)
        if [[ -z "$target" ]]; then continue; fi
        if [[ "$target" == "$want" || "$target" == "$bin" || "$target" == "${want} (deleted)" || "$target" == "${bin} (deleted)" ]]; then
            pid="${pid_dir#/proc/}"; pid="${pid%%/*}"
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    local i
    for (( i = 0; i < 20; i++ )); do
        if (( $(proc_holders "$bin") == 0 )); then return 0; fi
        sleep 0.25
    done
    return 1
}

confirm_force_close() {
    local channel="$1" holders="$2"
    echo ""
    echo "${C_BOLD}${C_YEL}  Chrome ${channel} is open.${C_RESET}"
    echo "     I need to close it to make the change. Any unsaved tabs will be lost."
    while true; do
        echo -n "${C_BOLD}Close Chrome ${channel} and continue? [y/N]: ${C_RESET}"
        local line; read -r line || return 1
        case "$line" in
            y|Y) return 0 ;;
            ""|n|N) infof "Cancelled - nothing was changed."; return 1 ;;
        esac
    done
}

request_target_close() {
    local target="$1" assume_yes="$2" holders
    holders=$(proc_holders "$target")
    (( holders == 0 )) && return 0
    if $assume_yes; then
        warnf "Chrome is open and will be closed (--yes)."
    elif $QUIET; then
        errf "Chrome is open."
        echo "    Close it, or add --yes to close it automatically."
        return 1
    else
        confirm_force_close "$(basename "$(dirname "$target")")" "$holders" || return 1
    fi
    if ! kill_chrome_processes "$target"; then
        errf "Chrome is still open - close it and try again."
        echo "    Nothing was changed."
        return 1
    fi
}

LNX_CHANNELS=(); LNX_PATHS=(); LNX_VERSIONS=(); LNX_RUNNING=(); LNX_HOLDERS=(); LNX_BACKUPS=(); LNX_STATE=()
CHOSEN_INDEX=-1
CHOSEN_CUSTOM_PATH=""

# Cheap patched/stock hint for the install list. Runs the FAST probe only (the
# recorded-RVA check, never the full .text scan), so it costs a handful of
# targeted reads rather than a sweep of the ~285 MB binary. Echoes "patched",
# "not patched", or "" (unknown / relocated / unrecognized - the list just omits
# a tag then; the real patch/check path still does the full probe). Clobbers the
# parse/probe globals, which the actual flow resets before it runs.
elf_patch_state() {
    local f="$1"
    parse_elf "$f" >/dev/null 2>&1 || { echo ""; return; }
    reset_probe_results
    FAST_PROBE_ONLY=true
    probe_slice_pass "$f" "${SLICE_BASE[0]}" "${SLICE_TRAW[0]}" "${SLICE_TVADDR[0]}" "${SLICE_TSIZE[0]}" "${SLICE_CONTAINER[0]}"
    FAST_PROBE_ONLY=false
    if (( BEST_SATISFIED == 0 )) || { ! $BEST_FULL && (( BEST_TIES > 1 )); }; then echo ""; return; fi
    classify_flip_states_slice "$f" 2>/dev/null || { echo ""; return; }
    if (( STATE_STOCK > 0 && STATE_PATCHED == 0 )); then echo "not patched"
    elif (( STATE_STOCK == 0 && STATE_PATCHED > 0 )); then echo "patched"
    else echo ""; fi
}

enumerate_linux_installs() {
    LNX_CHANNELS=(); LNX_PATHS=(); LNX_VERSIONS=(); LNX_RUNNING=(); LNX_HOLDERS=(); LNX_BACKUPS=(); LNX_STATE=()
    local i
    for (( i = 0; i < ${#LINUX_CHANNELS[@]}; i++ )); do
        local bin="${LINUX_DIRS[$i]}/chrome"
        if [[ ! -f "$bin" ]]; then continue; fi
        local ver holders has_backup running state
        ver=$(chrome_version "$bin"); holders=$(proc_holders "$bin")
        if (( holders > 0 )); then running=true; else running=false; fi
        if [[ -f "${bin}.bak" ]]; then has_backup=true; else has_backup=false; fi
        state=$(elf_patch_state "$bin")
        LNX_CHANNELS+=("${LINUX_CHANNELS[$i]}"); LNX_PATHS+=("$bin"); LNX_VERSIONS+=("$ver")
        LNX_RUNNING+=("$running"); LNX_HOLDERS+=("$holders"); LNX_BACKUPS+=("$has_backup"); LNX_STATE+=("$state")
    done
}

print_linux_install_row() {
    local idx="$1" i="$2"
    echo -n "  ${C_BOLD}${idx})${C_RESET} ${C_CYN}${LNX_CHANNELS[$i]}${C_RESET}"
    if [[ -n "${LNX_VERSIONS[$i]}" ]]; then echo -n "  ${LNX_VERSIONS[$i]}"; fi
    if ${LNX_RUNNING[$i]}; then
        echo -n "  ${C_YEL}[open]${C_RESET}"
    else
        echo -n "  ${C_GRN}[closed]${C_RESET}"
    fi
    case "${LNX_STATE[$i]:-}" in
        patched)       echo -n "  ${C_GRN}[patched]${C_RESET}" ;;
        "not patched") echo -n "  ${C_DIM}[not patched]${C_RESET}" ;;
    esac
    if ${LNX_BACKUPS[$i]}; then echo -n " ${C_DIM}(backup saved)${C_RESET}"; fi
    echo ""
    echo "      ${C_DIM}${LNX_PATHS[$i]}${C_RESET}"
}

read_custom_path() {
    while true; do
        echo -n "${C_BOLD}Enter the full path to the Chrome file, or leave blank to cancel: ${C_RESET}"
        local line; read -r line || return 1
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        if (( ${#line} >= 2 )); then
            if [[ "${line:0:1}" == '"' && "${line: -1}" == '"' ]] ||
               [[ "${line:0:1}" == "'" && "${line: -1}" == "'" ]]; then
                line="${line:1:${#line}-2}"
            fi
        fi
        if [[ -z "$line" ]]; then return 1; fi
        if [[ ! -f "$line" ]]; then
            errf "That's not a file. Try again."; continue
        fi
        CHOSEN_CUSTOM_PATH="$line"; return 0
    done
}

choose_linux_install() {
    local count=${#LNX_CHANNELS[@]}
    if (( count == 0 )); then
        warnf "Couldn't find Chrome on this computer."
        echo ""
        if read_custom_path; then TARGET_FILE="$CHOSEN_CUSTOM_PATH"; return 0; fi
        infof "No path entered - nothing was changed."
        return 1
    fi
    if (( count == 1 )); then
        okf "Found one Chrome:"; print_linux_install_row 1 0
    else
        echo ""; echo "${TAG_INFO} Found ${count} Chrome versions:"
        local j
        for (( j = 0; j < count; j++ )); do print_linux_install_row $(( j + 1 )) "$j"; done
        echo ""; echo "${TAG_INFO} Only the one you pick is changed; the others are left alone."
    fi
    while true; do
        if (( count == 1 )); then
            echo -n "${C_BOLD}Patch this Chrome? [Enter=yes, r=restore, c=custom path, q=quit]: ${C_RESET}"
        else
            echo -n "${C_BOLD}Which Chrome do you want to patch? [1-${count}, r=restore, c=custom path, q=quit]: ${C_RESET}"
        fi
        local line; read -r line || return 1
        if [[ "$line" == "q" || "$line" == "Q" ]]; then return 1; fi
        if [[ "$line" == "c" || "$line" == "C" ]]; then
            if read_custom_path; then TARGET_FILE="$CHOSEN_CUSTOM_PATH"; return 0; fi
            continue
        fi
        if [[ "$line" == "r" || "$line" == "R" ]]; then
            cmd="restore"
            if (( count == 1 )); then CHOSEN_INDEX=0; return 0; fi
            echo ""; echo "${TAG_INFO} Restore selected. Which Chrome do you want to restore?"
            while true; do
                echo -n "${C_BOLD}Which Chrome do you want to restore? [1-${count}, c=custom path, q=cancel]: ${C_RESET}"
                local restore_line; read -r restore_line || return 1
                if [[ "$restore_line" == "q" || "$restore_line" == "Q" ]]; then infof "Restore cancelled."; return 1; fi
                if [[ "$restore_line" == "c" || "$restore_line" == "C" ]]; then
                    if read_custom_path; then TARGET_FILE="$CHOSEN_CUSTOM_PATH"; return 0; fi
                    continue
                fi
                if [[ "$restore_line" =~ ^[0-9]+$ ]] && (( restore_line >= 1 && restore_line <= count )); then
                    CHOSEN_INDEX=$(( restore_line - 1 )); return 0
                fi
                errf "Enter a number between 1 and ${count}, c for custom path, or q to cancel."
            done
        fi
        if (( count == 1 )) && [[ -z "$line" ]]; then CHOSEN_INDEX=0; return 0; fi
        if [[ "$line" =~ ^[0-9]+$ ]] && (( line >= 1 && line <= count )); then CHOSEN_INDEX=$(( line - 1 )); return 0; fi
        if (( count == 1 )); then
            errf "Press Enter to accept, r to restore, c for custom path, or q to quit."
        else
            errf "Enter a number between 1 and ${count}, r to restore, c for custom path, or q to quit."
        fi
    done
}

choose_macos_install() {
    local count=${#MAC_APPS[@]} i
    if (( count == 0 )); then
        warnf "Couldn't find Google Chrome on this Mac."
        echo "    Give the path, e.g. bash $0 patch \"/path/to/Google Chrome.app\""
        return 1
    fi
    echo ""; echo "${TAG_INFO} Found ${count} Chrome install(s):"
    for (( i = 0; i < count; i++ )); do
        echo -n "  ${C_BOLD}$(( i + 1 ))${C_RESET}) ${C_CYN}${MAC_LABELS[$i]}${C_RESET}"
        [[ -n "${MAC_VERSIONS[$i]}" ]] && echo -n "  ${MAC_VERSIONS[$i]}"
        ${MAC_RUNNING[$i]} && echo -n "  ${C_YEL}[open]${C_RESET}" || echo -n "  ${C_GRN}[closed]${C_RESET}"
        echo ""; echo "      ${C_DIM}${MAC_APPS[$i]}${C_RESET}"
    done
    while true; do
        echo -n "${C_BOLD}Which install? [1-${count}, q=quit]: ${C_RESET}"
        local line; read -r line || return 1
        [[ "$line" == q || "$line" == Q ]] && return 1
        if [[ "$line" =~ ^[0-9]+$ ]] && (( line >= 1 && line <= count )); then CHOSEN_INDEX=$(( line - 1 )); return 0; fi
        errf "Enter a number between 1 and ${count}, or q."
    done
}

# ============================================================================
# Orchestration - ELF flow (Linux). Uses the shared slice engine on the single
# elf slice; keeps the strict backup-must-be-complete-stock safety checks.
# ============================================================================
do_patch_elf() {
    local target="$1" assume_yes="$2" allow_partial="$3"
    local fsize; fsize=$(file_size "$target")
    (( fsize > 0 )) || { errf "That file is empty."; return 1; }
    okf "Read Chrome from ${target}."

    parse_elf "$target" || return 1
    local target_id target_hash
    target_id=$(get_elf_build_id "$target")
    target_hash=$(file_sha256 "$target")
    [[ -n "$target_id" ]] || { errf "This doesn't look like a valid Chrome file."; return 1; }

    infof "Checking your Chrome version..."
    probe_slice 0 "$target"
    if (( BEST_SATISFIED == 0 )); then
        report_layout_candidates "$target"
        warnf "This Chrome version isn't recognized - nothing was changed."
        return 1
    fi
    if ! $BEST_FULL && (( BEST_TIES > 1 )); then
        warnf "Couldn't tell which Chrome version this is - nothing was changed."
        return 1
    fi
    classify_flip_states_slice "$target" || { errf "Chrome looks partly changed or damaged - nothing was changed."; return 1; }

    local backup="${target}.bak"
    local work_file; work_file=$(mktemp "${TMPDIR:-/tmp}/chrome-mv2-work.XXXXXX"); WORK_FILE="$work_file"

    if [[ ! -f "$backup" ]]; then
        # Already fully patched, but no backup to prove the pre-patch bytes: MV2 is
        # already on, so report that rather than the scary "not untouched" decline.
        if $BEST_FULL && (( STATE_STOCK == 0 && STATE_PATCHED > 0 )); then
            rm -f -- "$work_file"; WORK_FILE=""
            successf "Chrome is already patched - Manifest V2 is already on (Chrome ${BEST_MS_NAME})."
            echo "          There's no backup here, so 'restore' isn't available."
            echo "          Reinstall Chrome if you want a clean, restorable copy."
            return 0
        fi
        if { ! $BEST_FULL && ! $allow_partial; } || (( STATE_PATCHED != 0 )); then
            errf "There's no backup yet, and this doesn't look like an untouched Chrome."
            echo "    Reinstall Chrome first so we can save a clean backup."
            rm -f -- "$work_file"; WORK_FILE=""; return 1
        fi
        infof "Saving a backup..."
        save_backup_snapshot "$target" "$backup" "$target" "$target_id" || { rm -f -- "$work_file"; WORK_FILE=""; return 1; }
        validate_backup_snapshot "$backup" || { errf "The backup couldn't be verified."; rm -f -- "$work_file"; WORK_FILE=""; return 1; }
        okf "Backup saved."
    else
        validate_backup_snapshot "$backup" || { errf "The backup couldn't be verified, so I won't overwrite it."; rm -f -- "$work_file"; WORK_FILE=""; return 1; }
        parse_elf "$backup" || { rm -f -- "$work_file"; WORK_FILE=""; return 1; }
        probe_slice 0 "$backup"
        classify_flip_states_slice "$backup" || { errf "The backup looks damaged."; rm -f -- "$work_file"; WORK_FILE=""; return 1; }
        if { ! $BEST_FULL && ! $allow_partial; } || (( BEST_TIES != 1 || STATE_PATCHED != 0 )); then
            errf "The backup doesn't look like an untouched Chrome."; rm -f -- "$work_file"; WORK_FILE=""; return 1
        fi
        if [[ "$target_id" != "$BACKUP_BUILD_ID" ]]; then
            parse_elf "$target" || { rm -f -- "$work_file"; WORK_FILE=""; return 1; }
            probe_slice 0 "$target"
            classify_flip_states_slice "$target" || { rm -f -- "$work_file"; WORK_FILE=""; return 1; }
            if ! $BEST_FULL || (( BEST_TIES != 1 || STATE_PATCHED != 0 )); then
                errf "This updated Chrome isn't fully supported yet."
                echo "    Your backup was kept. Please report this Chrome version."
                rm -f -- "$work_file"; WORK_FILE=""; return 1
            fi
            infof "Chrome was updated - saving a fresh backup..."
            save_backup_snapshot "$target" "$backup" "$target" "$target_id" || { rm -f -- "$work_file"; WORK_FILE=""; return 1; }
            validate_backup_snapshot "$backup" || { errf "The new backup couldn't be verified."; rm -f -- "$work_file"; WORK_FILE=""; return 1; }
            okf "Backup updated."
        elif $BACKUP_LEGACY; then
            save_backup_snapshot "$target" "$backup" "$backup" "$BACKUP_BUILD_ID" || { rm -f -- "$work_file"; WORK_FILE=""; return 1; }
            okf "Backup checked and updated."
        fi
    fi
    cp -- "$backup" "$work_file"
    parse_elf "$work_file" || { rm -f -- "$work_file"; WORK_FILE=""; return 1; }
    probe_slice 0 "$work_file"
    if (( BEST_SATISFIED == 0 )); then
        report_layout_candidates "$work_file"
        warnf "This Chrome version isn't recognized."
        rm -f -- "$work_file"; WORK_FILE=""; return 1
    fi
    if ! $BEST_FULL && (( BEST_TIES > 1 )); then
        warnf "Couldn't tell which Chrome version this is - nothing was changed."
        rm -f -- "$work_file"; WORK_FILE=""; return 1
    fi
    if ! $BEST_FULL && ! $allow_partial; then
        warnf "Only ${BEST_SATISFIED} of ${BEST_TOTAL} changes matched; a partial patch needs --allow-partial."
        rm -f -- "$work_file"; WORK_FILE=""; return 1
    fi

    infof "Found Chrome ${BEST_MS_NAME}. Applying ${#FLIP_OFFSETS[@]} change(s)..."
    apply_flips_slice "$work_file"

    # Verify the prepared image is fully flipped and unambiguous.
    parse_elf "$work_file" || { rm -f -- "$work_file"; WORK_FILE=""; return 1; }
    probe_slice 0 "$work_file"
    (( BEST_SATISFIED > 0 && BEST_TIES == 1 )) || { errf "Something went wrong while preparing the change - nothing was changed."; rm -f -- "$work_file"; WORK_FILE=""; return 1; }
    classify_flip_states_slice "$work_file" || { errf "Something went wrong while preparing the change - nothing was changed."; rm -f -- "$work_file"; WORK_FILE=""; return 1; }
    (( STATE_STOCK == 0 && STATE_PATCHED == ${#FLIP_OFFSETS[@]} )) || { errf "Something went wrong while preparing the change - nothing was changed."; rm -f -- "$work_file"; WORK_FILE=""; return 1; }

    local prepared_hash; prepared_hash=$(file_sha256 "$work_file")
    if [[ "$prepared_hash" == "$target_hash" ]]; then
        rm -f -- "$work_file"; WORK_FILE=""
        successf "Already done - no change was needed."
        return 0
    fi
    if [[ "$target_hash" != "$BACKUP_HASH" ]]; then
        errf "This Chrome has other changes we didn't make, so we won't overwrite it."
        echo "    Reinstall Chrome, or check the file yourself, then try again."
        rm -f -- "$work_file"; WORK_FILE=""; return 1
    fi

    request_target_close "$target" "$assume_yes" || { rm -f -- "$work_file"; WORK_FILE=""; return 1; }
    if (( $(proc_holders "$target") > 0 )); then
        errf "Chrome reopened before we could finish - nothing was changed."
        rm -f -- "$work_file"; WORK_FILE=""; return 1
    fi
    write_target "$target" "$work_file" "$target_hash" "$prepared_hash" || { rm -f -- "$work_file"; WORK_FILE=""; return 1; }
    rm -f -- "$work_file"; WORK_FILE=""
    # write_target verified the copy against prepared_hash before the atomic mv,
    # so the target now equals the prepared image - no post-write re-read needed.

    rule
    if $BEST_FULL; then
        successf "Done. Manifest V2 re-enabled."
        echo "          Your older extensions will work again (Chrome ${BEST_MS_NAME}). Restart Chrome."
    else
        echo "${TAG_WARNING} Only part of the change was applied (Chrome ${BEST_MS_NAME}, ${BEST_SATISFIED}/${BEST_TOTAL})."
        echo "          $((BEST_TOTAL - BEST_SATISFIED)) part(s) couldn't be found, so this may not fully work."
        echo "          Please report your Chrome version. To undo: sudo bash $0 restore"
    fi
    rule
    return 0
}

do_restore_elf() {
    local target="$1" assume_yes="$2" force_restore="$3"
    local backup="${target}.bak"
    infof "Restoring the original Chrome..."
    [[ -f "$backup" ]] || { errf "No backup found, so there's nothing to restore."; return 1; }
    validate_backup_snapshot "$backup" || { errf "The backup couldn't be verified."; return 1; }
    parse_elf "$backup" || return 1
    probe_slice 0 "$backup"
    classify_flip_states_slice "$backup" || return 1
    if (( BEST_SATISFIED == 0 || BEST_TIES != 1 || STATE_PATCHED != 0 )); then
        errf "The backup doesn't look like an untouched Chrome."; return 1
    fi
    okf "Backup looks good (Chrome ${BEST_MS_NAME})."
    parse_elf "$target" || return 1
    local target_id target_hash
    target_id=$(get_elf_build_id "$target")
    target_hash=$(file_sha256 "$target")
    if [[ "$target_id" != "$BACKUP_BUILD_ID" ]] && ! $force_restore; then
        errf "This backup is from a different Chrome version, so I won't use it."
        echo "    Add --force-restore only if you really mean to go back to that version."
        return 1
    fi
    if [[ "$target_id" != "$BACKUP_BUILD_ID" ]]; then warnf "Restoring a different Chrome version (--force-restore)."; fi
    if [[ "$target_hash" == "$BACKUP_HASH" ]]; then
        successf "Chrome is already the original - nothing to undo."
        rm -f -- "$backup" "$(backup_meta_path "$backup")"
        infof "Backup removed - Chrome is back to normal."
        return 0
    fi
    request_target_close "$target" "$assume_yes" || return 1
    if (( $(proc_holders "$target") > 0 )); then errf "Chrome reopened before we could finish - nothing was changed."; return 1; fi
    write_target "$target" "$backup" "$target_hash" "$BACKUP_HASH" || return 1
    successf "Done. Your original Chrome is back."
    rm -f -- "$backup" "$(backup_meta_path "$backup")"
    infof "Backup removed - Chrome is back to normal."
    return 0
}

do_check_elf() {
    local target="$1" build_id size hash
    parse_elf "$target" || return 1
    build_id=$(get_elf_build_id "$target"); size=$(file_size "$target"); hash=$(file_sha256 "$target")
    probe_slice 0 "$target"
    if (( BEST_SATISFIED == 0 )); then
        warnf "This Chrome version isn't recognized yet."
    elif ! $BEST_FULL && (( BEST_TIES > 1 )); then
        warnf "Couldn't tell which Chrome version this is."
    else
        classify_flip_states_slice "$target" || { warnf "Chrome looks partly changed or damaged."; return 1; }
        local state="already patched"
        (( STATE_STOCK > 0 && STATE_PATCHED == 0 )) && state="not patched yet"
        (( STATE_STOCK > 0 && STATE_PATCHED > 0 )) && state="partly patched"
        okf "This is Chrome ${BEST_MS_NAME} - ${state}."
    fi
    local backup="${target}.bak"
    if [[ -f "$backup" ]]; then
        if validate_backup_snapshot "$backup"; then
            okf "A backup is saved."
        else
            warnf "A backup exists but looks damaged."
        fi
    else
        infof "No backup saved yet."
    fi
    $BEST_FULL && (( BEST_TIES == 1 ))
}

# ============================================================================
# Orchestration - Mach-O flow (macOS). Per-slice probe/flip on the host slice,
# UUID-keyed backup outside the bundle, ad-hoc inside-out re-sign.
# ============================================================================
do_check_macho() {
    local target="$1"
    parse_macho "$target" || return 1
    compute_identity "$target"; TARGET_TOKEN=$(identity_token)
    local idx
    for (( idx = 0; idx < NUM_SLICES; idx++ )); do
        local c="${SLICE_CONTAINER[$idx]}"
        probe_slice "$idx" "$target"
        if (( BEST_SATISFIED == 0 )); then
            warnf "  ${c#macho-}: this Chrome version isn't recognized yet."
        elif ! $BEST_FULL && (( BEST_TIES > 1 )); then
            warnf "  ${c#macho-}: couldn't tell which Chrome version this is."
        else
            if classify_flip_states_slice "$target"; then
                local state="not patched yet"
                if (( STATE_PATCHED > 0 && STATE_STOCK == 0 )); then state="already patched"
                elif (( STATE_PATCHED > 0 && STATE_STOCK > 0 )); then state="partly patched"; fi
                okf "  ${c#macho-}: Chrome ${BEST_MS_NAME} - ${state}."
            else
                warnf "  ${c#macho-}: looks partly changed or damaged."
            fi
        fi
    done
    local backup; backup=$(backup_path)
    if [[ -f "$backup" ]]; then
        if validate_backup_snapshot "$backup"; then okf "A backup is saved."
        else warnf "A backup exists but looks damaged."; fi
    else infof "No backup saved yet."; fi
    return 0
}

# Remove a Mach-O backup and its metadata after a successful restore. For a real
# .app the backup lives in a UUID-keyed dir under Application Support; prune the
# now-empty dir (and the brand dir) too. Loose Mach-O keeps <file>.bak beside it.
remove_macho_backup() {
    local backup="$1"
    rm -f -- "$backup" "$(backup_meta_path "$backup")"
    if [[ "$TARGET_CONTAINER" == "macho" && -n "$APP_PATH" ]]; then
        rmdir -- "$(backup_dir)" 2>/dev/null || true
        rmdir -- "$(dirname "$(backup_dir)")" 2>/dev/null || true
    fi
}

do_restore_macho() {
    local target="$1" app_path="$2" assume_yes="$3" force_restore="$4"
    infof "Restoring the original Chrome..."
    parse_macho "$target" >/dev/null || return 1
    compute_identity "$target"; local target_id="$IDENTITY_UUIDS"
    TARGET_TOKEN=$(identity_token)                 # backup dir is keyed by this
    local backup; backup=$(backup_path)
    [[ -f "$backup" ]] || { errf "No backup found, so there's nothing to restore."; return 1; }
    validate_backup_snapshot "$backup" || { errf "The backup couldn't be verified."; return 1; }
    okf "Backup looks good."

    local target_hash; target_hash=$(file_sha256 "$target")
    if [[ "$target_id" != "$BACKUP_IDENTITY" ]] && ! $force_restore; then
        errf "This backup is from a different Chrome version, so I won't use it."
        echo "    Add --force-restore only if you really mean to go back to that version."; return 1
    fi
    if [[ "$target_hash" == "$BACKUP_HASH" ]]; then
        successf "Chrome is already the original - nothing to undo."
        remove_macho_backup "$backup"
        infof "Backup removed - Chrome is back to normal."
        return 0
    fi

    if [[ -n "$app_path" ]]; then quit_chrome "$app_path" "$assume_yes" || return 1; fi
    write_target "$target" "$backup" "$target_hash" "$BACKUP_HASH" || return 1
    if [[ -n "$app_path" ]] && have_codesign; then
        resign_inside_out "$FRAMEWORK_BUNDLE" "$app_path" || warnf "Re-signing failed. Try again: bash $0 restore \"$app_path\""
    fi
    successf "Done. Your original Chrome is back."
    remove_macho_backup "$backup"
    infof "Backup removed - Chrome is back to normal."
    return 0
}

do_patch_macho() {
    local target="$1" app_path="$2" assume_yes="$3" allow_partial="$4"
    local size; size=$(file_size "$target")
    (( size > 0 )) || { errf "That file is empty."; return 1; }
    okf "Read Chrome from ${target}."
    parse_macho "$target" || return 1
    compute_identity "$target"; local target_id="$IDENTITY_UUIDS"
    TARGET_TOKEN=$(identity_token)                 # backup dir is keyed by this
    local target_hash; target_hash=$(file_sha256 "$target")

    # Decide which slices we will patch (probe each against the live target).
    local idx to_patch=() ic=() any=false default_declined=false
    for (( idx = 0; idx < NUM_SLICES; idx++ )); do
        local c="${SLICE_CONTAINER[$idx]}"
        probe_slice "$idx" "$target"
        if slice_decision "$c" "$allow_partial"; then
            to_patch+=("$idx"); ic+=("$c"); any=true
            infof "  ${c#macho-}: found Chrome ${BEST_MS_NAME} - will patch."
        else
            warnf "  ${c#macho-}: skipped (${SKIP_REASON})."
            [[ "$c" == "macho-x64" ]] && default_declined=true
        fi
    done
    if ! $any; then errf "This Chrome version isn't recognized - nothing was changed."; return 1; fi

    local backup; backup=$(backup_path)
    if [[ ! -f "$backup" ]]; then
        infof "Saving a backup..."
        save_backup_snapshot "$target" "$backup" "$target" "$target_id" || return 1
        validate_backup_snapshot "$backup" || { errf "The backup couldn't be verified."; return 1; }
    else
        validate_backup_snapshot "$backup" || { errf "The backup couldn't be verified, so I won't overwrite it."; return 1; }
        if [[ "$target_id" != "$BACKUP_IDENTITY" ]]; then
            infof "Chrome was updated - saving a fresh backup..."
            save_backup_snapshot "$target" "$backup" "$target" "$target_id" || return 1
            validate_backup_snapshot "$backup" || { errf "The new backup couldn't be verified."; return 1; }
        elif $BACKUP_LEGACY; then
            save_backup_snapshot "$target" "$backup" "$backup" "$BACKUP_IDENTITY" || return 1
        fi
    fi

    # Build the patched image from the clean backup, per slice.
    local work; work=$(mktemp "${TMPDIR:-/tmp}/chrome-mv2-work.XXXXXX"); WORK_FILE="$work"
    cp -- "$backup" "$work"
    parse_macho "$work" >/dev/null || { rm -f -- "$work"; WORK_FILE=""; return 1; }
    local k
    for k in "${to_patch[@]}"; do
        probe_slice "$k" "$work"
        apply_flips_slice "$work"
    done
    # Verify the prepared slices are fully flipped.
    parse_macho "$work" >/dev/null || { rm -f -- "$work"; WORK_FILE=""; return 1; }
    for k in "${to_patch[@]}"; do
        probe_slice "$k" "$work"
        classify_flip_states_slice "$work" || { errf "Something went wrong while preparing the change - nothing was changed."; rm -f -- "$work"; WORK_FILE=""; return 1; }
        if (( STATE_STOCK != 0 )); then errf "Something went wrong while preparing the change - nothing was changed."; rm -f -- "$work"; WORK_FILE=""; return 1; fi
    done

    local prepared_hash; prepared_hash=$(file_sha256 "$work")
    if [[ "$prepared_hash" == "$target_hash" ]]; then rm -f -- "$work"; WORK_FILE=""; successf "Already done - no change was needed."; return 0; fi
    if [[ "$target_hash" != "$BACKUP_HASH" ]]; then
        errf "This Chrome has other changes we didn't make, so we won't overwrite it."
        echo "    Reinstall Chrome, or check the file yourself, then try again."; rm -f -- "$work"; WORK_FILE=""; return 1
    fi

    if [[ -n "$app_path" ]]; then quit_chrome "$app_path" "$assume_yes" || { rm -f -- "$work"; WORK_FILE=""; return 1; }; fi
    write_target "$target" "$work" "$target_hash" "$prepared_hash" || { rm -f -- "$work"; WORK_FILE=""; return 1; }
    rm -f -- "$work"; WORK_FILE=""

    # Re-sign the now-modified bundle inside-out, then verify. On any failure,
    # roll the framework binary back to the pristine backup and re-sign as best we
    # can, then report the true state (see below) rather than assume a clean stock.
    if [[ -n "$app_path" ]]; then
        if have_codesign; then
            if ! resign_inside_out "$FRAMEWORK_BUNDLE" "$app_path" || ! verify_signature "$app_path"; then
                errf "Re-signing failed - putting the original Chrome back."
                write_target "$target" "$backup" "" || true
                # resign_inside_out signs inside-out, so it may have already re-signed
                # sibling bundle components before failing. A framework-only rollback
                # cannot undo those, so the bundle can be left in a mixed signing
                # state. Re-sign+verify the reverted bundle and report honestly.
                if resign_inside_out "$FRAMEWORK_BUNDLE" "$app_path" >/dev/null 2>&1 \
                   && verify_signature "$app_path" >/dev/null 2>&1; then
                    infof "Restored the original Chrome. It should open normally."
                else
                    warnf "Chrome may not open. Run a full restore to be safe."
                    echo "    To restore: bash $0 restore \"$app_path\""
                fi
                return 1
            fi
            okf "Re-signed and verified."
        else
            errf "Couldn't find 'codesign' (it normally comes with macOS)."
            echo "    Chrome was changed but isn't signed, so it may not open."
            echo "    To restore: bash $0 restore \"$app_path\""
            return 1
        fi
    fi

    rule
    successf "Done. Manifest V2 re-enabled."
    [[ -n "$app_path" ]] && echo "          Restart Chrome. To undo: bash $0 restore \"$app_path\""
    rule
    return 0
}

# ============================================================================
# Target resolution + entry point
# ============================================================================
# Resolve a user-supplied path into TARGET_CONTAINER / TARGET_FILE / APP_PATH /
# FRAMEWORK_BUNDLE. A .app/.framework or a Mach-O file is the macOS flow; an ELF
# file is the Linux flow. The container is decided by magic, not the host OS, so
# a scratch copy of either binary can be patched anywhere bash runs.
resolve_any_target() {
    local path="$1"
    APP_PATH=""; FRAMEWORK_BUNDLE=""; TARGET_FILE=""; TARGET_CONTAINER=""
    if [[ -d "$path" ]]; then
        case "$path" in
            *.app|*.framework) TARGET_CONTAINER="macho"; resolve_macho_target "$path" || return 1 ;;
            *) errf "That folder isn't a Chrome app: ${path}"; return 1 ;;
        esac
    elif [[ -f "$path" ]]; then
        local kind; kind=$(detect_container_kind "$path")
        case "$kind" in
            elf)   TARGET_CONTAINER="elf"; TARGET_FILE="$path" ;;
            macho) TARGET_CONTAINER="macho"; resolve_macho_target "$path" || return 1 ;;
            *)     errf "That doesn't look like a Chrome file: ${path}"; return 1 ;;
        esac
    else
        errf "That path doesn't exist: ${path}"; return 1
    fi
    return 0
}

print_usage() {
    cat <<EOF
Usage: bash chrome-mv2.sh [command] [path] [options]

Turns Manifest V2 extension support back on in Google Chrome. Works on both
Linux (the chrome binary) and macOS (Google Chrome.app). On macOS it also
re-signs the app so it opens normally.

Commands:
  patch                  Turn Manifest V2 back on (default).
  restore                Undo the change and put the original Chrome back.
  check                  Show the current status. Changes nothing.

Arguments:
  path                   Path to Chrome. On macOS, a Google Chrome.app also works.
                         If left out, installed Chrome is found automatically.

Options:
  -y, --yes              Close a running Chrome without asking.
  -q, --quiet            Don't ask any questions (for scripts).
      --allow-partial    Developer option: allow an incomplete patch.
      --force-restore    Restore a backup from a different Chrome version.
      --signatures PATH  Use an external signatures file (needs python3).
  -v, --version          Show the version and exit.
  -h, --help             Show this help and exit.

Environment:
  MV2_TEST_NO_ELEVATION  Skip the write-permission check (tests only).
  MV2_TEST_HOST_ARCH     Force the detected Mac host CPU (arm64/x86_64; tests).
  NO_COLOR / FORCE_COLOR Disable / force ANSI colour.
EOF
}

cleanup() {
    local rc=$?      # preserve the real exit status; the trap must not mask it
    local t
    for t in "${WORK_FILE:-}" "${WRITE_TMP:-}" "${META_TMP:-}"; do
        [[ -n "$t" && -f "$t" ]] && rm -f -- "$t"
    done
    # On failure, hold a double-clicked terminal open so the error stays visible.
    # Skip when scripting (--quiet) or with no interactive terminal (CI/pipes/tests).
    if (( rc != 0 )) && ! ${QUIET:-false} && [[ -t 0 && -t 1 ]]; then
        echo
        read -n 1 -s -r -p "Press any key to exit..." || true
        echo
    fi
    return "$rc"
}
trap cleanup EXIT

main() {
    init_colors
    local cmd="patch" target_path="" assume_yes=false allow_partial=false force_restore=false
    QUIET=false
    local positional=()
    while (( $# > 0 )); do
        case "$1" in
            --yes|-y) assume_yes=true ;;
            --quiet|-q) QUIET=true ;;
            --allow-partial) allow_partial=true ;;
            --force-restore) force_restore=true ;;
            --signatures) (( $# >= 2 )) || { errf "--signatures needs a path."; exit 2; }; SIGNATURES_OVERRIDE="$2"; shift ;;
            --) shift; while (( $# > 0 )); do positional+=("$1"); shift; done; break ;;
            --version|-v) echo "chrome-mv2-patch ${APP_VERSION}"; exit 0 ;;
            --help|-h) print_usage; exit 0 ;;
            -*) errf "Unknown option: $1"; print_usage; exit 2 ;;
            *) positional+=("$1") ;;
        esac
        shift
    done
    if (( ${#positional[@]} >= 1 )); then
        case "${positional[0]}" in
            patch|restore|check) cmd="${positional[0]}"; (( ${#positional[@]} >= 2 )) && target_path="${positional[1]}" ;;
            *) target_path="${positional[0]}" ;;
        esac
    fi
    (( ${#positional[@]} <= 2 )) || { errf "Too many arguments."; print_usage; exit 2; }

    load_milestones || exit 1
    banner

    local tool
    for tool in od dd grep head mktemp cp mv awk; do
        command -v "$tool" >/dev/null 2>&1 || { errf "A required tool is missing: '${tool}'."; exit 1; }
    done
    command -v shasum >/dev/null 2>&1 || command -v sha256sum >/dev/null 2>&1 || { errf "Need shasum or sha256sum."; exit 1; }

    # Resolve the target. A given path is dispatched by magic; otherwise install
    # discovery is chosen by the host OS.
    if [[ -n "$target_path" ]]; then
        [[ -e "$target_path" ]] || { errf "That path doesn't exist: ${target_path}"; exit 1; }
        resolve_any_target "$target_path" || exit 1
    elif [[ "$(uname -s 2>/dev/null || echo)" == "Darwin" ]]; then
        infof "Looking for Chrome..."
        enumerate_macos_installs
        if $QUIET; then
            (( ${#MAC_APPS[@]} == 1 )) || { errf "With --quiet, give the path to the Chrome you want."; exit 1; }
            CHOSEN_INDEX=0
        else
            choose_macos_install || exit 0
        fi
        APP_PATH="${MAC_APPS[$CHOSEN_INDEX]}"; TARGET_CONTAINER="macho"
        resolve_framework_from_app "$APP_PATH" || { errf "Couldn't find Chrome inside ${APP_PATH}"; exit 1; }
    else
        infof "Looking for Chrome..."
        enumerate_linux_installs
        if $QUIET; then
            if (( ${#LNX_CHANNELS[@]} == 0 )); then
                errf "Couldn't find Chrome on this computer."
                echo "    Give the path, e.g. sudo bash $0 patch /path/to/chrome"; exit 1
            fi
            if (( ${#LNX_CHANNELS[@]} > 1 )); then
                errf "Found ${#LNX_CHANNELS[@]} Chrome versions, and --quiet can't ask which one."
                local j; for (( j = 0; j < ${#LNX_CHANNELS[@]}; j++ )); do print_linux_install_row $(( j + 1 )) "$j"; done
                echo "    Re-run with the path of the one you want."; exit 1
            fi
            CHOSEN_INDEX=0
        else
            choose_linux_install || exit 0
        fi
        if [[ -z "$TARGET_FILE" ]]; then TARGET_FILE="${LNX_PATHS[$CHOSEN_INDEX]}"; fi
        TARGET_CONTAINER="elf"
    fi
    if [[ "$TARGET_CONTAINER" == "macho" ]]; then
        detect_host_container
        infof "Your Mac: $(host_arch_label)."
        okf "File: ${TARGET_FILE}"
        if [[ -n "$APP_PATH" ]]; then
            okf "App: ${APP_PATH}"
        elif [[ "$cmd" != "check" ]]; then
            warnf "No app found - the re-signing step will be skipped."
        fi
    else
        okf "Chrome: ${C_CYN}$(basename "$(dirname "$TARGET_FILE")")${C_RESET}"
        okf "File: ${TARGET_FILE}"
    fi

    # Check is read-only. Patch/restore need write access to the target and its
    # directory for the atomic replace/backup, but a user-owned offline copy
    # should not require root.
    if [[ "$cmd" != "check" && -z "${MV2_TEST_NO_ELEVATION:-}" ]]; then
        local dir; dir=$(dirname "$TARGET_FILE")
        if [[ ! -w "$TARGET_FILE" || ! -w "$dir" ]]; then
            errf "Can't write to Chrome here."
            echo "    Re-run with sudo, or use a copy you can write to."
            exit 1
        fi
    fi

    case "$cmd" in
        restore)
            if [[ "$TARGET_CONTAINER" == "elf" ]]; then do_restore_elf "$TARGET_FILE" "$assume_yes" "$force_restore"
            else do_restore_macho "$TARGET_FILE" "$APP_PATH" "$assume_yes" "$force_restore"; fi ;;
        patch)
            if [[ "$TARGET_CONTAINER" == "elf" ]]; then do_patch_elf "$TARGET_FILE" "$assume_yes" "$allow_partial"
            else do_patch_macho "$TARGET_FILE" "$APP_PATH" "$assume_yes" "$allow_partial"; fi ;;
        check)
            if [[ "$TARGET_CONTAINER" == "elf" ]]; then do_check_elf "$TARGET_FILE"
            else do_check_macho "$TARGET_FILE"; fi ;;
    esac
}

if [[ -z "${MV2_TEST_LIBRARY_ONLY:-}" ]]; then
    main "$@"
fi
