"""Apply / check / restore the MV2 gate flips on a Windows chrome.dll.

Why this exists: on machines where a WDAC code-integrity policy forces Windows
PowerShell into ConstrainedLanguage, chrome-mv2.ps1 cannot run at all (it needs
Add-Type, [pscustomobject] and [IO.File] method calls). This is the same engine
in Python, reusing the repo's already-tested image parser and masked matcher
from derive_milestone.py so only the write path is new code.

Semantics mirrored from chrome-mv2.ps1:
  - a site counts as located only when its signature matches EXACTLY
    expectedMatches times; a different count declines the site
  - milestone ranking: full beats partial; among fulls the one with more sites
    wins; an equal-rank tie declines
  - flips, and nothing else:
        short  0x7F disp8       -> 0xEB disp8
        near   0x0F 0x8F disp32 -> 0x90 0xE9 disp32
        bcond  arm64 b.gt (cond 0xC) -> b.al (cond 0xE), imm19 preserved
  - finalize: clear the Authenticode Security directory, recompute the PE
    checksum
  - backup: <target>.bak plus a <target>.bak.json identity sidecar in the exact
    format chrome-mv2.ps1 reads (Schema/Format/Machine/TimeStamp/Length/SHA256)

Usage:
    python scripts/mv2_apply.py check   "C:\\...\\chrome.dll"
    python scripts/mv2_apply.py patch   "C:\\...\\chrome.dll" [--out COPY] [--allow-partial]
    python scripts/mv2_apply.py restore "C:\\...\\chrome.dll"
"""

import argparse
import hashlib
import json
import os
import struct
import sys
from array import array
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from derive_milestone import masked_match_count, open_images  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
DEFAULT_JSON = REPO / "signatures.json"


# ---------------------------------------------------------------------------
# PE fields the matcher does not need: checksum slot, Security directory.
# ---------------------------------------------------------------------------
def pe_fields(data):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    timestamp = struct.unpack_from("<I", data, e_lfanew + 8)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    fixed_len = 96 if magic == 0x10B else 112
    return {
        "machine": machine,
        "timestamp": timestamp,
        "checksum_at": opt + 64,               # same slot in PE32 and PE32+
        "secdir_at": opt + fixed_len + 4 * 8,  # data directory [4] = Security
    }


def pe_checksum(data, checksum_off):
    """Same value as Mv2Native.PeChecksum: 16-bit ones-complement sum of the
    file with the CheckSum dword excluded, plus the file size."""
    dwords = len(data) // 4
    words = array("I")
    words.frombytes(bytes(memoryview(data)[:dwords * 4]))
    if sys.byteorder != "little":
        words.byteswap()
    total = sum(words) - words[checksum_off // 4]
    rem = len(data) % 4
    if rem:
        total += int.from_bytes(bytes(memoryview(data)[dwords * 4:]), "little")
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (total + len(data)) & 0xFFFFFFFF


def sha256(data):
    h = hashlib.sha256()
    h.update(memoryview(data))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Locate + rank (mirrors Find-AffectedJgSites / Invoke-PatchMilestones)
# ---------------------------------------------------------------------------
NEAR_PAIRS = (b"\x0f\x8f", b"\x90\xe9")


def locate_milestone(img, ms):
    """-> (located_site_count, flips) where each flip is (site, file_offset)."""
    located = 0
    flips = []
    for s in ms["sites"]:
        expected = int(s["expectedMatches"])
        sig = bytes.fromhex(s["sig"])
        jg_off = int(s["jgOff"])
        hits = masked_match_count(img.text, sig, jg_off, s["kind"], cap=expected + 2)
        if s["kind"] == "near":
            # masked_match_count masks the two near-jg opcode bytes independently,
            # so it also accepts the half-flipped pairs 0F E9 / 90 8F. The runtime
            # patchers require the pair to be exactly 0F 8F (stock) or 90 E9
            # (patched); anything else is a state this tool never produces and is
            # dropped here, which lets the exact-count rule decline the site.
            hits = [h for h in hits
                    if bytes(img.text[h + jg_off:h + jg_off + 2]) in NEAR_PAIRS]
        if len(hits) != expected:
            continue
        located += 1
        for start in hits:
            flips.append((s, img.text_raw + start + jg_off))
    return located, flips


def pick_milestone(img, milestones):
    """-> (milestone, flips, located, tied). Full beats partial; among fulls the
    bigger table wins; an equal-rank collision sets tied."""
    best = None
    tied = False
    for ms in milestones:
        located, flips = locate_milestone(img, ms)
        if located == 0:
            continue
        total = len(ms["sites"])
        cand_full = located == total
        if best is None:
            best, tied = (ms, flips, located, total, cand_full), False
            continue
        b_ms, b_flips, b_loc, b_total, b_full = best
        if cand_full and not b_full:
            best, tied = (ms, flips, located, total, cand_full), False
        elif cand_full and b_full and total > b_total:
            best, tied = (ms, flips, located, total, cand_full), False
        elif not cand_full and not b_full and located > b_loc:
            best, tied = (ms, flips, located, total, cand_full), False
        elif (cand_full and b_full and total == b_total) or \
             (not cand_full and not b_full and located == b_loc):
            tied = True
    if best is None:
        return None, [], 0, False
    return best[0], best[1], best[2], tied


STOCK, PATCHED, ODD = "stock", "patched", "odd"


def flip_state(buf, off, kind):
    """Current state of one gate, plus the bytes that patch it."""
    if kind == "short":
        cur = buf[off]
        if cur == 0xEB:
            return PATCHED, b"\xeb"
        return (STOCK, b"\xeb") if cur == 0x7F else (ODD, b"")
    if kind == "near":
        pair = bytes(buf[off:off + 2])
        if pair == b"\x90\xe9":
            return PATCHED, b"\x90\xe9"
        return (STOCK, b"\x90\xe9") if pair == b"\x0f\x8f" else (ODD, b"")
    cur = buf[off]                      # bcond: cond nibble of byte0
    patched = bytes([(cur & 0xF0) | 0x0E])
    cond = cur & 0x0F
    if cond == 0x0E:
        return PATCHED, patched
    return (STOCK, patched) if cond == 0x0C else (ODD, b"")


# ---------------------------------------------------------------------------
# Backup + atomic write
# ---------------------------------------------------------------------------
def identity(buf, img, fields):
    return {
        "Schema": 1, "Format": img.container, "Machine": fields["machine"],
        "TimeStamp": fields["timestamp"], "Length": len(buf), "SHA256": sha256(buf),
    }


def write_atomic(target, buf, expected_current_hash=None):
    target = Path(target)
    tmp = target.with_name(".chrome-mv2-%s.tmp" % os.urandom(8).hex())
    try:
        with open(tmp, "wb") as fh:
            fh.write(buf)
            fh.flush()
            os.fsync(fh.fileno())
        if sha256(Path(tmp).read_bytes()) != sha256(buf):
            raise RuntimeError("write-back verification failed - nothing was changed")
        if expected_current_hash is not None and target.exists():
            if sha256(target.read_bytes()) != expected_current_hash:
                raise RuntimeError("the file changed while we were working - nothing was changed")
        os.replace(tmp, target)
        tmp = None
    finally:
        if tmp is not None and Path(tmp).exists():
            Path(tmp).unlink()


def save_backup(target, buf, ident):
    bak = Path(str(target) + ".bak")
    write_atomic(bak, buf)
    meta = json.dumps(ident, separators=(",", ":")) + "\n"
    write_atomic(Path(str(bak) + ".json"), meta.encode("utf-8"))
    return bak


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def load_table(json_path, container):
    doc = json.loads(Path(json_path).read_text(encoding="utf-8"))
    return [ms for ms in doc.get("milestones", []) if ms.get("container") == container]


def analyze(path, json_path):
    img = open_images(path)[0]
    if not img.container.startswith("pe"):
        raise SystemExit("error: this tool only patches Windows chrome.dll (PE)")
    buf = bytearray(img.data)
    fields = pe_fields(buf)
    ms, flips, located, tied = pick_milestone(img, load_table(json_path, img.container))
    return img, buf, fields, ms, flips, located, tied


def cmd_check(args):
    img, buf, fields, ms, flips, located, tied = analyze(args.target, args.signatures)
    stored = struct.unpack_from("<I", buf, fields["checksum_at"])[0]
    computed = pe_checksum(buf, fields["checksum_at"])
    sec_va, sec_sz = struct.unpack_from("<II", buf, fields["secdir_at"])

    print(f"file       : {args.target}")
    print(f"container  : {img.container} (machine 0x{fields['machine']:04X}, {len(buf)} bytes)")
    print(f"checksum   : stored 0x{stored:08X}  computed 0x{computed:08X}  "
          f"{'MATCH (algorithm self-test ok)' if stored == computed else 'MISMATCH'}")
    print(f"signature  : Security dir va=0x{sec_va:X} size={sec_sz} "
          f"({'present, stock-signed' if sec_va and sec_sz else 'cleared, already patched by this tool'})")
    if ms is None:
        print("milestone  : no known layout matched")
        return 1
    if tied:
        print(f"milestone  : ambiguous tie involving '{ms['name']}' - declining")
        return 1
    print(f"milestone  : {ms['name']} ({located}/{len(ms['sites'])} sites located)")

    counts = {STOCK: 0, PATCHED: 0, ODD: 0}
    for site, off in flips:
        state, _ = flip_state(buf, off, site["kind"])
        counts[state] += 1
        rva = img.rva(off - img.text_raw)
        print(f"    {state:7} {site['kind']:5} jg@0x{rva:08X}  {site['name'][:58]}")
    full = located == len(ms["sites"])
    print(f"state      : {counts[STOCK]} stock, {counts[PATCHED]} patched, {counts[ODD]} unexpected"
          f"  ({'complete layout' if full else 'PARTIAL layout'})")

    bak = Path(str(args.target) + ".bak")
    print(f"backup     : {'present at ' + str(bak) if bak.exists() else 'none yet'}")
    return 0 if full else 1


def cmd_patch(args):
    img, buf, fields, ms, flips, located, tied = analyze(args.target, args.signatures)
    if ms is None:
        raise SystemExit("error: no known layout matched - nothing was changed")
    if tied:
        raise SystemExit("error: two milestones tied - cannot tell which build this is")
    total = len(ms["sites"])
    if located != total and not args.allow_partial:
        raise SystemExit(f"error: only {located} of {total} sites located; "
                         f"pass --allow-partial to override (not recommended)")

    stock_hash = sha256(buf)
    plan, already, odd = [], 0, 0
    for site, off in flips:
        state, patched_bytes = flip_state(buf, off, site["kind"])
        if state == PATCHED:
            already += 1
        elif state == STOCK:
            plan.append((off, patched_bytes))
        else:
            odd += 1
            print(f"  ! skipped a gate that did not look as expected at 0x{off:X}")
    print(f"milestone {ms['name']}: {located}/{total} sites, "
          f"{len(plan)} to flip, {already} already flipped, {odd} skipped")
    if not plan:
        print("nothing to do - already patched")
        return 0

    for off, patched_bytes in plan:
        buf[off:off + len(patched_bytes)] = patched_bytes

    sec_va, sec_sz = struct.unpack_from("<II", buf, fields["secdir_at"])
    if sec_va or sec_sz:
        struct.pack_into("<II", buf, fields["secdir_at"], 0, 0)
    struct.pack_into("<I", buf, fields["checksum_at"],
                     pe_checksum(buf, fields["checksum_at"]))

    # Prove the write touches only what it is supposed to: the planned gate
    # bytes, the 8-byte Security directory, and the 4-byte checksum.
    allowed = set()
    for off, patched_bytes in plan:
        allowed.update(range(off, off + len(patched_bytes)))
    allowed.update(range(fields["secdir_at"], fields["secdir_at"] + 8))
    allowed.update(range(fields["checksum_at"], fields["checksum_at"] + 4))
    stock = img.data
    changed = [i for i in allowed if stock[i] != buf[i]]
    unexpected = 0
    step = 1 << 20
    for base in range(0, len(buf), step):
        a = memoryview(stock)[base:base + step]
        b = memoryview(buf)[base:base + step]
        if a == b:
            continue
        for i in range(base, min(base + step, len(buf))):
            if stock[i] != buf[i] and i not in allowed:
                unexpected += 1
    print(f"diff check : {len(changed)} intended byte(s) changed, {unexpected} unintended")
    if unexpected:
        raise SystemExit("error: unintended differences - refusing to write")

    if args.out:
        write_atomic(args.out, buf)
        print(f"wrote patched copy to {args.out} (target untouched)")
        return 0

    bak = Path(str(args.target) + ".bak")
    if not bak.exists():
        if already and not args.force:
            raise SystemExit("error: no backup exists and the file is already partly patched; "
                             "refusing to snapshot a modified DLL (use --force to override)")
        save_backup(args.target, img.data, identity(img.data, img, fields))
        print(f"backup     : saved {bak}")
    else:
        print(f"backup     : kept existing {bak}")

    write_atomic(args.target, buf, expected_current_hash=stock_hash)
    print(f"patched    : {args.target}")
    print("Restart Chrome, then load an MV2 extension to test.")
    return 0


def cmd_restore(args):
    bak = Path(str(args.target) + ".bak")
    if not bak.exists():
        raise SystemExit(f"error: no backup at {bak}")
    data = bak.read_bytes()
    meta_path = Path(str(bak) + ".json")
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        img = open_images(bak)[0]
        fields = pe_fields(data)
        want = identity(data, img, fields)
        for key in ("Format", "Machine", "TimeStamp", "Length", "SHA256"):
            if str(meta.get(key)).lower() != str(want[key]).lower():
                raise SystemExit(f"error: backup does not match its saved info ({key}) - not restoring")
        print("backup     : identity verified")
    else:
        print("backup     : no .json sidecar, restoring unverified")
    write_atomic(args.target, data)
    print(f"restored   : {args.target} (backup kept at {bak})")
    return 0


def main():
    ap = argparse.ArgumentParser(description="MV2 gate patcher for chrome.dll (Python port).")
    ap.add_argument("command", choices=("check", "patch", "restore"))
    ap.add_argument("target", help="path to chrome.dll")
    ap.add_argument("--signatures", default=str(DEFAULT_JSON))
    ap.add_argument("--out", help="patch: write the result here instead of replacing the target")
    ap.add_argument("--allow-partial", action="store_true")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    return {"check": cmd_check, "patch": cmd_patch, "restore": cmd_restore}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
