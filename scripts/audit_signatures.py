"""Audit signatures.json - the checks that catch the failure modes seen in the wild.

Table-only checks (no binary needed, fast, CI-friendly):

  tie        Two milestones in one container with an identical signature set.
             The runtime ranks candidates by "full beats partial, then most
             sites"; two equal-size fulls are a genuine equal-rank collision and
             the patcher DECLINES. `152-macos-arm64` and `154-macos-arm64` were
             byte-identical for months, so every 152/154 macOS-ARM install was
             refused outright. This is the single most damaging table defect and
             it is invisible from any one binary.
  fragile    A signature window that swallows PC-relative immediates (arm64
             adrp/adr, x86 lea rip+disp / call rel32). Those bytes encode a
             distance to another part of the image, so the site matches only the
             one artifact it was derived from - a different build of the SAME
             version silently drops the gate. Prefer a shorter window that stops
             before the relocation.
  anchor     The longest fixed (unmasked) run in a signature is what the runtime
             scans for. A short or ubiquitous anchor makes the relocation path
             crawl; `cmp w?,#2` alone occurs ~40k times in a Chrome arm64 .text.
  shape      Field sanity: kind/jgOff/expectedMatches/sig agree, the jump opcode
             actually sits at jgOff, and the sig is long enough to contain it.

With --binary, each given artifact is additionally cross-checked:

  verify     Which milestones fully match, and which one the runtime would pick.
  complete   An independent completeness pass that does NOT use the cmp,2;jg
             finder: anchor on the gate's most specific single marker (the
             `cmp byte[ext+FLAG],0` / `ldrb w,[ext,#FLAG]` load) and report any
             occurrence that has a manifest-version compare beside it yet no
             covering site. That is how the arm64 `type != PLATFORM_APP` gate was
             found missing from four shipped tables.

Usage:
    python scripts/audit_signatures.py [signatures.json]
    python scripts/audit_signatures.py --binary _scratch/chrome-155*-win64.dll
    python scripts/audit_signatures.py --strict          # non-zero exit on warnings
"""

import argparse
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from derive_milestone import open_images, masked_match_count, _masked_indices  # noqa: E402

PE_CONTAINERS = {"pe", "pe32", "pe-arm64"}
ARM64_CONTAINERS = {"pe-arm64", "elf-arm64", "macho-arm64"}
JUMP_OPCODE = {"short": (0x7F, 0xEB), "near": (0x0F, 0x90)}

# Extension field offsets per container family, as recorded in mv2-reversing.md.
# (manifest_version, manifest ptr, location flag)
FIELDS = {
    "pe": (0x50, 0x228, 0x208), "elf": (0x50, 0x228, 0x208),
    "macho-x64": (0x50, 0x228, 0x208), "pe32": (0x28, 0x164, 0x154),
    "pe-arm64": (0x50, 0x228, 0x208), "elf-arm64": (0x50, 0x228, 0x208),
    "macho-arm64": (0x50, 0x228, 0x208),
}


class Report:
    def __init__(self):
        self.problems = 0
        self.warnings = 0

    def fail(self, msg):
        self.problems += 1
        print("  FAIL  " + msg)

    def warn(self, msg):
        self.warnings += 1
        print("  warn  " + msg)

    def ok(self, msg):
        print("  ok    " + msg)


def site_key(site):
    if site.get("kind") == "featurebyte":
        return ("featurebyte", site.get("feature", ""), str(site.get("structRVA", "")),
                site.get("patchOff"), site.get("stock"), site.get("patched"),
                site.get("expectedMatches"))
    return (site["kind"], site["jgOff"], site["sig"].upper(), site["expectedMatches"])


def unmasked_runs(site):
    """[(start, length)] of the fixed spans the runtime can anchor on."""
    n = len(site["sig"]) // 2
    masked = _masked_indices(site["jgOff"], site["kind"])
    runs, i = [], 0
    while i < n:
        if i in masked:
            i += 1
            continue
        j = i
        while j < n and j not in masked:
            j += 1
        runs.append((i, j - i))
        i = j
    return runs


def pc_relative_spans(site, container):
    """Byte offsets inside the sig that hold a PC-relative immediate."""
    raw = bytes.fromhex(site["sig"])
    masked = _masked_indices(site["jgOff"], site["kind"])
    hits = []
    if container in ARM64_CONTAINERS:
        # ADRP/ADR: op bit31 selects adrp; immhi/immlo span the whole word.
        for pos in range(0, len(raw) - 3, 4):
            if pos in masked:
                continue
            word = int.from_bytes(raw[pos:pos + 4], "little")
            if (word & 0x1F000000) == 0x10000000:
                hits.append((pos, 4, "adrp/adr" if word & 0x80000000 else "adr"))
    else:
        for pos in range(0, len(raw) - 5):
            if pos in masked:
                continue
            # lea r64,[rip+disp32]  (48 8D /r with mod=00 rm=101)
            if raw[pos] in (0x48, 0x4C) and raw[pos + 1] == 0x8D and (raw[pos + 2] & 0xC7) == 0x05:
                hits.append((pos, 7, "lea rip-relative"))
            # call rel32 / jmp rel32 reaching outside the window
            elif raw[pos] == 0xE8 and pos + 5 <= len(raw):
                hits.append((pos, 5, "call rel32"))
    return hits


def audit_table(table, rep):
    entries = table["milestones"]
    print("\n== table: %d milestone(s), %d site(s)"
          % (len(entries), sum(len(m["sites"]) for m in entries)))

    names = [m["name"] for m in entries]
    dupe_names = [n for n, c in collections.Counter(names).items() if c > 1]
    if dupe_names:
        rep.fail("duplicate milestone name(s): %s" % ", ".join(dupe_names))

    # --- tie detection
    groups = collections.defaultdict(list)
    for m in entries:
        groups[(m["container"], frozenset(site_key(s) for s in m["sites"]))].append(m["name"])
    ties = [v for v in groups.values() if len(v) > 1]
    if ties:
        for v in ties:
            rep.fail("TIE: %s have identical signature sets - the patcher will "
                     "decline every build they match" % " == ".join(sorted(v)))
    else:
        rep.ok("no equal-rank ties (every container's signature sets are distinct)")

    # --- per-site shape, anchors, relocations
    fragile = weak = bad = 0
    for m in entries:
        container = m["container"]
        if container not in FIELDS:
            rep.fail("%s: unknown container %r" % (m["name"], container))
            continue
        for s in m["sites"]:
            if s.get("kind") == "featurebyte":
                tag = "%s feature:%s" % (m["name"], s.get("feature", "?"))
                if not s.get("feature"):
                    rep.fail("%s: featurebyte site needs a 'feature' name" % tag)
                    bad += 1
                for f in ("patchOff", "stock", "patched"):
                    v = s.get(f)
                    if not isinstance(v, int) or isinstance(v, bool):
                        rep.fail("%s: featurebyte %s must be an integer" % (tag, f))
                        bad += 1
                if s.get("stock") == s.get("patched"):
                    rep.fail("%s: featurebyte stock and patched bytes are identical" % tag)
                    bad += 1
                if not isinstance(s.get("verify"), dict) or not s.get("verify"):
                    rep.warn("%s: featurebyte has no verify criteria; the struct match may be ambiguous" % tag)
                    weak += 1
                if s.get("expectedMatches", 0) < 1:
                    rep.fail("%s: expectedMatches must be >= 1" % tag)
                    bad += 1
                continue
            tag = "%s %s" % (m["name"], s["jgRVA"])
            try:
                raw = bytes.fromhex(s["sig"])
            except ValueError:
                rep.fail("%s: sig is not hex" % tag)
                bad += 1
                continue
            need = 4 if s["kind"] in ("bcond", "cbz") else (6 if s["kind"] == "near" else 2)
            if s["jgOff"] + need > len(raw):
                rep.fail("%s: jgOff %d + %d bytes runs past a %d-byte sig"
                         % (tag, s["jgOff"], need, len(raw)))
                bad += 1
            elif (s["kind"] in JUMP_OPCODE
                  and raw[s["jgOff"]] in (0xEB, 0xE9)) or (
                  s["kind"] == "near" and raw[s["jgOff"]] == 0x90 and
                  len(raw) > s["jgOff"] + 1 and raw[s["jgOff"] + 1] == 0xE9):
                rep.fail("%s: kind %s but byte at jgOff is 0x%02X, not %s"
                         % (tag, s["kind"], raw[s["jgOff"]],
                            "/".join("0x%02X" % b for b in JUMP_OPCODE[s["kind"]])))
                bad += 1
            elif s["kind"] == "bcond" and (int.from_bytes(raw[s["jgOff"]:s["jgOff"] + 4], "little")
                                           & 0xFF00001F) not in (0x5400000C, 0x5400000E):
                rep.fail("%s: kind bcond but the word at jgOff is not b.gt/b.al" % tag)
                bad += 1
            elif s["kind"] == "cbz" and (int.from_bytes(raw[s["jgOff"]:s["jgOff"] + 4], "little")
                                         & 0xFF000000) != 0x34000000:
                rep.fail("%s: kind cbz but the word at jgOff is not a 32-bit CBZ" % tag)
                bad += 1
            elif s.get("stockOpcode") is not None:
                so = str(s["stockOpcode"])
                if not re.fullmatch(r"0[xX][0-9A-Fa-f]+", so):
                    rep.fail("%s: bad stockOpcode" % tag)
                    bad += 1
                else:
                    sb = bytes.fromhex(so[2:].zfill(2))
                    want = 1 if s["kind"] == "short" else 2
                    if len(sb) != want or raw[s["jgOff"]:s["jgOff"] + want] != sb:
                        rep.fail("%s: sig bytes at jgOff do not match stockOpcode" % tag)
                        bad += 1
            if s["expectedMatches"] < 1:
                rep.fail("%s: expectedMatches must be >= 1" % tag)
                bad += 1

            for pos, span, what in pc_relative_spans(s, container):
                rep.warn("%s: sig holds a %s at byte %d - build-specific, so this "
                         "site matches only the artifact it came from" % (tag, what, pos))
                fragile += 1
            runs = unmasked_runs(s)
            best = max((length for _, length in runs), default=0)
            if best < 6:
                rep.warn("%s: longest fixed run is only %d byte(s); the relocation "
                         "scan will be slow" % (tag, best))
                weak += 1
    if not (fragile or weak or bad):
        rep.ok("every site is well-formed, relocation-friendly and free of "
               "build-specific immediates")


def would_select(table, img):
    """Mirror the runtime's ranking: full beats partial, then most sites."""
    ranked = []
    for m in table["milestones"]:
        if m["container"] != img.container:
            continue
        # Rank on required branch sites only; optional / featurebyte sites are
        # best-effort and never decide milestone selection.
        req = [s for s in m["sites"] if s.get("kind") != "featurebyte" and not s.get("optional")]
        satisfied = sum(1 for s in req
                        if len(masked_match_count(img.text, bytes.fromhex(s["sig"]),
                                                  s["jgOff"], s["kind"],
                                                  cap=s["expectedMatches"] + 1)) == s["expectedMatches"])
        if satisfied:
            ranked.append((satisfied == len(req), len(req), satisfied, m["name"]))
    if not ranked:
        return None, [], []
    fulls = [r for r in ranked if r[0]]
    pool = fulls or ranked
    top = max(r[1] if r[0] else r[2] for r in pool)
    best = [r for r in pool if (r[1] if r[0] else r[2]) == top]
    return best, fulls, ranked


def flip_addresses(table, img):
    """Every address the runtime would actually flip in this image.

    Not the recorded jgRVAs: an `expectedMatches > 1` site covers a linker-folded
    body that lives at N addresses, and only the first is written down. Resolving
    the real set is what keeps the completeness pass from reporting each extra
    copy as a missing gate.
    """
    out = set()
    for m in table["milestones"]:
        if m["container"] != img.container:
            continue
        for s in m["sites"]:
            if s.get("kind") == "featurebyte":
                continue          # a .rdata data byte, not a .text manifest gate
            found = masked_match_count(img.text, bytes.fromhex(s["sig"]), s["jgOff"], s["kind"],
                                       cap=s["expectedMatches"] + 1)
            if len(found) != s["expectedMatches"]:
                continue
            for pos in found:
                out.add(img.rva(pos) + s["jgOff"])
    return out


def classify_marker(text, pos, img, mv):
    """Name the shape around an uncovered flag marker, or None if it needs a human.

    Every category here was confirmed by disassembly and is present in earlier
    Chrome versions too, so none of them is a regression to chase. See
    mv2-reversing.md section 7 - the sanctioned edit is a `jg`/`b.gt` flip and
    nothing else.
    """
    arm = img.container in ARM64_CONTAINERS
    lo = max(0, pos - 0x40)
    if arm:
        words = [int.from_bytes(text[q:q + 4], "little")
                 for q in range((lo + 3) & ~3, min(pos + 0x20, len(text) - 3), 4)]
        has_cmp2 = any((w & 0xFFFFFC1F) == 0x7100081F for w in words)
        has_bgt = any((w & 0xFF00001F) == 0x5400000C for w in words)
        # b.cond with cond != GT, sitting right after a cmp #2
        conds = [w & 0xF for w in words if (w & 0xFF000010) == 0x54000000]
        if any((w & 0xFFC00000) == 0xB9000000 and ((w >> 10) & 0xFFF) == mv // 4 for w in words):
            return "Extension initializer (stores manifest_version)"
        # CSEL / CCMP fold the whole check into data flow; there is no branch at all.
        if not has_bgt and any((w & 0xFFE00C00) == 0x1A800000            # CSEL (32-bit)
                               or (w & 0xFFE00C10) == 0x7A400800         # CCMP (imm)
                               or (w & 0xFFE00C10) == 0x7A400000         # CCMP (reg)
                               for w in words):
            return "branchless csel/ccmp (no b.gt exists to flip)"
        if has_cmp2 and conds and 0xC not in conds:
            return "b.ne/b.hs sibling (equality or inverted test, no b.gt to flip)"
        if not has_cmp2:
            return "no cmp #2 head (reached by an unrelated branch)"
    else:
        seg = text[lo:min(pos + 0x20, len(text))]
        # mov dword[reg+mv], imm  -> the initializer writes the field
        if bytes([0xC7, 0x40 | 0, mv]) in seg or bytes([0x89, 0x40 | 0, mv]) in seg:
            return "Extension initializer (stores manifest_version)"
        cmp2 = [i for i in range(len(seg) - 3)
                if seg[i] == 0x83 and (seg[i + 1] & 0xF8) == 0x78
                and seg[i + 2] == (mv & 0xFF) and seg[i + 3] == 0x02]
        if not cmp2:
            return "no cmp,2 head (reached by an unrelated branch)"
        for i in cmp2:
            tail = seg[i + 4:i + 10]
            if tail[:1] == b"\x7f" or tail[:2] == b"\x0f\x8f":
                return None                      # a real jg is here - human must look
        # cmovcc (0F 40..4F) / setcc (0F 90..9F) fold the check into data flow,
        # leaving no branch to flip.
        if any(seg[i] == 0x0F and (0x40 <= seg[i + 1] <= 0x4F or 0x90 <= seg[i + 1] <= 0x9F)
               for i in range(len(seg) - 1)):
            return "branchless cmov/setcc (no jg exists to flip)"
        return "jne/jae sibling (equality or inverted test, no jg to flip)"
    return None


def completeness(table, img, rep):
    """Flag-marker anchored sweep, independent of the cmp,2;jg finder."""
    mv, manifest, flag = FIELDS[img.container]
    text = img.text
    covered = flip_addresses(table, img)
    window = 0x80
    markers = []
    if img.container in ARM64_CONTAINERS:
        want_flag = 0x39400000 | ((flag & 0xFFF) << 10)
        want_man = 0xF9400000 | (((manifest // 8) & 0xFFF) << 10)
        limit = len(text) - len(text) % 4
        for pos in range(0, limit, 4):
            if (int.from_bytes(text[pos:pos + 4], "little") & 0xFFFFFC00) != want_flag:
                continue
            lo = max(0, pos - window) & ~3
            near = range(lo, min(pos + window, limit), 4)
            has_cmp = any((int.from_bytes(text[q:q + 4], "little") & 0xFFFFFC1F) == 0x7100081F
                          for q in near)
            has_man = any((int.from_bytes(text[q:q + 4], "little") & 0xFFFFFC00) == want_man
                          for q in near)
            if has_cmp and has_man:
                markers.append(pos)
    else:
        pattern = (re.escape(b"\x80") + b"[\xb8-\xbf]"
                   + re.escape(flag.to_bytes(4, "little")) + re.escape(b"\x00"))
        for hit in re.finditer(pattern, text, re.S):
            pos = hit.start()
            seg = text[max(0, pos - window):min(pos + window, len(text))]
            has_cmp = any(seg[i] == 0x83 and (seg[i + 1] & 0xF8) == 0x78
                          and seg[i + 2] == (mv & 0xFF) and seg[i + 3] == 0x02
                          for i in range(len(seg) - 3))
            if has_cmp and manifest.to_bytes(4, "little") in seg:
                markers.append(pos)

    explained = collections.Counter()
    unexplained = []
    for pos in markers:
        rva = img.rva(pos)
        if any(abs(rva - c) <= window for c in covered):
            explained["covered by a site (incl. folded copies)"] += 1
            continue
        why = classify_marker(text, pos, img, mv)
        if why:
            explained[why] += 1
        else:
            unexplained.append(rva)

    for why, count in sorted(explained.items(), key=lambda kv: -kv[1]):
        print("        %3d  %s" % (count, why))
    if unexplained:
        rep.warn("%s: %d gate marker(s) NEED REVIEW: %s"
                 % (img.container, len(unexplained),
                    ", ".join("0x%08X" % r for r in unexplained)))
        print("        Disassemble each before adding anything; only an existing "
              "jg/b.gt may be flipped (mv2-reversing.md section 7).")
    else:
        rep.ok("%s: all %d flag-anchored gate marker(s) accounted for"
               % (img.container, len(markers)))


def audit_binary(table, path, rep):
    for img in open_images(path):
        print("\n== %s [%s]" % (os.path.basename(path), img.container))
        best, fulls, ranked = would_select(table, img)
        if not ranked:
            rep.fail("%s: no milestone matches even partially" % img.container)
            continue
        for is_full, total, satisfied, name in sorted(ranked, key=lambda r: (-r[1], r[3])):
            print("        %-22s %s (%d/%d)" % (name, "FULL " if is_full else "partial", satisfied, total))
        if not fulls:
            rep.fail("%s: no FULL match - this build would be declined" % img.container)
        elif len(best) > 1:
            rep.fail("%s: %d milestones tie at %d sites (%s) - would be declined"
                     % (img.container, len(best), best[0][1], ", ".join(r[3] for r in best)))
        else:
            rep.ok("%s: would select %s (%d sites, %d flip(s))"
                   % (img.container, best[0][3], best[0][1],
                      sum(s["expectedMatches"] for m in table["milestones"]
                          if m["name"] == best[0][3] for s in m["sites"])))
        completeness(table, img, rep)


def main():
    parser = argparse.ArgumentParser(description="Audit signatures.json for the defects that "
                                                 "silently break patching.")
    parser.add_argument("signatures", nargs="?", default="signatures.json")
    parser.add_argument("--binary", action="append", default=[], metavar="PATH",
                        help="also cross-check this stock artifact (repeatable)")
    parser.add_argument("--strict", action="store_true",
                        help="exit non-zero on warnings too, not just failures")
    args = parser.parse_args()

    with open(args.signatures, encoding="utf-8") as handle:
        table = json.load(handle)

    rep = Report()
    audit_table(table, rep)
    for path in args.binary:
        audit_binary(table, path, rep)

    print("\n%d failure(s), %d warning(s)" % (rep.problems, rep.warnings))
    if rep.problems:
        return 1
    return 1 if (args.strict and rep.warnings) else 0


if __name__ == "__main__":
    sys.exit(main())
