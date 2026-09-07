"""Port a milestone in one command: classify, de-duplicate, harden, name, merge.

`derive_milestone.py` finds every `cmp <mv>,2 ; jg` / `cmp w?,#2 ; b.gt` candidate
- around 170 on x86 and 1100 on arm64, nearly all unrelated enum dispatches. Turning
that into a shippable entry used to be manual: disassemble candidates, decide which
are real gates, collapse the ones a linker folded, shorten any signature holding a
build-specific immediate, and carry the site names over from the previous milestone.
This script does all of it and prints why each candidate was kept or dropped.

    python scripts/port_milestone.py <binary> --name 155
    python scripts/port_milestone.py <binary> --name 155 --prev 154 --merge --sync

What it does, in order:

  1. LEARN   Take the (manifest_version, manifest, location-flag) Extension field
             offsets from whichever triple most candidates agree on, rather than
             hardcoding them - they move between versions (Chrome 154.0.8037
             shifted the Manifest fields +0x20, breaking every member signature).
             `--fields` overrides when a build is too sparse to learn from.
  2. ACCEPT  Keep a candidate only if its window carries BOTH the manifest load and
             the location-flag compare at those exact offsets. Base registers are
             not required to match: the type!=PLATFORM_APP variant reloads the
             Extension from a stack slot or a REX.B register, and demanding one
             base silently dropped it on four platforms.
  3. HARDEN  Search window offsets for the shortest signature that still matches
             exactly, holds no PC-relative immediate (adrp/adr, lea rip+disp), and
             keeps a fixed anchor run the relocation scan can use. The default
             32-byte arm64 window swallows an `adrp`, which pins the site to one
             build of one version.
  4. FOLD    Collapse candidates whose signatures are equal under the runtime's
             masking into a single site with expectedMatches=N. Two entries for one
             folded body double-count the flips and can tie the whole table.
  5. NAME    Carry names from --prev by matching signatures after rewriting the
             field offsets that moved, so a diff shows only genuinely new sites.

Requires only the standard library. Install capstone for `--disasm`, which dumps
the instructions behind any site or rejected candidate.
"""

import argparse
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from derive_milestone import (open_images, find_gates_for, masked_match_count,  # noqa: E402
                              milestone_name_for, _masked_indices, SIGLEN, NEED)
from audit_signatures import pc_relative_spans, unmasked_runs, ARM64_CONTAINERS  # noqa: E402

MIN_ANCHOR = 6          # bytes of fixed run the relocation scan wants
WINDOW = 0x40           # bytes after the cmp searched for the family markers


# --------------------------------------------------------------------------- 1-2
def _is_free_gate(text, cmp_pos, arm, mask=0x10A):
    """The register-free predicate: `mov r32,0x10A ; bt r32,type`.

    `manifest_v2_util::IsExtensionAffected` tests the affected Manifest::Type set
    with a bitmask instead of loading anything off the Extension, so it carries
    neither the manifest load nor the location-flag compare and the member test
    rejects it. x86/x64 only - arm64 has no register-free copy.
    """
    if arm:
        return False
    imm = mask.to_bytes(4, "little")
    seg = bytes(text[cmp_pos:min(cmp_pos + WINDOW, len(text))])
    at = 0
    while True:
        at = seg.find(imm, at)
        if at < 0:
            return False
        if at >= 1 and 0xB8 <= seg[at - 1] <= 0xBF and b"\x0f\xa3" in seg[at + 4:at + 16]:
            return True
        at += 1


def _mv_disp(text, cmp_pos, arm):
    """The manifest_version displacement the head compare reads, or None."""
    if arm:
        return None
    if text[cmp_pos] != 0x83:
        return None
    modrm = text[cmp_pos + 1]
    if (modrm & 0xF8) == 0x78:                     # mod=01, disp8
        return text[cmp_pos + 2]
    if (modrm & 0xF8) == 0xB8:                     # mod=10, disp32
        return int.from_bytes(text[cmp_pos + 2:cmp_pos + 6], "little")
    return None


def _disp32_at(seg, pos, opcode):
    """If a `<opcode> <modrm mod=10> [sib] <disp32>` starts at pos, return the disp32.

    Both markers appear with an optional REX prefix and, when the base register is
    r12/rsp, an extra SIB byte (rm=100). Guessing a fixed offset instead of walking
    modrm/SIB is what made the type!=PLATFORM_APP variant - which reloads the
    Extension into r12 - invisible on Linux and macOS x64.
    """
    at = pos
    if seg[at] in (0x40, 0x41, 0x44, 0x45, 0x48, 0x49, 0x4C, 0x4D):
        at += 1                                   # REX
    if at >= len(seg) or seg[at] != opcode:
        return None
    at += 1
    if at >= len(seg):
        return None
    modrm = seg[at]
    if (modrm >> 6) != 0b10:                      # need mod=10 (disp32)
        return None
    at += 1
    if (modrm & 7) == 0b100:                      # rm=100 -> a SIB byte follows
        at += 1
    if at + 4 > len(seg):
        return None
    return int.from_bytes(seg[at:at + 4], "little"), at + 4


def _markers(text, start, end, arm, manifest, flag):
    """(has manifest load, has location-flag compare) inside [start, end)."""
    seg = bytes(text[start:end])
    if arm:
        want_man = 0xF9400000 | (((manifest // 8) & 0xFFF) << 10)
        want_flag = 0x39400000 | ((flag & 0xFFF) << 10)
        has_man = has_flag = False
        for pos in range(0, len(seg) - 3, 4):
            word = int.from_bytes(seg[pos:pos + 4], "little")
            has_man = has_man or (word & 0xFFFFFC00) == want_man
            has_flag = has_flag or (word & 0xFFFFFC00) == want_flag
        return has_man, has_flag
    has_man = has_flag = False
    for pos in range(len(seg)):
        got = _disp32_at(seg, pos, 0x8B)          # mov r,[base+disp32]
        if got and got[0] == manifest:
            has_man = True
        got = _disp32_at(seg, pos, 0x80)          # cmp byte[base+disp32], imm8
        if got and got[0] == flag and got[1] < len(seg) and seg[got[1]] == 0x00:
            has_flag = True
    return has_man, has_flag


def learn_fields(img, gates, override=None):
    """The (mv, manifest, flag) triple most candidates agree on."""
    if override:
        parts = [None if p == "-" else int(p, 0) for p in override.split(":")]
        return tuple(parts)
    arm = img.container in ARM64_CONTAINERS
    text = img.text
    votes = collections.Counter()
    # Candidate offsets seen in shipped tables, plus anything this build reveals.
    man_candidates = (0x228, 0x164, 0x1F8, 0x230, 0x250)
    flag_candidates = (0x208, 0x154, 0x1D8, 0x210, 0x230)
    for cmp_pos, jg_pos, _kind in gates:
        mv = _mv_disp(text, cmp_pos, arm)
        lo, hi = cmp_pos, min(cmp_pos + WINDOW, len(text))
        for manifest in man_candidates:
            for flag in flag_candidates:
                has_man, has_flag = _markers(text, lo, hi, arm, manifest, flag)
                if has_man and has_flag:
                    votes[(mv, manifest, flag)] += 1
    if not votes:
        sys.exit("error: no gate family found; pass --fields mv:manifest:flag "
                 "(use '-' for mv on arm64)")
    return votes.most_common(1)[0][0]


# ----------------------------------------------------------------------------- 3
def _backoff_starts(text, cmp_pos, kind):
    """Window starts to try: the cmp itself, plus the load that feeds it.

    Backing up is only safe when the earlier bytes belong to the gate's own
    dataflow. Reaching further picks up the tail of whatever instruction happened
    to precede it, which differs between two copies of the SAME folded body - so
    the copies stop looking identical and get emitted as separate sites instead of
    one `expectedMatches=2` entry. x86 gates compare memory directly and need no
    back-up at all.
    """
    starts = [cmp_pos]
    if kind != "bcond" or cmp_pos < 4:
        return starts
    cmp_word = int.from_bytes(bytes(text[cmp_pos:cmp_pos + 4]), "little")
    rn = (cmp_word >> 5) & 0x1F                      # the register `cmp w<Rn>,#2` reads
    prev = int.from_bytes(bytes(text[cmp_pos - 4:cmp_pos]), "little")
    if (prev & 0xFFC00000) == 0xB9400000 and (prev & 0x1F) == rn:
        starts.append(cmp_pos - 4)                   # ldr w<Rn>,[x?,#imm] - the mv load
    return starts


def harden(img, cmp_pos, jg_pos, kind):
    """Shortest (start, sig) that matches exactly once per real copy and is portable.

    Widening is not the only lever: including the load that feeds the compare can
    turn a weak anchor into a strong one, which is how the arm64
    type!=PLATFORM_APP site got a signature that works on every build instead of
    just the one it came from.
    """
    text = img.text
    step = 4 if kind in ("bcond", "cbz") else 1
    floor = NEED[kind] + 4
    best = None
    for start in _backoff_starts(text, cmp_pos, kind):
        jg_off = jg_pos - start
        for length in range(max(floor, jg_off + NEED[kind]), SIGLEN[kind] + 2 * step + 1, step):
            if start + length > len(text):
                break
            sig = bytes(text[start:start + length])
            site = {"kind": kind, "jgOff": jg_off, "sig": sig.hex().upper()}
            if pc_relative_spans(site, img.container):
                continue
            anchor = max((n for _, n in unmasked_runs(site)), default=0)
            if anchor < MIN_ANCHOR:
                continue
            found = masked_match_count(text, sig, jg_off, kind, cap=16)
            if not found or len(found) > 4:
                continue
            # Prefer the plain window; only take a backed-up one if it is strictly
            # more selective (fewer stray matches) or the plain one had no portable
            # form at all.
            score = (len(found), start != cmp_pos, length)
            if best is None or score < best[0]:
                best = (score, start, jg_off, sig, len(found), anchor)
            break            # first acceptable length at this start is the shortest
    if best is None:          # nothing portable: fall back to the plain window
        jg_off = jg_pos - cmp_pos
        length = max(SIGLEN[kind], jg_off + NEED[kind] + 4)
        sig = bytes(text[cmp_pos:cmp_pos + length])
        found = masked_match_count(text, sig, jg_off, kind, cap=16)
        return cmp_pos, jg_off, sig, len(found), None
    _score, start, jg_off, sig, count, anchor = best
    return start, jg_off, sig, count, anchor


# ----------------------------------------------------------------------------- 4
def masked_form(site):
    raw = bytearray(bytes.fromhex(site["sig"]))
    for i in _masked_indices(site["jgOff"], site["kind"]):
        if i < len(raw):
            raw[i] = 0
    return (site["kind"], site["jgOff"], bytes(raw).hex().upper())


# ----------------------------------------------------------------------------- 5
def rewrite_offsets(sig_hex, moves, arm):
    """Re-encode a previous milestone's signature with the fields that moved."""
    raw = bytearray(bytes.fromhex(sig_hex))
    if arm:
        for pos in range(0, len(raw) - 3, 4):
            word = int.from_bytes(raw[pos:pos + 4], "little")
            for mask, value, scale in ((0xFFC00000, 0xB9400000, 4), (0xFFC00000, 0xF9400000, 8)):
                if (word & mask) == value:
                    cur = ((word >> 10) & 0xFFF) * scale
                    if cur in moves:
                        word = (word & ~(0xFFF << 10)) | ((moves[cur] // scale) << 10)
                        raw[pos:pos + 4] = word.to_bytes(4, "little")
    else:
        for pos in range(len(raw) - 2):
            if raw[pos] == 0x8B and 0x40 <= raw[pos + 1] <= 0x7F and raw[pos + 2] in moves:
                raw[pos + 2] = moves[raw[pos + 2]]
    return bytes(raw).hex().upper()


def carry_names(sites, img, table_path, prev_name, arm, moves):
    """Name new sites by locating the previous milestone's signatures in THIS image.

    Comparing signature text directly does not work: this script picks its own
    window offset and length per site, so the same gate legitimately has different
    bytes than last version. Instead, scan each previous signature (with the moved
    field offsets re-encoded) against the new image and match on the address it
    lands on - the one thing both descriptions agree about.
    """
    try:
        with open(table_path, encoding="utf-8") as handle:
            table = json.load(handle)
    except OSError:
        return 0
    prev = [m for m in table["milestones"] if m["name"] == prev_name]
    if not prev:
        print("    note: no milestone %r to carry names from" % prev_name)
        return 0

    # Map EVERY address a new site covers - not just its recorded jgRVA - so that a
    # previous signature landing on the second copy of a folded body still resolves.
    by_rva = {}
    for site in sites:
        found = masked_match_count(img.text, bytes.fromhex(site["sig"]), site["jgOff"],
                                   site["kind"], cap=site["expectedMatches"] + 1)
        for pos in found:
            by_rva[img.rva(pos) + site["jgOff"]] = site
        by_rva.setdefault(int(site["jgRVA"], 16), site)
    named = 0
    for old in prev[0]["sites"]:
        if old.get("kind") == "featurebyte":
            continue        # not a jg gate; carried through by the merge, not by name
        # Try the full signature first, then progressively shorter prefixes. A gate
        # usually survives a version with its head intact (`cmp mv,2 ; jg ; load the
        # manifest`) while trailing bytes shift by a byte or two, so the full window
        # no longer occurs but the head still does. A prefix is only trusted when it
        # lands on exactly one address, and that address is one of the new sites.
        floor = old["jgOff"] + NEED[old["kind"]] + 6
        matched = False
        for sig_hex in (rewrite_offsets(old["sig"], moves, arm), old["sig"]):
            full = bytes.fromhex(sig_hex)
            step = 4 if old["kind"] in ("bcond", "cbz") else 1
            lengths = list(range(len(full), max(floor, step) - 1, -step))
            for length in lengths:
                sig = full[:length]
                found = masked_match_count(img.text, sig, old["jgOff"], old["kind"], cap=8)
                if not found:
                    continue
                hits = {img.rva(pos) + old["jgOff"] for pos in found}
                targets = [by_rva[rva] for rva in hits if rva in by_rva]
                if len(hits) != len(targets) or not targets:
                    break        # it matches somewhere that is not a site: stop trusting it
                for site in targets:
                    if site["name"].startswith("MV2 gate"):
                        site["name"] = old["name"]
                        named += 1
                matched = True
                break
            if matched:
                break
    return named


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("binary")
    parser.add_argument("--name", required=True, help="milestone base name, e.g. 155")
    parser.add_argument("--prev", help="previous milestone base name to carry site names from")
    parser.add_argument("--fields", help="override the learned family: mv:manifest:flag")
    parser.add_argument("--moved", default="",
                        help="field offsets that moved since --prev, as old:new[,old:new]")
    parser.add_argument("--signatures", default="signatures.json")
    parser.add_argument("--merge", action="store_true",
                        help="write the entry into signatures.json (replacing a same-named one)")
    parser.add_argument("--sync", action="store_true",
                        help="with --merge, also update both embedded tables")
    parser.add_argument("--json", help="write the derived entry to this file")
    parser.add_argument("--rejected", action="store_true", help="list dropped candidates")
    args = parser.parse_args()

    moves = {}
    for pair in filter(None, args.moved.split(",")):
        old, new = pair.split(":")
        moves[int(old, 0)] = int(new, 0)

    derived = []
    for img in open_images(args.binary):
        arm = img.container in ARM64_CONTAINERS
        text = img.text
        gates = find_gates_for(img)
        mv, manifest, flag = learn_fields(img, gates, args.fields)
        name = milestone_name_for(args.name, img)
        print("\n=== %s  [%s]  %d candidate(s)" % (name, img.container, len(gates)))
        print("    family: manifest_version=%s  manifest=+0x%X  flag=+0x%X"
              % ("+0x%X" % mv if mv is not None else "(arm64: in a register)", manifest, flag))

        accepted, rejected, weak = [], [], []
        for cmp_pos, jg_pos, kind in gates:
            free = _is_free_gate(text, cmp_pos, arm)
            if not free:
                if not arm and _mv_disp(text, cmp_pos, arm) != mv:
                    rejected.append((jg_pos, kind, "head compare is not on +0x%X" % mv))
                    continue
                has_man, has_flag = _markers(text, cmp_pos, min(cmp_pos + WINDOW, len(text)),
                                             arm, manifest, flag)
                if not (has_man and has_flag):
                    missing = " and ".join(w for w, ok in (("manifest load", has_man),
                                                           ("flag compare", has_flag)) if not ok)
                    rejected.append((jg_pos, kind, "no %s in the window" % missing))
                    continue
            start, jg_off, sig, count, anchor = harden(img, cmp_pos, jg_pos, kind)
            site = {"name": "MV2 gate" if not free else "MV2 gate (register-free predicate)",
                    "kind": kind, "jgRVA": "0x%08X" % img.rva(jg_pos),
                    "jgOff": jg_off, "expectedMatches": count, "sig": sig.hex().upper()}
            if anchor is None:
                weak.append(site["jgRVA"])
            accepted.append(site)

        folded = {}
        for site in sorted(accepted, key=lambda s: int(s["jgRVA"], 16)):
            folded.setdefault(masked_form(site), site)
        sites = sorted(folded.values(), key=lambda s: int(s["jgRVA"], 16))
        if len(sites) != len(accepted):
            print("    folded %d candidate(s) into %d site(s) (linker-shared bodies)"
                  % (len(accepted), len(sites)))

        named = carry_names(sites, img, args.signatures,
                            milestone_name_for(args.prev, img), arm, moves) if args.prev else 0
        for site in sites:
            print("    %-5s exp=%d %s  %s" % (site["kind"], site["expectedMatches"],
                                              site["jgRVA"], site["name"]))
        print("    %d site(s), %d flip(s); %d/%d named from %s; %d candidate(s) dropped"
              % (len(sites), sum(s["expectedMatches"] for s in sites), named, len(sites),
                 args.prev or "-", len(rejected)))
        if weak:
            print("    WARNING: no portable signature found for %s - it keeps a "
                  "build-specific window and may not match another artifact of this "
                  "version" % ", ".join(weak))
        unnamed = [s["jgRVA"] for s in sites if s["name"] == "MV2 gate"]
        if unnamed:
            print("    %d site(s) need a hand-written name: %s"
                  % (len(unnamed), ", ".join(unnamed)))
        if args.rejected:
            for jg_pos, kind, why in rejected:
                print("      drop 0x%08X %-5s %s" % (img.rva(jg_pos), kind, why))
        derived.append({"name": name, "container": img.container, "sites": sites})

    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump({"milestones": derived}, handle, indent=2)
        print("\nwrote %s" % args.json)

    if args.merge:
        with open(args.signatures, encoding="utf-8") as handle:
            table = json.load(handle, object_pairs_hook=collections.OrderedDict)
        by_name = {m["name"]: i for i, m in enumerate(table["milestones"])}
        for entry in derived:
            if entry["name"] in by_name:
                old = table["milestones"][by_name[entry["name"]]]
                # Carry forward any prior site the jg-gate deriver did not
                # reproduce (matched by name): featurebyte sites (e.g.
                # webRequestBlocking) and the ExtensionSettings /
                # FilterSensitivePolicies gate, which is authored by hand rather
                # than pattern-derived. Required or optional, it must persist.
                have = {s.get("name") for s in entry["sites"]}
                carried = [s for s in old.get("sites", []) if s.get("name") not in have]
                if carried:
                    entry["sites"].extend(carried)
                    print("  carried %d prior site(s) into %s" % (len(carried), entry["name"]))
                table["milestones"][by_name[entry["name"]]] = entry
                print("replaced %s in %s" % (entry["name"], args.signatures))
            else:
                table["milestones"].append(entry)
                print("added %s to %s" % (entry["name"], args.signatures))
        with open(args.signatures, "w", encoding="utf-8") as handle:
            json.dump(table, handle, indent=2)
            handle.write("\n")
        if args.sync:
            import sync_embedded
            sys.argv = ["sync_embedded.py", "--signatures", args.signatures]
            sync_embedded.main()
        print("\nNext: python scripts/audit_signatures.py --binary %s" % args.binary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
