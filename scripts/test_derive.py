"""Safety checks for the arm64 bcond finder/masker in derive_milestone.py."""
import json, struct, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import derive_milestone as dm

W = lambda *ws: b"".join(struct.pack("<I", w) for w in ws)
CMP2 = 0x7100091F   # cmp w8,#2
CMP1 = 0x7100051F   # cmp w8,#1  (type follow-up)
BGT  = 0x5400008C   # b.gt +?    (cond GT)
BAL  = 0x5400008E   # b.al +?    (cond AL, i.e. already patched)
BLE  = 0x5400008D   # b.le +?    (cond LE, inverted-sense)
NOP  = 0xD503201F
MOVZ0 = 0x52800000  # movz w0,#0
RET  = 0xD65F03C0


class Img:
    """Minimal stand-in exposing .text/.container/.rva for the finder."""
    def __init__(self, container, text):
        self.container, self._t = container, text
    @property
    def text(self):
        return self._t
    def rva(self, p):
        return p + 0x100000000


def gates(text):
    return dm.find_gates_arm64(Img("macho-arm64", text))


def n_matches(sig_text, sig_hex, jg_off):
    return len(dm.masked_match_count(sig_text, bytes.fromhex(sig_hex), jg_off, "bcond", cap=8))


ok = True

# 1. Stock gate is found; derive a site from it.
stock = W(CMP2, BGT, NOP, CMP1)
g = gates(stock)
assert len(g) == 1 and g[0][2] == "bcond", g
site, cnt = dm.build_site(Img("macho-arm64", stock), g[0][0], g[0][1], "bcond", "s")
print(f"[1] stock gate found: sig={site['sig']} matches={cnt}")
ok &= cnt == 1

# 2. Idempotency: the stock-derived signature still matches a PATCHED (AL) binary,
#    so a re-run relocates/recognizes it instead of double-writing.
patched = W(CMP2, BAL, NOP, CMP1)
m = n_matches(patched, site["sig"], site["jgOff"])
print(f"[2] patched(AL) still matches stock sig: {m} (expect 1)")
ok &= m == 1

# 3. find_gates_arm64 does NOT re-anchor on an already-patched binary (anchor=GT),
#    so it never emits a fresh 'stock' gate for patched bytes.
print(f"[3] find_gates on patched(AL): {len(gates(patched))} (expect 0)")
ok &= len(gates(patched)) == 0

# 4. Inverted polarity: fall-through is `movz w0,#0 ; ret` (the not-affected return),
#    no #1/#5 type follow-up -> DECLINE (flipping would force the wrong outcome).
inverted = W(CMP2, BGT, MOVZ0, RET)
print(f"[4] inverted-polarity gate: {len(gates(inverted))} (expect 0 = declined)")
ok &= len(gates(inverted)) == 0

# 5. A wrong condition (LE) in the branch word must NOT match the stock sig.
wrong = W(CMP2, BLE, NOP, CMP1)
m = n_matches(wrong, site["sig"], site["jgOff"])
print(f"[5] LE-condition binary matches stock sig: {m} (expect 0)")
ok &= m == 0

# 6. The arm64 bcond finder is shared by macOS arm64 AND Windows-on-ARM (pe-arm64):
#    find_gates_for must dispatch BOTH arm64 containers to find_gates_arm64, and
#    the x86 containers to the jg finder. A pe-arm64 image finds the same gate.
g_win = dm.find_gates_for(Img("pe-arm64", stock))
print(f"[6] pe-arm64 dispatch -> arm64 finder: {len(g_win)} gate(s) kind={g_win[0][2] if g_win else None} (expect 1 bcond)")
ok &= len(g_win) == 1 and g_win[0][2] == "bcond"
g_x64 = dm.find_gates_for(Img("pe", stock))  # x64 jg finder must NOT match arm64 bytes
print(f"[7] pe (x64) dispatch -> jg finder on arm64 bytes: {len(g_x64)} (expect 0)")
ok &= len(g_x64) == 0

# 8. Linux arm64 shares the same bcond finder: find_gates_for must dispatch
#    'elf-arm64' to find_gates_arm64 too (while x86_64 'elf' uses the jg finder).
g_lin = dm.find_gates_for(Img("elf-arm64", stock))
print(f"[8] elf-arm64 dispatch -> arm64 finder: {len(g_lin)} gate(s) kind={g_lin[0][2] if g_lin else None} (expect 1 bcond)")
ok &= len(g_lin) == 1 and g_lin[0][2] == "bcond"
ok &= len(dm.find_gates_for(Img("elf", stock))) == 0  # x86_64 elf must not match arm64 bytes

# 9. parse_elf tags the container from e_machine: 0xB7 aarch64 -> elf-arm64,
#    0x3E x86_64 -> elf (so the two never cross-probe).
import tempfile, _testutil as T
_d = Path(tempfile.mkdtemp(prefix="mv2-derive-elf-"))
T.make_elf(_d / "a64", "1F0900718C0000541F2003D51F050071", machine=0xB7)
T.make_elf(_d / "x64", "837E50027F2F554889E5")
c_arm = dm.parse_elf((_d / "a64").read_bytes()).container
c_x64 = dm.parse_elf((_d / "x64").read_bytes()).container
print(f"[9] parse_elf containers: aarch64->{c_arm} x86_64->{c_x64} (expect elf-arm64 / elf)")
ok &= c_arm == "elf-arm64" and c_x64 == "elf"

# Chrome 159: inverted branches must select fall-through; CSEL must select WZR.
for kind, insn, patched_insn in (
    ("short-nop", bytes.fromhex("7E18"), b"\x90" * 2),
    ("near-nop", bytes.fromhex("0F8E12345600"), b"\x90" * 6),
    ("bcond-nop", W(BLE), W(NOP)),
    ("csel", W(0x1A88C3E0), W(0x1A88E3E0)),
    ("cbz", W(0xB4000080), W(0x14000004)),
):
    prefix, suffix = W(CMP2), W(MOVZ0, RET)
    sig = prefix + insn + suffix
    for code in (insn, patched_insn):
        relocated = b"\xCC" * 40 + prefix + code + suffix
        assert dm.masked_match_count(relocated, sig, 4, kind) == [40], kind
    # Neither a half-written NOP nor a changed CSEL operand is our patch.
    bad = bytearray(patched_insn)
    bad[-1] ^= 1
    assert not dm.masked_match_count(prefix + bad + suffix, sig, 4, kind), kind
    if kind == "cbz":
        assert not dm.masked_match_count(prefix + W(0x34000080) + suffix, sig, 4, kind), "CBZ register width must match"
        assert not dm.masked_match_count(prefix + W(0xB4000081) + suffix, sig, 4, kind), "CBZ register must match"
    elif kind != "csel":
        moved = bytearray(insn)
        moved[1 if kind == "short-nop" else 2] ^= 0x20
        assert dm.masked_match_count(prefix + moved + suffix, sig, 4, kind) == [0], kind
    else:
        for word in (0x9A88C3E0, 0x1A88C000, 0x1A88D3E0):
            wrong_sig = prefix + W(word) + suffix
            assert not dm.masked_match_count(wrong_sig, wrong_sig, 4, kind), hex(word)
    assert not dm.masked_match_count(sig, sig[:5], 4, kind), kind
print("[10] Chrome 159 instruction matching, relocation, and corruption checks passed")

# Real InstallVerifier fragments: its following pointer load changes across builds.
table = json.loads((Path(__file__).resolve().parent.parent / "signatures.json").read_text())
decoys = bytes.fromhex(
    "881F40F90851493968011837"  # another IsFromStore caller
    "880A40F908514939C8041837"
    "881E40F90851493928011837")
for milestone in table["milestones"] + table.get("milestones_v2", []):
    if milestone["name"] not in ("154-win-arm64", "159-win-arm64"):
        continue
    site = next(s for s in milestone["sites"] if s["kind"] == "tbz")
    for load in ("60E641F9", "600640F9", "60B647F9", "A09647F9", "A02642F9", "A0BE42F9"):
        fragment = bytes.fromhex("E80B40F90851493988011837" + load + "E80F40F9")
        text = b"\xCC" * 8 + fragment + decoys
        hits = dm.masked_match_count(text, bytes.fromhex(site["sig"]), site["jgOff"], "tbz")
        assert [p + site["jgOff"] for p in hits] == [16], (milestone["name"], load, hits)
print("[11] ARM64 InstallVerifier survives pointer-load changes and rejects other callers")

print("ALL DERIVATION SAFETY CHECKS:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
