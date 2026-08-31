"""Regression tests for scripts/mv2_apply.py (the Python PE patch runtime).

Pure Python, no PowerShell: builds synthetic PE32+ fixtures (x64 and arm64) and
drives mv2_apply.py as a black box, mirroring the assertions test_windows.py
makes against chrome-mv2.ps1 - flip encodings, idempotence, backup/restore,
and the decline paths (partial layout, ambiguous tie).
"""
import json
import struct
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import _testutil as T  # noqa: E402

APPLY = str(HERE / "mv2_apply.py")
A = T.Asserter()

TEXT_RAW = 0x400        # .text PointerToRawData
TEXT_RVA = 0x1000       # .text VirtualAddress
SIG_OFF = 0x40          # signature position within .text
SIG_AT = TEXT_RAW + SIG_OFF


def make_pe(path, sig, machine=0x8664, signed=True, timestamp=0x12345678):
    """Minimal PE32+ with a .text carrying `sig`. Same geometry as the
    New-TestPe fixture in test_windows.py, so jgRVA math matches."""
    buf = bytearray(0x800)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    nt = 0x80
    buf[nt:nt + 4] = b"PE\0\0"
    struct.pack_into("<HHI", buf, nt + 4, machine, 1, timestamp)
    struct.pack_into("<H", buf, nt + 20, 0xF0)          # SizeOfOptionalHeader
    opt = nt + 24
    struct.pack_into("<H", buf, opt, 0x20B)             # PE32+
    struct.pack_into("<I", buf, opt + 108, 16)          # NumberOfRvaAndSizes
    if signed:                                          # Security directory [4]
        struct.pack_into("<II", buf, opt + 144, 0x700, 0x20)
    sec = opt + 0xF0
    buf[sec:sec + 5] = b".text"
    struct.pack_into("<IIII", buf, sec + 8, 0x200, TEXT_RVA, 0x200, TEXT_RAW)
    buf[SIG_AT:SIG_AT + len(sig)] = sig
    Path(path).write_bytes(bytes(buf))


def write_sigs(path, milestones):
    Path(path).write_text(json.dumps({"milestones": milestones}), encoding="utf-8")


def site(name, kind, jg_rva, jg_off, matches, sig_hex):
    return {"name": name, "kind": kind, "jgRVA": jg_rva, "jgOff": jg_off,
            "expectedMatches": matches, "sig": sig_hex}


def apply_cmd(command, target, sigs, *extra):
    return T.run([sys.executable, APPLY, command, str(target), "--signatures", str(sigs), *extra])


def pe_checksum_of(path):
    """Independent checksum recomputation, so the test does not trust the
    implementation's own arithmetic."""
    data = Path(path).read_bytes()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    csum_at = e_lfanew + 24 + 64
    total = 0
    for i in range(0, len(data) - 3, 4):
        if i == csum_at:
            continue
        total += struct.unpack_from("<I", data, i)[0]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (total + len(data)) & 0xFFFFFFFF, struct.unpack_from("<I", data, csum_at)[0]


SHORT_SIG = "837E50027F2F554889E5"
NEAR_SIG = "837F50020F8F8B000000488B"
BCOND_SIG = "1F0900718C000054"


def test_short_roundtrip(tmp):
    target = tmp / "short fixture.dll"
    sigs = tmp / "short signatures.json"
    make_pe(target, bytes.fromhex(SHORT_SIG))
    write_sigs(sigs, [{"name": "test-pe", "container": "pe",
                       "sites": [site("gate", "short", "0x00001044", 4, 1, SHORT_SIG)]}])
    stock = T.sha256(target)

    r = apply_cmd("check", target, sigs)
    A.eq(r.returncode, 0, "check should accept a complete layout")
    A.true("1 stock" in r.stdout, "check should report the gate as stock")

    r = apply_cmd("patch", target, sigs)
    A.eq(r.returncode, 0, f"patch should succeed ({r.stderr.strip()})")
    A.eq(T.byte_at(target, SIG_AT + 4), 0xEB, "patch should flip the short jump")
    A.eq(T.byte_at(target, SIG_AT + 5), 0x2F, "patch must preserve disp8")
    A.is_file(str(target) + ".bak", "patch should create a backup")
    A.is_file(str(target) + ".bak.json", "patch should create backup metadata")
    meta = json.loads(Path(str(target) + ".bak.json").read_text(encoding="utf-8"))
    A.eq(meta["SHA256"], stock, "backup metadata should record the stock hash")
    A.eq(meta["Format"], "pe", "backup metadata should record the container")

    data = Path(target).read_bytes()
    opt = struct.unpack_from("<I", data, 0x3C)[0] + 24
    A.eq(struct.unpack_from("<II", data, opt + 144), (0, 0), "patch should clear the Security directory")
    computed, stored = pe_checksum_of(target)
    A.eq(stored, computed, "patch should leave a correct PE checksum")

    patched = T.sha256(target)
    r = apply_cmd("patch", target, sigs)
    A.eq(r.returncode, 0, "re-patch should succeed")
    A.eq(T.sha256(target), patched, "re-patch should be idempotent")
    A.true("already patched" in r.stdout, "re-patch should say there is nothing to do")

    r = apply_cmd("restore", target, sigs)
    A.eq(r.returncode, 0, f"restore should succeed ({r.stderr.strip()})")
    A.eq(T.sha256(target), stock, "restore should recover the stock file byte-for-byte")


def test_near_and_bcond(tmp):
    target = tmp / "near fixture.dll"
    sigs = tmp / "near signatures.json"
    make_pe(target, bytes.fromhex(NEAR_SIG))
    write_sigs(sigs, [{"name": "test-near", "container": "pe",
                       "sites": [site("gate", "near", "0x00001044", 4, 1, NEAR_SIG)]}])
    A.eq(apply_cmd("patch", target, sigs).returncode, 0, "near patch should succeed")
    A.eq(T.byte_at(target, SIG_AT + 4), 0x90, "near patch should write nop")
    A.eq(T.byte_at(target, SIG_AT + 5), 0xE9, "near patch should write jmp near")
    A.eq(T.byte_at(target, SIG_AT + 6), 0x8B, "near patch must preserve disp32")

    # A half-flipped pair is not a state this tool produces: it must be declined,
    # never "fixed up" by guessing.
    T.poke(target, SIG_AT + 5, 0x8F)
    r = apply_cmd("check", target, sigs)
    A.true(r.returncode != 0, "a mixed 90 8F pair must not be recognized")

    arm = tmp / "arm fixture.dll"
    arm_sigs = tmp / "arm signatures.json"
    make_pe(arm, bytes.fromhex(BCOND_SIG), machine=0xAA64)
    write_sigs(arm_sigs, [{"name": "test-arm", "container": "pe-arm64",
                           "sites": [site("gate", "bcond", "0x00001044", 4, 1, BCOND_SIG)]}])
    A.eq(apply_cmd("patch", arm, arm_sigs).returncode, 0, "arm64 bcond patch should succeed")
    word = struct.unpack_from("<I", Path(arm).read_bytes(), SIG_AT + 4)[0]
    A.eq(word & 0xF, 0x0E, "bcond patch should rewrite the condition to AL")
    A.eq(word & ~0xF, 0x54000080 & ~0xF, "bcond patch must preserve imm19 and opcode")


def test_declines(tmp):
    target = tmp / "partial fixture.dll"
    sigs = tmp / "partial signatures.json"
    make_pe(target, bytes.fromhex(SHORT_SIG))
    stock = T.sha256(target)
    write_sigs(sigs, [{"name": "test-partial", "container": "pe", "sites": [
        site("present", "short", "0x00001044", 4, 1, SHORT_SIG),
        site("missing", "short", "0x00001084", 4, 1, "837A50027F34488B8A28"),
    ]}])
    r = apply_cmd("patch", target, sigs)
    A.true(r.returncode != 0, "a partial layout must be declined by default")
    A.eq(T.sha256(target), stock, "a declined partial patch must not write")
    A.eq(apply_cmd("patch", target, sigs, "--allow-partial").returncode, 0,
         "--allow-partial should override the decline")
    A.eq(T.byte_at(target, SIG_AT + 4), 0xEB, "allowed partial should flip the located gate")

    tie = tmp / "tie fixture.dll"
    tie_sigs = tmp / "tie signatures.json"
    make_pe(tie, bytes.fromhex(SHORT_SIG))
    stock = T.sha256(tie)
    one = [site("gate", "short", "0x00001044", 4, 1, SHORT_SIG)]
    write_sigs(tie_sigs, [{"name": "twin-a", "container": "pe", "sites": one},
                          {"name": "twin-b", "container": "pe", "sites": one}])
    r = apply_cmd("patch", tie, tie_sigs)
    A.true(r.returncode != 0, "two equal-rank milestones must decline")
    A.eq(T.sha256(tie), stock, "a declined tie must not write")

    missing = tmp / "unknown fixture.dll"
    make_pe(missing, bytes.fromhex("9090909090909090909090"))
    r = apply_cmd("patch", missing, tie_sigs)
    A.true(r.returncode != 0, "an unmatched binary must be declined")


def main():
    with TemporaryDirectory(prefix="mv2 apply tests ") as td:
        tmp = Path(td)
        test_short_roundtrip(tmp)
        test_near_and_bcond(tmp)
        test_declines(tmp)
    print(f"mv2_apply.py: {A.passed} assertions passed")


if __name__ == "__main__":
    main()
