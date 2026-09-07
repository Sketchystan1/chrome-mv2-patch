"""Universal Python patcher (chrome-mv2.py) regression tests, driven black-box.

Builds synthetic PE / ELF / Mach-O fixtures and drives chrome-mv2.py as a
subprocess. The Python engine is cross-platform, so all three containers run on
ANY OS via MV2_TEST_NO_ELEVATION=1 (+ MV2_TEST_HOST_ARCH for Mach-O). One
white-box check (the atomic-write race guard) imports the module directly.

Run directly (`python scripts/test_pyport.py`) or via `python scripts/run_tests.py`.
"""
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _testutil as T

SCRIPT = str(T.REPO / "chrome-mv2.py")
A = T.Asserter()
BASE_ENV = {"MV2_TEST_NO_ELEVATION": "1"}


def pyrun(sub, target, sigs, *extra, env=None):
    e = dict(BASE_ENV)
    if env:
        e.update(env)
    cmd = [sys.executable, SCRIPT, sub, str(target), "--signatures", str(sigs), "--quiet", *extra]
    return T.run(cmd, e)


def load_module():
    spec = importlib.util.spec_from_file_location("mv2mod", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def sig_doc(name, container, sites):
    return json.dumps({"milestones": [{"name": name, "container": container, "sites": sites}]})


def site(name, kind, jg_rva, sig, jg_off=4, expected=1):
    return {"name": name, "kind": kind, "jgRVA": jg_rva, "jgOff": jg_off,
            "expectedMatches": expected, "sig": sig}


def test_pe(tmp):
    sigs = tmp / "pe.json"
    sigs.write_text(sig_doc("test-pe", "pe", [site("gate", "short", "0x00001044", "837E50027F2F554889E5")]))

    t = tmp / "full fixture.dll"
    T.make_pe(t, "837E50027F2F554889E5")
    A.true(pyrun("patch", t, sigs).returncode == 0, "PE patch should succeed")
    A.eq(T.byte_at(t, 0x444), 0xEB, "PE patch should flip the short jump")
    A.is_file(f"{t}.bak", "PE patch should create a backup")
    A.is_file(f"{t}.bak.json", "PE patch should create backup metadata")

    h1 = T.sha256(t)
    pyrun("patch", t, sigs)
    A.eq(T.sha256(t), h1, "idempotent PE patch should preserve bytes")

    pyrun("restore", t, sigs)
    A.eq(T.byte_at(t, 0x444), 0x7F, "PE restore should recover the stock byte")
    A.true(not Path(f"{t}.bak").exists(), "PE restore should remove the backup")
    A.true(not Path(f"{t}.bak.json").exists(), "PE restore should remove the backup metadata")

    # unrelated modification refused and preserved
    unrel = tmp / "unrelated.dll"
    T.make_pe(unrel, "837E50027F2F554889E5")
    pyrun("patch", unrel, sigs)
    T.copy(f"{unrel}.bak", unrel)          # stock again, backup retained
    T.poke(unrel, 0x620, 0xA5)
    A.true(pyrun("patch", unrel, sigs).returncode != 0, "PE patch must refuse unrelated modifications")
    A.eq(T.byte_at(unrel, 0x620), 0xA5, "refused PE patch must preserve unrelated bytes")

    # stale restore across a different build refuses (no --force-restore)
    stale = tmp / "stale.dll"
    T.make_pe(stale, "837E50027F2F554889E5")
    pyrun("patch", stale, sigs)            # creates backup for build A
    T.make_pe(stale, "837E50027F2F554889E5", timestamp=0x22345678)   # now build B
    A.true(pyrun("restore", stale, sigs).returncode != 0, "PE stale restore should fail closed")

    # check on a recognized stock build returns 0
    chk = tmp / "check.dll"
    T.make_pe(chk, "837E50027F2F554889E5")
    A.true(pyrun("check", chk, sigs).returncode == 0, "PE check on a recognized build returns 0")

    # arm64 PE (machine 0xAA64) bcond flip
    asigs = tmp / "pe.arm64.json"
    asigs.write_text(sig_doc("test-pe-arm64", "pe-arm64",
                             [site("gate", "bcond", "0x00001044", "1F0900718C0000541F2003D51F050071")]))
    a = tmp / "arm64 fixture.dll"
    T.make_pe(a, "1F0900718C0000541F2003D51F050071", machine=0xAA64)
    A.true(pyrun("patch", a, asigs).returncode == 0, "arm64 PE patch should succeed")
    A.eq(T.byte_at(a, 0x444), 0x8E, "arm64 PE patch should flip b.gt (0x8C) -> b.al (0x8E)")
    pyrun("restore", a, asigs)
    A.eq(T.byte_at(a, 0x444), 0x8C, "arm64 PE restore should recover the stock b.gt")
    A.true(pyrun("patch", a, sigs).returncode != 0, "pe (x64) table must not patch a pe-arm64 binary")

    # arm64 PE CBZ -> B rewrite (Gate B mac-arm64 shape)
    cbz_sig = "E00314AA642EEA9460DFFF340B000014"   # mov; bl; CBZ w0(34FFDF60); b; mov
    csigs = tmp / "pe.cbz.json"
    csigs.write_text(json.dumps({"milestones": [{"name": "t-cbz", "container": "pe-arm64", "sites": [
        {"name": "gate", "kind": "cbz", "jgRVA": "0x00001044", "jgOff": 8,
         "expectedMatches": 1, "sig": cbz_sig}]}]}))
    c = tmp / "cbz fixture.dll"
    T.make_pe(c, cbz_sig, machine=0xAA64)
    A.true(pyrun("patch", c, csigs).returncode == 0, "cbz PE patch should succeed")
    A.eq(T.read_word(c, 0x448), 0x17FFFEFB, "cbz patch should rewrite 34FFDF60 -> 17FFFEFB (B, same target)")
    h = T.sha256(c)
    pyrun("patch", c, csigs)
    A.eq(T.sha256(c), h, "idempotent cbz re-patch should preserve bytes")
    pyrun("restore", c, csigs)
    A.eq(T.read_word(c, 0x448), 0x34FFDF60, "cbz restore should recover the stock CBZ")
    # a foreign B (wrong target) must not read as patched
    fb = tmp / "cbz foreign.dll"
    T.make_pe(fb, cbz_sig, machine=0xAA64)
    T.write_word(fb, 0x448, 0x14000001)          # B +4 - not our target
    A.true(pyrun("patch", fb, csigs).returncode != 0, "foreign B word must not match as patched cbz")

    # near stockOpcode (Gate B mac-x64 shape): stock 0F 84 (je) patched to 90 E9
    je_sig = "837F50020F84FCFCFFFF488B8C24200100"   # cmp; je near; mov
    jsigs = tmp / "pe.je.json"
    jsigs.write_text(json.dumps({"milestones": [{"name": "t-je", "container": "pe", "sites": [
        {"name": "gate", "kind": "near", "stockOpcode": "0x0F84", "jgRVA": "0x00001044",
         "jgOff": 4, "expectedMatches": 1, "sig": je_sig}]}]}))
    j = tmp / "je fixture.dll"
    T.make_pe(j, je_sig)
    A.true(pyrun("patch", j, jsigs).returncode == 0, "near-je stockOpcode patch should succeed")
    A.eq(T.byte_at(j, 0x444), 0x90, "near-je patch should write the 90 E9 nop/jmp pair")
    A.eq(T.byte_at(j, 0x445), 0xE9, "near-je patch should write E9 at jgOff+1")
    A.eq(T.read_dword(j, 0x446), -0x304, "near-je patch must preserve disp32 bit-identically")
    h = T.sha256(j)
    pyrun("patch", j, jsigs)
    A.eq(T.sha256(j), h, "idempotent near-je re-patch should preserve bytes")
    pyrun("restore", j, jsigs)
    A.eq(T.byte_at(j, 0x444), 0x0F, "near-je restore should recover the stock 0F 84")


def test_elf(tmp):
    sigs = tmp / "elf.json"
    sigs.write_text(sig_doc("test-elf", "elf", [site("gate", "short", "0x00400044", "837E50027F2F554889E5")]))

    t = tmp / "full fixture chrome"
    T.make_elf(t, "837E50027F2F554889E5")
    A.true(pyrun("patch", t, sigs).returncode == 0, "ELF patch should succeed")
    A.eq(T.byte_at(t, 0x144), 0xEB, "ELF patch should flip the short jump")
    A.is_file(f"{t}.bak", "ELF patch should create a backup")
    A.is_file(f"{t}.bak.meta", "ELF patch should create backup metadata")

    h1 = T.sha256(t)
    pyrun("patch", t, sigs)
    A.eq(T.sha256(t), h1, "idempotent ELF patch should preserve bytes")

    pyrun("restore", t, sigs)
    A.eq(T.byte_at(t, 0x144), 0x7F, "ELF restore should recover the stock byte")
    A.true(not Path(f"{t}.bak").exists(), "ELF restore should remove the backup")

    # forced stale restore across a different build
    T.make_elf(t, "837E50027F2F554889E5")
    pyrun("patch", t, sigs)
    T.poke(t, 0x310, 0x22)                 # different build-id note byte
    A.true(pyrun("restore", t, sigs).returncode != 0, "stale ELF restore should fail closed")
    A.true(pyrun("restore", t, sigs, "--force-restore").returncode == 0, "forced stale restore should succeed")
    A.eq(T.byte_at(t, 0x144), 0x7F, "forced stale restore should recover the backup")

    # partial: declined by default, no backup; flips with --allow-partial
    partial = tmp / "partial fixture"
    psig = tmp / "partial.json"
    T.make_elf(partial, "837E50027F2F554889E5", 0x33)
    psig.write_text(sig_doc("partial", "elf", [
        site("present", "short", "0x00400044", "837E50027F2F554889E5"),
        site("missing", "short", "0x00400084", "837A50027F34488B8A28")]))
    A.true(pyrun("patch", partial, psig).returncode != 0, "partial layout should be declined")
    A.true(not Path(f"{partial}.bak").exists(), "declined partial must not create a backup")
    A.true(pyrun("patch", partial, psig, "--allow-partial").returncode == 0, "explicit partial patch should succeed")
    A.eq(T.byte_at(partial, 0x144), 0xEB, "explicit partial patch should flip the located gate")

    # most-specific full match wins ('small' listed first to prove it's by specificity)
    two = tmp / "two gate fixture"
    tsig = tmp / "two.json"
    T.make_elf(two, "837E50027F2F554889E5" + "00" * 22 + "837A50027F34488B8A28")
    tsig.write_text(json.dumps({"milestones": [
        {"name": "small", "container": "elf", "sites": [site("a", "short", "0x00400044", "837E50027F2F554889E5")]},
        {"name": "big", "container": "elf", "sites": [
            site("a", "short", "0x00400044", "837E50027F2F554889E5"),
            site("b", "short", "0x00400064", "837A50027F34488B8A28")]}]}))
    A.true(pyrun("patch", two, tsig).returncode == 0, "most-specific full match should patch")
    A.eq(T.byte_at(two, 0x144), 0xEB, "the 2-site milestone must flip gate A")
    A.eq(T.byte_at(two, 0x164), 0xEB, "the 2-site milestone must flip gate B (proves 'big' won)")

    # two equal-size full matches -> genuine collision, declined
    fa = tmp / "full ambiguous"
    fsig = tmp / "fa.json"
    T.make_elf(fa, "837E50027F2F554889E5" + "00" * 22 + "837A50027F34488B8A28")
    fsig.write_text(json.dumps({"milestones": [
        {"name": "x", "container": "elf", "sites": [site("a", "short", "0x00400044", "837E50027F2F554889E5")]},
        {"name": "y", "container": "elf", "sites": [site("b", "short", "0x00400064", "837A50027F34488B8A28")]}]}))
    A.true(pyrun("patch", fa, fsig).returncode != 0, "two equal-size full matches should be declined")
    A.eq(T.byte_at(fa, 0x144), 0x7F, "declined full collision must change nothing")

    # mixed near pair fails check
    mixed = tmp / "mixed near"
    msig = tmp / "mixed.json"
    T.make_elf(mixed, "837F50020FE98B000000488B", 0x55)
    msig.write_text(sig_doc("near", "elf", [site("n", "near", "0x00400044", "837F50020F8F8B000000488B")]))
    A.true(pyrun("check", mixed, msig).returncode != 0, "mixed near pair should fail check")

    # tampered backup metadata fails restore
    T.make_elf(t, "837E50027F2F554889E5")
    pyrun("patch", t, sigs)
    with open(f"{t}.bak.meta", "a") as f:
        f.write("sha256=bad\n")
    A.true(pyrun("restore", t, sigs).returncode != 0, "tampered backup metadata should fail restore")

    # arm64 ELF bcond flip
    a64 = tmp / "arm64 fixture chrome"
    a64sig = tmp / "arm64.json"
    T.make_elf(a64, "1F0900718C0000541F2003D51F050071", machine=0xB7)
    a64sig.write_text(sig_doc("test-elf-arm64", "elf-arm64",
                              [site("gate", "bcond", "0x00400044", "1F0900718C0000541F2003D51F050071")]))
    A.true(pyrun("patch", a64, a64sig).returncode == 0, "arm64 ELF patch should succeed")
    A.eq(T.byte_at(a64, 0x144), 0x8E, "arm64 patch should flip b.gt (0x8C) -> b.al (0x8E)")
    pyrun("restore", a64, a64sig)
    A.eq(T.byte_at(a64, 0x144), 0x8C, "arm64 restore should recover the stock b.gt")
    A.true(pyrun("patch", a64, sigs).returncode != 0, "elf (x86_64) table must not patch an elf-arm64 binary")


def test_macho(tmp):
    sigs = tmp / "mac.json"
    sigs.write_text(json.dumps({"milestones": [
        {"name": "t-x64", "container": "macho-x64", "sites": [
            site("gx", "short", "0x100000044", "837E50027F2F554889E5")]},
        {"name": "t-arm64", "container": "macho-arm64", "sites": [
            site("ga", "bcond", "0x100000044", "1F0900718C000054")]}]}))
    ENVX = {"MV2_TEST_HOST_ARCH": "x86_64"}
    ENVA = {"MV2_TEST_HOST_ARCH": "arm64"}

    t = tmp / "fixture-fat"
    x64_jg, arm_jg = T.make_fat_macho(t)
    A.true(pyrun("check", t, sigs, env=ENVX).returncode == 0, "check parses the fat fixture")

    pyrun("patch", t, sigs, env=ENVX)
    A.eq(T.byte_at(t, x64_jg), 0xEB, "x64 short jg flipped by default (x64 host)")
    A.eq(T.byte_at(t, arm_jg) & 0x0F, 0x0C, "arm64 left stock (GT) on an x64 host")
    A.is_file(f"{t}.bak", "macho patch creates a backup")
    A.is_file(f"{t}.bak.meta", "macho patch creates backup metadata")

    h1 = T.sha256(t)
    pyrun("patch", t, sigs, env=ENVX)
    A.eq(T.sha256(t), h1, "idempotent macho patch preserves bytes")

    pyrun("restore", t, sigs, env=ENVX)
    A.eq(T.byte_at(t, x64_jg), 0x7F, "restore recovers x64 stock byte")
    A.true(not Path(f"{t}.bak").exists(), "macho restore removes the backup")

    # arm64 host: arm64 slice is the default target
    ah = tmp / "fixture-armhost"
    ax64_jg, aarm_jg = T.make_fat_macho(ah)
    pyrun("patch", ah, sigs, env=ENVA)
    A.eq(T.byte_at(ah, aarm_jg) & 0x0F, 0x0E, "arm64 b.cond flipped GT->AL on an arm64 host")
    A.eq(T.byte_at(ah, ax64_jg), 0x7F, "x64 left stock on an arm64 host")
    A.is_file(f"{ah}.bak", "arm64-host patch creates a backup")

    # tampered backup metadata rejected on restore
    with open(f"{ah}.bak.meta", "a") as f:
        f.write("sha256=bad\n")
    A.true(pyrun("restore", ah, sigs, env=ENVA).returncode != 0, "tampered macho metadata should fail restore")


def test_race(tmp):
    m = load_module()
    rt = tmp / "race target"
    rs = tmp / "race source"
    rt.write_bytes(b"old")
    rs.write_bytes(b"new")
    threw = False
    try:
        m.write_atomic(str(rt), b"new", expected_current_hash="0" * 64)
    except m.Mv2Error:
        threw = True
    A.true(threw, "atomic writer should reject a changed target")
    A.eq(rt.read_bytes(), b"old", "race rejection must preserve target bytes")


def test_featurebyte(tmp):
    # A milestone with a required MV2 gate (short jg) plus an OPTIONAL featurebyte
    # site (webRequestBlocking rule-1 max_manifest_version 2 -> 3 in .rdata).
    gate = "837E50027F2F554889E5"
    fb = {"name": "wrb", "kind": "featurebyte", "optional": True, "feature": "webRequestBlocking",
          "structRVA": "0x00002040", "patchOff": 192, "stock": 2, "patched": 3,
          "verify": {"96": 2, "180": 0, "188": 0, "196": 1}, "expectedMatches": 1}
    # An optional SHORT branch site too (Gate B's shape: a jg guard flipped to skip).
    gate2 = "83FE027F0590"
    gb = {"name": "gateB", "kind": "short", "optional": True, "jgRVA": "0x00001083",
          "jgOff": 3, "expectedMatches": 1, "sig": gate2}
    sigs = tmp / "fb.json"
    sigs.write_text(sig_doc("test-fb", "pe", [site("gate", "short", "0x00001044", gate), fb, gb]))

    t = tmp / "feature fixture.dll"
    T.make_pe_feature(t, gate, gate2_hex=gate2, gate2_off=0x80)
    A.true(pyrun("patch", t, sigs).returncode == 0, "featurebyte patch should succeed")
    A.eq(T.byte_at(t, 0x444), 0xEB, "the required MV2 gate should flip")
    A.eq(T.byte_at(t, 0x700), 0x03, "featurebyte should flip max_manifest_version 2 -> 3")
    A.eq(T.byte_at(t, 0x483), 0xEB, "optional short site should flip its jg -> jmp")

    h1 = T.sha256(t)
    pyrun("patch", t, sigs)
    A.eq(T.sha256(t), h1, "idempotent featurebyte patch should preserve bytes")

    pyrun("restore", t, sigs)
    A.eq(T.byte_at(t, 0x444), 0x7F, "restore should recover the gate byte")
    A.eq(T.byte_at(t, 0x700), 0x02, "restore should recover the stock max_manifest_version")
    A.eq(T.byte_at(t, 0x483), 0x7F, "restore should recover the optional short jg")

    # Feature struct ABSENT (single-section PE, no .rdata): the optional site is
    # skipped and the required MV2 gate still patches - featurebyte never blocks MV2.
    plain = tmp / "no feature.dll"
    T.make_pe(plain, gate)
    A.true(pyrun("patch", plain, sigs).returncode == 0, "patch should succeed with the optional site absent")
    A.eq(T.byte_at(plain, 0x444), 0xEB, "MV2 gate should still flip when featurebyte is absent")


def main():
    tmp = Path(tempfile.mkdtemp(prefix="chrome-mv2-py-tests-"))
    test_pe(tmp)
    test_elf(tmp)
    test_macho(tmp)
    test_featurebyte(tmp)
    test_race(tmp)
    print(f"Python tests passed: {A.passed} assertions")


if __name__ == "__main__":
    main()
