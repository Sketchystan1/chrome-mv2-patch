"""Linux ELF regression tests for chrome-mv2.sh, driven as a black box.

Builds synthetic ELF fixtures in Python and exercises patch / restore / check,
backup + metadata, idempotency, decline paths, and the atomic-write race guard.
Run directly (`python scripts/test_linux.py`) or via `python scripts/run_tests.py`.
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _testutil as T

SCRIPT = str(T.REPO / "chrome-mv2.sh")
ENV = {"MV2_TEST_NO_ELEVATION": "1"}
A = T.Asserter()


def patch(target, sigs, *extra):
    return T.bash(SCRIPT, "patch", target, sigs, *extra, env=ENV)


def restore(target, sigs, *extra):
    return T.bash(SCRIPT, "restore", target, sigs, *extra, env=ENV)


def check(target, sigs, *extra):
    return T.bash(SCRIPT, "check", target, sigs, *extra, env=ENV)


FULL_SIG = {"milestones": [{"name": "test-elf", "container": "elf", "sites": [
    {"name": "gate", "kind": "short", "jgRVA": "0x00400044", "jgOff": 4,
     "expectedMatches": 1, "sig": "837E50027F2F554889E5"}]}]}


def main():
    tmp = Path(tempfile.mkdtemp(prefix="chrome-mv2-bash-tests-"))
    target = tmp / "full fixture chrome"
    sigs = tmp / "full signatures.json"
    T.make_elf(target, "837E50027F2F554889E5")
    sigs.write_text(json.dumps(FULL_SIG))

    A.true(patch(target, sigs).returncode == 0, "full synthetic patch should succeed")
    A.eq(T.byte_at(target, 0x144), 0xEB, "full patch should flip short jump")
    A.is_file(f"{target}.bak", "patch should create backup")
    A.is_file(f"{target}.bak.meta", "patch should create backup metadata")

    h1 = T.sha256(target)
    patch(target, sigs)
    A.eq(T.sha256(target), h1, "idempotent patch should preserve bytes")

    restore(target, sigs)
    A.eq(T.byte_at(target, 0x144), 0x7F, "restore should recover stock byte")
    A.true(not Path(f"{target}.bak").exists(), "restore should remove the backup")
    A.true(not Path(f"{target}.bak.meta").exists(), "restore should remove the backup metadata")

    # target is stock again; re-patch to recreate a backup for the remaining sub-tests
    patch(target, sigs)

    # unrelated modification must be refused and preserved
    T.poke(target, 0x220, 0xA5)
    A.true(patch(target, sigs).returncode != 0, "patch must refuse unrelated modifications")
    A.eq(T.byte_at(target, 0x220), 0xA5, "refused patch must preserve unrelated bytes")
    T.copy(f"{target}.bak", target)

    # stale restore across a different build refuses unless forced
    patch(target, sigs)
    T.poke(target, 0x310, 0x22)
    A.true(restore(target, sigs).returncode != 0, "stale restore should fail closed")
    A.true(restore(target, sigs, "--force-restore").returncode == 0, "forced stale restore should succeed")
    A.eq(T.byte_at(target, 0x144), 0x7F, "forced stale restore should recover backup")
    A.true(not Path(f"{target}.bak").exists(), "forced restore should also remove the backup")

    # partial layout: declined by default, no backup; flips with --allow-partial
    partial = tmp / "partial fixture"
    psig = tmp / "partial signatures.json"
    T.make_elf(partial, "837E50027F2F554889E5", 0x33)
    psig.write_text(json.dumps({"milestones": [{"name": "partial", "container": "elf", "sites": [
        {"name": "present", "kind": "short", "jgRVA": "0x00400044", "jgOff": 4, "expectedMatches": 1, "sig": "837E50027F2F554889E5"},
        {"name": "missing", "kind": "short", "jgRVA": "0x00400084", "jgOff": 4, "expectedMatches": 1, "sig": "837A50027F34488B8A28"}]}]}))
    A.true(patch(partial, psig).returncode != 0, "partial layout should be declined")
    A.true(not Path(f"{partial}.bak").exists(), "declined partial must not create a backup")
    A.true(patch(partial, psig, "--allow-partial").returncode == 0, "explicit partial patch should succeed")
    A.eq(T.byte_at(partial, 0x144), 0xEB, "explicit partial patch should flip located gate")
    restore(partial, psig)
    A.eq(T.byte_at(partial, 0x144), 0x7F, "partial-mode backup should remain restorable")
    A.true(not Path(f"{partial}.bak").exists(), "restore should remove the partial backup")

    # milestone selection prefers the MOST-SPECIFIC full match. Two gates present;
    # a 1-site milestone AND a 2-site superset both fully match (same container).
    # The 2-site one must win (so a fuller multi-site table beats a smaller
    # single-site table that also fits, and vice-versa). "small"
    # is listed first to prove the choice is by specificity, not table order.
    two = tmp / "two gate fixture"
    tsig = tmp / "two gate signatures.json"
    T.make_elf(two, "837E50027F2F554889E5" + "00" * 22 + "837A50027F34488B8A28")
    tsig.write_text(json.dumps({"milestones": [
        {"name": "small", "container": "elf", "sites": [
            {"name": "gate-a", "kind": "short", "jgRVA": "0x00400044", "jgOff": 4, "expectedMatches": 1, "sig": "837E50027F2F554889E5"}]},
        {"name": "big", "container": "elf", "sites": [
            {"name": "gate-a", "kind": "short", "jgRVA": "0x00400044", "jgOff": 4, "expectedMatches": 1, "sig": "837E50027F2F554889E5"},
            {"name": "gate-b", "kind": "short", "jgRVA": "0x00400064", "jgOff": 4, "expectedMatches": 1, "sig": "837A50027F34488B8A28"}]}]}))
    A.true(patch(two, tsig).returncode == 0, "most-specific full match should patch")
    A.eq(T.byte_at(two, 0x144), 0xEB, "the 2-site milestone must flip gate A")
    A.eq(T.byte_at(two, 0x164), 0xEB, "the 2-site milestone must flip gate B (proves 'big' won, not 'small')")
    restore(two, tsig)

    # two DIFFERENT milestones that each fully match with the SAME site count are a
    # genuine collision -> declined even though both are full.
    fullamb = tmp / "full ambiguous fixture"
    fasig = tmp / "full ambiguous signatures.json"
    T.make_elf(fullamb, "837E50027F2F554889E5" + "00" * 22 + "837A50027F34488B8A28")
    fasig.write_text(json.dumps({"milestones": [
        {"name": "x", "container": "elf", "sites": [
            {"name": "gate-a", "kind": "short", "jgRVA": "0x00400044", "jgOff": 4, "expectedMatches": 1, "sig": "837E50027F2F554889E5"}]},
        {"name": "y", "container": "elf", "sites": [
            {"name": "gate-b", "kind": "short", "jgRVA": "0x00400064", "jgOff": 4, "expectedMatches": 1, "sig": "837A50027F34488B8A28"}]}]}))
    A.true(patch(fullamb, fasig).returncode != 0, "two equal-size full matches should be declined")
    A.eq(T.byte_at(fullamb, 0x144), 0x7F, "declined full collision must change nothing")

    # ambiguous milestones (two tie): declined even with --allow-partial
    amb = tmp / "ambiguous fixture"
    asig = tmp / "ambiguous signatures.json"
    T.make_elf(amb, "837E50027F2F554889E5", 0x44)
    asig.write_text(json.dumps({"milestones": [
        {"name": "a", "container": "elf", "sites": [
            {"name": "present-a", "kind": "short", "jgRVA": "0x00400044", "jgOff": 4, "expectedMatches": 1, "sig": "837E50027F2F554889E5"},
            {"name": "missing-a", "kind": "short", "jgRVA": "0x00400084", "jgOff": 4, "expectedMatches": 1, "sig": "837A50027F34488B8A28"}]},
        {"name": "b", "container": "elf", "sites": [
            {"name": "present-b", "kind": "short", "jgRVA": "0x00400044", "jgOff": 4, "expectedMatches": 1, "sig": "837E50027F2F554889E5"},
            {"name": "missing-b", "kind": "short", "jgRVA": "0x004000C4", "jgOff": 4, "expectedMatches": 1, "sig": "837B50027F30488B8B28"}]}]}))
    A.true(patch(amb, asig, "--allow-partial").returncode != 0, "ambiguous layouts should be declined")

    # mixed near pair: check must fail
    mixed = tmp / "mixed near fixture"
    msig = tmp / "mixed signatures.json"
    T.make_elf(mixed, "837F50020FE98B000000488B", 0x55)
    msig.write_text(json.dumps({"milestones": [{"name": "near", "container": "elf", "sites": [
        {"name": "near-gate", "kind": "near", "jgRVA": "0x00400044", "jgOff": 4, "expectedMatches": 1, "sig": "837F50020F8F8B000000488B"}]}]}))
    A.true(check(mixed, msig).returncode != 0, "mixed near pair should fail check")

    # corrupt section table: check must fail (target is stock here after the
    # forced restore above, so it is a valid clean ELF to corrupt)
    bad = tmp / "bad elf"
    T.copy(target, bad)
    with open(bad, "r+b") as f:
        f.seek(0x28)
        f.write(b"\xff\xff\xff\x7f\x00\x00\x00\x00")
    A.true(check(bad, sigs).returncode != 0, "out-of-bounds section table should fail")

    # tampered backup metadata: restore must fail (re-patch to recreate a backup,
    # since the restores above removed it)
    patch(target, sigs)
    with open(f"{target}.bak.meta", "a") as f:
        f.write("sha256=bad\n")
    A.true(restore(target, sigs).returncode != 0, "tampered backup metadata should fail restore")

    # atomic-write race guard (white-box via the script's own function)
    rt, rs = tmp / "race target", tmp / "race source"
    rt.write_text("old")
    rs.write_text("new")
    race = ('set -euo pipefail; export MV2_TEST_LIBRARY_ONLY=1; source "$1"; init_colors; '
            'write_target "$2" "$3" "$(printf wrong)"')
    A.true(T.run([T.BASH, "-c", race, "_", T.posix(SCRIPT), T.posix(rt), T.posix(rs)]).returncode != 0,
           "atomic writer should reject a changed target")
    A.eq(rt.read_text(), "old", "race rejection must preserve target bytes")

    # ELF64 arm64 (aarch64): e_machine 0xB7 -> container elf-arm64, bcond flip.
    # Gate = cmp w8,#2 ; b.gt ; nop ; cmp w?,#1 ; the flip rewrites b.gt(0x8C)->b.al(0x8E).
    a64 = tmp / "arm64 fixture chrome"
    a64sig = tmp / "arm64 signatures.json"
    T.make_elf(a64, "1F0900718C0000541F2003D51F050071", machine=0xB7)
    a64sig.write_text(json.dumps({"milestones": [{"name": "test-elf-arm64", "container": "elf-arm64", "sites": [
        {"name": "gate", "kind": "bcond", "jgRVA": "0x00400044", "jgOff": 4,
         "expectedMatches": 1, "sig": "1F0900718C0000541F2003D51F050071"}]}]}))
    A.true(patch(a64, a64sig).returncode == 0, "arm64 ELF patch should succeed")
    A.eq(T.byte_at(a64, 0x144), 0x8E, "arm64 patch should flip b.gt (0x8C) to b.al (0x8E)")
    A.is_file(f"{a64}.bak", "arm64 patch should create backup")
    restore(a64, a64sig)
    A.eq(T.byte_at(a64, 0x144), 0x8C, "arm64 restore should recover stock b.gt")
    A.true(not Path(f"{a64}.bak").exists(), "arm64 restore should remove the backup")
    A.true(patch(a64, sigs).returncode != 0, "elf (x86_64) table must not patch an elf-arm64 binary")

    print(f"Bash tests passed: {A.passed} assertions")


if __name__ == "__main__":
    main()

