"""macOS Mach-O regression tests for chrome-mv2.sh, driven as a black box.

Builds a synthetic universal (fat) fixture in Python and exercises patch /
restore / check on the arm64 (Apple Silicon) slice - the only supported macOS
target. The x86_64 slice is present in the fixture but must be SKIPPED (Intel
macOS is no longer supported). The host CPU is pinned per scenario via
MV2_TEST_HOST_ARCH so results are independent of the CI runner's architecture.
The loose-file target path skips bundle re-signing, so this runs anywhere.
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _testutil as T

SCRIPT = str(T.REPO / "chrome-mv2.sh")
# macOS is arm64-only now; the default host is Apple Silicon. An x86_64 host is
# exercised separately and must be refused.
ENV = {"MV2_TEST_NO_ELEVATION": "1", "MV2_TEST_HOST_ARCH": "arm64"}
ENV_X64 = {"MV2_TEST_NO_ELEVATION": "1", "MV2_TEST_HOST_ARCH": "x86_64"}
A = T.Asserter()


def cmd(sub, target, sigs, *extra, env=ENV):
    return T.bash(SCRIPT, sub, target, sigs, *extra, env=env)


def nib(path, off):
    return T.byte_at(path, off) & 0x0F


SIGS = {"milestones": [
    {"name": "t-arm64", "container": "macho-arm64", "sites": [
        {"name": "gate-arm64", "kind": "bcond", "jgRVA": "0x100000044", "jgOff": 4,
         "expectedMatches": 1, "sig": "1F0900718C000054"}]}]}


def main():
    tmp = Path(tempfile.mkdtemp(prefix="chrome-mv2-macos-tests-"))
    sigs = tmp / "sigs.json"
    sigs.write_text(json.dumps(SIGS))
    target = tmp / "fixture-fat"
    x64_jg, arm_jg = T.make_fat_macho(target)

    A.true(cmd("check", target, sigs).returncode == 0, "check parses the fat fixture (arm64 slice)")

    # On an arm64 host the arm64 slice is the default target; the x64 slice is
    # unsupported and skipped entirely (its bytes must never change).
    cmd("patch", target, sigs)
    A.eq(nib(target, arm_jg), 0x0E, "arm64 b.cond flipped GT(0xC)->AL(0xE) by default")
    A.eq(T.byte_at(target, x64_jg), 0x7F, "x64 slice left stock (unsupported, skipped)")
    A.is_file(f"{target}.bak", "patch creates a backup")
    A.is_file(f"{target}.bak.meta", "patch creates backup metadata")

    # idempotent rerun preserves bytes
    h1 = T.sha256(target)
    cmd("patch", target, sigs)
    A.eq(T.sha256(target), h1, "idempotent patch preserves bytes")

    # restore -> arm64 slice stock again
    cmd("restore", target, sigs)
    A.eq(nib(target, arm_jg), 0x0C, "restore recovers arm64 stock (GT)")
    A.eq(T.byte_at(target, x64_jg), 0x7F, "x64 slice still stock after restore")
    A.true(not Path(f"{target}.bak").exists(), "restore should remove the backup")
    A.true(not Path(f"{target}.bak.meta").exists(), "restore should remove the backup metadata")

    # --- Intel (x86_64) host is no longer supported -------------------------
    x64host = tmp / "fixture-x64host"
    T.make_fat_macho(x64host)
    A.true(cmd("patch", x64host, sigs, env=ENV_X64).returncode != 0,
           "patch on an Intel (x86_64) host is refused")
    A.true(not Path(f"{x64host}.bak").exists(), "refused Intel patch creates no backup")

    # refuse to overwrite unrelated modifications
    cmd("patch", target, sigs)
    T.copy(f"{target}.bak", target)
    T.poke(target, 8, 0x99)  # tamper the fat header region
    A.true(cmd("patch", target, sigs).returncode != 0, "patch must refuse unrelated modifications")
    T.copy(f"{target}.bak", target)

    # decline: a valid-but-absent b.gt signature; no backup created
    miss = tmp / "miss.json"
    miss.write_text(json.dumps({"milestones": [{"name": "m", "container": "macho-arm64", "sites": [
        {"name": "absent", "kind": "bcond", "jgRVA": "0x100000044", "jgOff": 4,
         "expectedMatches": 1, "sig": "1F0A00718C000054"}]}]}))
    fresh = tmp / "fixture-fresh"
    T.make_fat_macho(fresh)
    A.true(cmd("patch", fresh, miss).returncode != 0, "declined patch fails")
    A.true(not Path(f"{fresh}.bak").exists(), "declined patch must not create a backup")

    # stale backup metadata rejected on restore
    cmd("patch", target, sigs)
    with open(f"{target}.bak.meta", "a") as f:
        f.write("sha256=bad\n")
    A.true(cmd("restore", target, sigs).returncode != 0, "tampered backup metadata should fail restore")

    print(f"macOS tests passed: {A.passed} assertions")


if __name__ == "__main__":
    main()
