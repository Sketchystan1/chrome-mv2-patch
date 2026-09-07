"""Write a synthetic universal (fat) Mach-O to disk for the derive_milestone
self-check — an x86_64 short-jg gate (skipped: Intel macOS is unsupported) and
an arm64 b.cond gate (the one the finder derives). Thin CLI over
_testutil.make_fat_macho (single source of truth).

    python scripts/make_macho_fixture.py <out-path>
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _testutil as T


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else str(T.REPO / "_scratch" / "fatfixture")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    x64_jg, arm_jg = T.make_fat_macho(out)
    print(f"wrote {out}  (x86_64 gate @file 0x{x64_jg - 4:X}, arm64 gate @file 0x{arm_jg - 4:X})")


if __name__ == "__main__":
    main()
