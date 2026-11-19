# Research and verification tools

Use Python 3.11 or newer. The deployed patcher is the [native Windows auto patcher](../mv2-mem-patch-win/README.md).
These scripts fetch research artifacts, inspect binaries and test that implementation.
Linux and macOS will use the same native discovery and in-memory patching workflow;
their artifact and container tools remain here for the future ports.

The milestone authoring pipeline and tests for the removed Python/PowerShell/Bash
patchers have been retired. The last legacy [`signatures.json`](../signatures.json)
is retained for older releases, including v1.16.0; the native patcher does not read
it. Historical source and experiments remain in Git history.
[mv2-reversing.md](../mv2-reversing.md) retains the shared predicate, failed
approaches and platform lessons.

## Tools

| Tool | Purpose | Requirements |
| --- | --- | --- |
| `fetch_chrome_binary.py` | Fetch a stock Windows DLL, Linux ELF or macOS framework into `_scratch/`; verify the target architecture and name it using the binary's reported version where available. | Python + 7-Zip |
| `fetch_arm64_browser.py` | Fetch complete stock Windows ARM64 Chrome/Edge Stable, Beta or Canary copies and write a browser-test matrix; verify vendor installer hashes, sizes, PE machines and versions. | Python + 7-Zip |
| `fetch_symbols.py` | Fetch matching PDB, Linux debug-info or macOS dSYM symbols; reject identity mismatches. | Python standard library |
| `symbols_from_pdb.py` | Resolve named MV2-related functions through Windows dbghelp. | Windows + matching PDB |
| `symbols_from_elf.py` | Stream an ELF's function symbols into `nm -S` style text without a full demangle/sort pass. | Python standard library |
| `binary_image.py` | Read code-section metadata from PE x64/x86/ARM64, ELF x64/ARM64 and thin/fat Mach-O ARM64; usable as a module or JSON inspection CLI. | Python standard library |
| `scan_windows.py` | Read-only x64 research prototype: recover field relationships and check local predicate routing. | Capstone + z3-solver |
| `check_autoscan_matrix.py` | Evaluate the native scanner against independent, hash-bound reviewed address baselines. | Built `mv2-scan.exe` |
| `test_autoscan_runtime.py`, `autoscan_cdp.mjs` | Exercise the same deployed DLL on isolated browser copies, including MV2/MV3 controls and cache/removal checks. | Windows, matching x64/x86/ARM64 native test targets, Node 22+, OpenSSL |
| `test_autoscan_crx.py`, `autoscan_crx_cdp.mjs` | Install signed CRX3 controls through the browser's Downloads page and native confirmation; reject tampered packages and missing developer proofs. | Windows, matching x64/x86/ARM64 native test targets, Node 22+, OpenSSL |
| `macho_insert_dylib.py` | Scratch-copy research for inserting/removing a dylib load command; retained for a future macOS loader. | Python standard library |

`_testutil.py` contains only synthetic PE/ELF/Mach-O fixture builders. The Mach-O
load-command helper edits the supplied file when explicitly invoked with
`insert`/`remove`; it has no installer, backup or signing workflow. Its self-test
uses temporary fixtures and does not modify a browser.

## Local checks

```text
python scripts/run_tests.py
python scripts/run_tests.py --fast
uv run --with capstone --with z3-solver scripts/run_tests.py
```

The default run checks the image readers, scanner evaluation, Mach-O load-command
fixtures and Python scanner, plus the Windows batch installer on Windows and CDP
helper syntax when Node is available. Independent checks run concurrently.
`--fast` (or `MV2_TEST_FAST=1`) skips the Windows installer integration suite.
Capstone/Z3 checks report a skip when those dependencies are unavailable.

The image-reader fixtures exercise Linux and macOS formats on any host. They do
not launch a Unix patcher or establish native browser behavior. The Windows
installer suite uses temporary files and isolated browser-named test processes.

The shipping C++ scanner, proxy, application, cache and lifecycle helpers have
their own CMake tests. After building the test targets from a matching Visual
Studio Developer Command Prompt:

```bat
cd mv2-mem-patch-win
cmake --build out/x64
ctest --preset x64
out\x64\mv2-scan.exe "C:\path\to\chrome.dll"
```

Use the x86/ARM64 presets for those builds; native ARM64 test execution requires
ARM64 Windows. Deployment DLLs live in `build/<arch>/`, and diagnostic/test
executables in `out/<arch>/`.

## Fetch and inspect a reference build

```text
python scripts/fetch_chrome_binary.py --platform win64 --version 157.0.8103.79
python scripts/fetch_chrome_binary.py --platform linux
python scripts/fetch_chrome_binary.py --platform linux-arm64
python scripts/fetch_chrome_binary.py --platform mac-arm64 --branded
python scripts/binary_image.py <stock-binary>
python scripts/fetch_symbols.py <stock-binary>
```

Use `win` for Windows x86 and `win-arm64` for Windows ARM64. `--channel beta`,
`--version` and `--url` select artifacts where supported. Windows ARM64 has no
Chrome for Testing fallback; use a channel installer or explicit URL.
Linux ARM64 also has a Chrome for Testing fallback.

macOS defaults to an unbranded Chrome for Testing framework; `--branded` fetches a
consumer DMG for optional install-check research. Consumer dSYMs require
`fetch_symbols.py --chrome-version <version>` and a matching framework UUID.
Chrome for Testing builds can lack published symbols. Never use a different
build's PDB, ELF debug-info or dSYM as address evidence.

Windows symbol names come from `symbols_from_pdb.py <chrome.dll> --symdir _scratch
--json _scratch/syms.json`; Linux names from `symbols_from_elf.py
_scratch/chrome.debug _scratch/syms.txt`. macOS symbol fetching emits nm-style
text directly. Symbols guide source/disassembly review; runtime discovery must
work without them.

## Discovery evaluation and browser experiments

```text
uv run --with capstone --with z3-solver scripts/scan_windows.py <chrome.dll> --json _scratch/scan.json
python scripts/check_autoscan_matrix.py _scratch/matrix.json --output _scratch/scanner-results
python scripts/test_autoscan_runtime.py _scratch/runtime-matrix.json --work _scratch/runtime-results
```

The Python scanner is a separate, bounded x64 proof prototype. It supports
fewer layouts than the native scanner and always reports
`complete_enforcement_coverage_proven: false`. It emits analysis reports only;
the retired signature-window `--plan` export is removed.

The native scanner matrix is a nonempty JSON list. Every entry supplies a stock
`binary`, a `version` label and an independently reviewed baseline:

```json
[
  {
    "version": "reference build",
    "binary": "C:/path/to/chrome.dll",
    "reviewed_baseline": {
      "sha256": "<SHA-256 of this stock binary>",
      "provenance": "source/symbol review and both branch outcomes",
      "core": ["0x1234", "0x5678"],
      "optional": ["0x9abc"]
    }
  }
]
```

Replace the example addresses and hash with reviewed evidence. Baselines are
evaluation input and are never passed to the scanner. An identity mismatch,
missing required decision or unexpected decision fails evaluation. Optional
decisions may be absent. The matrix writes individual reports and `results.json`;
`--scanner` overrides the default `out/x64/mv2-scan.exe`.

The runtime matrix instead needs `version`, `executable` and `binary` paths to
complete stock browser copies. It uses `out/x64/` test helpers and the DLL in
`build/x64/secur32.dll` by default; `--arch x86` selects matching x86 helpers and
the x86 DLL. `--dll` can select another local build.
`--work` must be a new directory beneath `_scratch/`. The test redirects external
extension registry reads to a private HKCU subtree, checks stock/patched/removal
behavior, and restarts with an empty cache. These browser experiments are
separate from the local fixture suite.

`--arch arm64` selects ARM64 helpers and the ARM64 DLL and requires native ARM64
Windows. The [Windows ARM64 workflow](../.github/workflows/win-arm64-test.yml)
builds and runs native CTest on `windows-11-arm`, then tests the latest consumer
Chrome and Edge Stable (release), Beta and Canary in six independent jobs. It
runs on pushes to `test/windows-arm64-browser-channels` and supports manual
dispatch. Each job saves vendor download metadata, browser identities and scan
reports, including on failure. Chrome also runs the seven-phase signed CRX/MV2
lifecycle. Edge ARM64 discovery currently fails with
`Edge installer recognition requires x64`; those jobs remain failures, and Edge
browser lifecycle coverage must be added when its ARM64 recognition is supported.

```text
python scripts/fetch_arm64_browser.py --browser chrome --channel canary --out _scratch/arm64-browser
python scripts/test_autoscan_crx.py _scratch/arm64-browser/matrix.json --arch arm64 --work _scratch/arm64-crx
```

The CRX installation harness uses a single-entry runtime matrix and a new, short
directory below `_scratch/`. It launches a browser copy on a private Windows
desktop and keeps downloads, profiles, cache and registry changes private. The
test-only `browser-ui.exe` invokes the owned browser's ordinary Add extension
confirmation without switching desktops or sending global input. It verifies
stock rejection, signed installation, tampered-signature and missing-proof
rejection, MV2 enablement/request blocking, an MV3 background control, cached and
empty-cache restarts, and removal. Browser executable and DLL hashes must remain
unchanged.

```text
python scripts/test_autoscan_crx.py _scratch/runtime-matrix.json --arch x86 --work _scratch/crx-check
```

## Future ports

Retain ELF virtual/file address mapping, Mach-O slice/UUID handling and matched
symbol fetching. Reuse the reviewed predicate and native decoding/proof model,
then implement each platform's function bounds, loader timing, relocation
validation, cache protection and transactional memory edits. macOS also needs a
validated loading/signing path with preserved entitlements. Historical branch and
off-store findings are in `mv2-reversing.md`; a successful fixture or local proof
does not certify a new platform.
