# Agent Workspace Guidelines — Chrome MV2 Patcher

Read [mv2-reversing.md](../mv2-reversing.md) before changing discovery or patch
semantics. [scripts/README.md](../scripts/README.md) describes the research and
verification tools; [the Windows README](../mv2-mem-patch-win/README.md) describes
the deployed implementation.

## Current repository

- `mv2-mem-patch-win/` builds the native Windows `secur32.dll` auto patcher for
  x64, x86 and ARM64. `install.bat` installs a local DLL beside `chrome.exe` or
  `msedge.exe`; `build.bat` and Visual Studio share CMake presets.
- Deployment DLLs and installers go in ignored `build/<arch>/`. Dependencies,
  diagnostic tools, fixtures and build intermediates go in ignored `out/<arch>/`.
- `scripts/` contains research tools and tests. Binary downloads and browser
  experiments belong in ignored `_scratch/`.
- Linux and macOS native auto patchers are planned. Their binary readers,
  downloaders, symbol tools and Mach-O loader research are retained for those ports.

The Go/Python patchers, PowerShell/Bash byte patchers, maintained signature tables
and table derivation tools are retired. The native scanner discovers the checks
from each browser image without tables, debug symbols, Capstone or Z3. Support
depends on recognized code, rather than a fixed milestone list.

## Patch semantics

Select a recognized check's existing not-affected outcome after reviewing both
paths. Preserve calls and their side effects, manifest values, branch targets and
instruction widths. Never turn a reason-string selector or CSP check into an
enforcement patch.

For x86/x64, a recognized taken outcome becomes a short `JMP` or `NOP; JMP`;
an inverted check becomes a complete NOP sequence. ARM64 conditional branches
select their existing target or fall-through; optional test-bit branches recompute
the unconditional branch displacement to the same target. Historical Linux/macOS
CBZ and CSEL forms are research evidence, not automatic Windows coverage.

Unknown instructions, conflicting field roles, ambiguous candidates, incomplete
plans and capacity/bounds failures must decline. Do not weaken a rejection or
identity check to accept a new browser. A bounded local predicate proof does not
prove complete enforcement coverage.

## Runtime contract

Keep discovery separate from application:

- Read the stock browser image without modifying it; infer field relationships
  and verify the source predicate with bounded instruction/control-flow analysis.
- Bind cache entries to the complete browser identity, scanner identity and
  protocol version. Authenticate and validate cached plans before reuse.
- Validate instruction bytes, addresses, branch targets and loaded executable
  code, accounting for the platform's loader relocations.
- Patch in the main browser process at a validated startup point outside the
  loader lock. Child processes must retain normal forwarding/loading behavior.
- Apply edits transactionally: execute/read → read/write → edit and verify →
  flush instruction cache → restore protections. Roll back every failed edit.
  Failed rollback or protection restoration must stop the browser.
- Chrome's unrecognized optional install checks are skipped; recognized Edge
  installer support requires both of its installer decisions.

The deployed Windows code has no runtime table download or analysis dependency.
Keep the browser's on-disk binaries unchanged. See the Windows README for cache,
startup, installation and removal details.

## Future Linux and macOS ports

Follow the Windows architecture: native automatic discovery from the installed
image, a validated cache, loaded-code verification and transactional in-memory
patching. Share source semantics and reusable decoding/proof logic where practical.
Keep container parsing, function bounds, loader startup, relocations, memory
protection, cache protection and installation in their platform owners.

Do not bring back per-version signature maintenance or ship the Python research
scanner as the runtime. ELF virtual addresses differ from file offsets; loaded
addresses need the image's load bias. Mach-O addresses are slice-specific and need
the dyld slide. macOS installation must account for code signing and entitlements;
the retained load-command editor is a scratch-copy experiment, not an installer.

Each port needs native validation with a real MV2 extension, MV3 control,
enable/disable, restart, browser update, cache invalidation and removal. Fixture
parsing, WSL/Wine launches and successful byte matching do not establish native
macOS, Linux ARM64 or Windows ARM64 runtime behavior.

## Verification

```text
python scripts/run_tests.py
uv run --with capstone --with z3-solver scripts/run_tests.py
```

The first command runs the portable fixtures and the Windows installer suite on
Windows; Python scanner checks skip if their optional dependencies are absent.
The second includes those research checks. `--fast` skips the Windows installer
integration suite. Native scanner, proxy, application and cache tests remain in
CMake; after building the test targets, run `ctest --preset <arch>` in
`mv2-mem-patch-win/`. Native ARM64 execution needs ARM64 Windows.

Use `mv2-scan.exe` and `scripts/check_autoscan_matrix.py` for read-only discovery
checks against independently reviewed, hash-bound address baselines. Use
`scripts/test_autoscan_runtime.py` only with isolated browser copies and its
private registry subtree. Never derive a baseline from the scanner under test or
modify a live browser installation during research.
