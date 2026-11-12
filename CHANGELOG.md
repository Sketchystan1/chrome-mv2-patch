# Changelog

## Unreleased

- Remove the optional MV3 `webRequestBlocking` permission patches from all tables.
- Add experimental Windows x64 MV2 discovery without a signature table or debug symbols.
- Speed up the Windows auto-patcher with native SIMD searches, parallel BLAKE3 identity checks, relocation filtering and a persistent protected plan cache. Raise the DLL/scanner size limit to 300,000 bytes.
- Balance hashing across an adaptive CPU budget, defer completed scan-view cleanup and reuse exact function trimming results; preserve full identity and loaded-code checks.
- Batch decision-page protection checks, use dynamic hash TLS to skip DLL thread notifications, and screen discovery candidates before function trimming.

## [1.16.0] - 2026-11-07

- Chrome 159 support.
- New instruction forms require an updated patcher.

## [1.15.0] - 2026-10-23

- Chrome 158 support.
- Fix Windows 157 x86.

## [1.14.0] - 2026-10-05

- Chrome 157 support.

## [1.13.0] - 2026-09-16

- Chrome 156 support.

## [1.12.0] - 2026-09-11

- chrome-mv2.ps1 switch from byte-patching to version.dll.

## [1.11.1] - 2026-09-11

- Fix 154.

## [1.11.0] - 2026-09-11

- Enable webRequestBlocking MV3.
- Drop Chromium support.

## [1.10.1] - 2026-09-09

- Fix macOS signatures.
- Fix Windows 154 signatures.

## [1.10.0] - 2026-09-07

- Drop 151 support, macos-x64.
- New ARM cbz based patch.

## [1.8.0] - 2026-09-05

- Enable webRequestBlocking MV3.
- Enable ExtensionSettings policy.

## [1.7.0] - 2026-09-02

- Chrome 155 support.
- Bug fixes.
- Python scripts updated.

## [1.6.1] - 2026-08-29

- New menu UI.

## [1.6.0] - 2026-08-23

- Chrome 154 support.

## [1.5.1] - 2026-08-21

- Windows script bug fixes.

## [1.5.0] - 2026-08-15

- Chromium support.

## [1.4.0] - 2026-08-14

- Linux ARM (arm64) support.

## [1.3.0] - 2026-08-13

- macOS x64, ARM support.
- Windows ARM support.

## [1.2.0] - 2026-08-12

- Linux support.
- Windows x86 support.
- Migrated from a binary to scripts.

## [1.1.0] - 2026-08-09

- Chrome 152 support.
- Windows x64 support.

## [1.0.0] - 2026-08-07

- First public release. 
- Windows x64 support.
- Chrome 151 support.
