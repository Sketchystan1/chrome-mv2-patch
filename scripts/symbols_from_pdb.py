"""Resolve MV2-related function names in a matching Chrome PDB via dbghelp.

Optional, Windows-only research aid for source/disassembly review. The native
auto patcher does not use symbols. Inlined checks are named by their enclosing
functions; names alone do not identify a patchable decision.

    python scripts/symbols_from_pdb.py path/to/chrome.dll --symdir _scratch --json _scratch/syms.json

Fetch matching symbols with scripts/fetch_symbols.py. Large PDBs can take
minutes to load; dbghelp ships with Windows."""

import argparse
import ctypes as C
import json
import struct
import sys
from ctypes import wintypes
from pathlib import Path

# Gate function name masks — version-independent (the C++ source names). The
# inlined copies (UserMayInstall / MustRemainDisabled) are named by their
# enclosing function; review its instructions to locate the decision.
GATE_MASKS = [
    "*IsExtensionAffected*",
    "*ShouldBlockExtensionInstallation*",
    "*ShouldBlockExtensionEnable*",
    "*OnExtensionSystemReady*",
    "*MaybeReEnableExtension*",
    "*UserMayInstall*",
    "*MustRemainDisabled*",
]


def pe_text_and_base(path):
    """(image_base, text_rva, text_size) from the PE headers (PE32 or PE32+)."""
    data = Path(path).read_bytes()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("not a PE")
    size_opt = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:      # PE32+: ImageBase is a 64-bit field at opt+24
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    elif magic == 0x10B:    # PE32:  ImageBase is a 32-bit field at opt+28
        image_base = struct.unpack_from("<I", data, opt + 28)[0]
    else:
        raise ValueError("unsupported PE optional header magic 0x%X" % magic)
    sec_off = opt + size_opt
    for i in range(num_sections):
        b = sec_off + i * 40
        name = data[b:b + 8].split(b"\x00")[0].decode("latin1")
        if name == ".text":
            v_size, v_addr = struct.unpack_from("<II", data, b + 8)[:2]
            return image_base, v_addr, v_size
    raise ValueError("no .text")


MAX_SYM_NAME = 2000


class SYMBOL_INFOW(C.Structure):
    _fields_ = [
        ("SizeOfStruct", wintypes.ULONG), ("TypeIndex", wintypes.ULONG),
        ("Reserved", C.c_ulonglong * 2), ("Index", wintypes.ULONG),
        ("Size", wintypes.ULONG), ("ModBase", C.c_ulonglong),
        ("Flags", wintypes.ULONG), ("Value", C.c_ulonglong),
        ("Address", C.c_ulonglong), ("Register", wintypes.ULONG),
        ("Scope", wintypes.ULONG), ("Tag", wintypes.ULONG),
        ("NameLen", wintypes.ULONG), ("MaxNameLen", wintypes.ULONG),
        ("Name", wintypes.WCHAR * (MAX_SYM_NAME + 1)),
    ]


def resolve(dll, symdir):
    if sys.platform != "win32":
        raise SystemExit("symbols_from_pdb.py is Windows-only (dbghelp). "
                         "On Linux use `nm chrome.debug` — see the script header.")

    image_base, text_rva, text_size = pe_text_and_base(dll)
    data_len = Path(dll).stat().st_size

    dbghelp = C.WinDLL("dbghelp.dll")
    kernel32 = C.WinDLL("kernel32.dll")
    dbghelp.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
    dbghelp.SymInitializeW.restype = wintypes.BOOL
    dbghelp.SymLoadModuleExW.argtypes = [
        wintypes.HANDLE, wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR,
        C.c_ulonglong, wintypes.DWORD, C.c_void_p, wintypes.DWORD]
    dbghelp.SymLoadModuleExW.restype = C.c_ulonglong
    SYMENUM = C.WINFUNCTYPE(wintypes.BOOL, C.POINTER(SYMBOL_INFOW), wintypes.ULONG, C.c_void_p)
    dbghelp.SymEnumSymbolsW.argtypes = [
        wintypes.HANDLE, C.c_ulonglong, wintypes.LPCWSTR, SYMENUM, C.c_void_p]
    dbghelp.SymEnumSymbolsW.restype = wintypes.BOOL

    SYMOPT_UNDNAME, SYMOPT_DEBUG = 0x2, 0x80000000
    SYMOPT_FAIL_CRITICAL, SYMOPT_NO_PROMPTS = 0x200, 0x80000
    hproc = kernel32.GetCurrentProcess()
    dbghelp.SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEBUG | SYMOPT_FAIL_CRITICAL | SYMOPT_NO_PROMPTS)
    if not dbghelp.SymInitializeW(hproc, symdir, False):
        raise OSError("SymInitializeW failed", C.get_last_error())

    print("[*] Loading module + PDB (first parse of the multi-GB PDB is slow)...", flush=True)
    base = dbghelp.SymLoadModuleExW(hproc, None, dll, None, image_base, data_len, None, 0)
    if base == 0 and C.get_last_error() != 0:
        raise OSError(f"SymLoadModuleExW failed, err={C.get_last_error()}")

    def enum(mask):
        out = []

        @SYMENUM
        def cb(pinfo, size, ctx):
            s = pinfo.contents
            out.append((s.Name, s.Address - image_base, s.Size))
            return True

        dbghelp.SymEnumSymbolsW(hproc, image_base, mask, cb, None)
        return out

    resolved = {}
    for mask in GATE_MASKS:
        syms = [s for s in enum(mask)
                if s[2] > 0 and text_rva <= s[1] < text_rva + text_size]
        label = mask.strip("*")
        resolved[label] = syms
        print(f"=== {label}: {len(syms)} symbol(s) in .text ===")
        for name, rva, size in syms:
            print(f"    rva={rva:#010x} size={size:#x}  {name}")
    return resolved


def main():
    ap = argparse.ArgumentParser(description="Resolve MV2 gate symbols from a Chrome PDB (Windows).")
    ap.add_argument("dll", help="path to chrome.dll (its matching PDB must be in --symdir)")
    ap.add_argument("--symdir", help="directory holding chrome.dll.pdb (default: the DLL's dir)")
    ap.add_argument("--json", help="also write the resolved symbols to this JSON file")
    args = ap.parse_args()

    symdir = args.symdir or str(Path(args.dll).resolve().parent)
    resolved = resolve(str(Path(args.dll).resolve()), symdir)
    if args.json:
        Path(args.json).write_text(json.dumps(resolved, indent=2), encoding="utf-8")
        print(f"\n[+] Wrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
