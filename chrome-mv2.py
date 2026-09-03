#!/usr/bin/env python3
# ============================================================================
# Google Chrome / Chromium Manifest V2 Patcher - one universal Python port.
#
# A single self-contained script that replaces both chrome-mv2.ps1 (Windows PE)
# and chrome-mv2.sh (Linux ELF + macOS Mach-O). It runs anywhere a bundled
# Python 3 does, using ONLY the standard library:
#   - struct / hashlib / json / array  -> the binary engine
#   - ctypes                           -> Windows APIs (elevation, Restart
#                                         Manager, window close, shortcut reopen)
#   - subprocess / os / signal / glob  -> Linux (/proc) and macOS (codesign,
#                                         osascript, open) platform glue
#
# It re-enables Manifest V2 extension support by flipping the inlined
# IsExtensionAffected manifest-version checks, dispatching on the target's
# container (detected from the file magic, NOT the host OS):
#
#   PE   (Windows chrome.dll):  x64 "pe", x86 "pe32", arm64 "pe-arm64".
#   ELF  (Linux chrome):        x86_64 "elf", aarch64 "elf-arm64".
#   MachO(macOS framework):     universal; only the slice for THIS Mac is patched.
#
#   JG_SHORT  0x7F disp8       -> 0xEB disp8        (jmp short, same disp8)
#   JG_NEAR   0x0F 0x8F disp32 -> 0x90 0xE9 disp32  (nop ; jmp near, same disp32)
#   BCOND     arm64 b.gt (GT 0xC) -> b.al (AL 0xE), imm19 preserved (one nibble)
#
# CARDINAL RULE: never delete or blank a call and never invent control flow -
# only flip the direction of an existing branch to its EXISTING target. A site
# counts as located only when its signature matches EXACTLY expectedMatches
# times; the milestone with the most located sites wins; ties/partials decline.
#
# The Windows signature tables and the Linux/macOS ones both live in the
# embedded JSON below (verbatim signatures.json), so the script needs no other
# file. A signatures.json next to the script overrides it; --signatures picks
# another explicitly.
#
# Usage:
#   Windows: python chrome-mv2.py [patch|restore|check] [path] [-y] [-q]
#   Linux:   sudo python3 chrome-mv2.py [patch|restore|check] [path] [-y] [-q]
#   macOS:   python3 chrome-mv2.py [patch|restore|check] [path] [-y] [-q]
# ============================================================================
import array
import glob
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time

APP_VERSION = "1.7.0"
SIGNATURES_FILE = "signatures.json"

IS_WIN = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

# Embedded signature tables (verbatim signatures.json). An external
# signatures.json beside the script overrides this; --signatures wins over both.
EMBEDDED_SIGNATURES = r'''{"milestones":[
{"name":"151","container":"pe","sites":[{"name":"IsExtensionAffected","kind":"short","jgRVA":"0x083012E4","jgOff":4,"expectedMatches":1,"sig":"837A50027F34488B8A280200008B413080BA08020000007508"},{"name":"ShouldBlockExtensionInstallation","kind":"short","jgRVA":"0x08301323","jgOff":3,"expectedMatches":1,"sig":"83FA027F234183F80175114183F9050F95C14183F90A"},{"name":"ShouldBlockExtensionEnable","kind":"short","jgRVA":"0x03291F6B","jgOff":7,"expectedMatches":1,"sig":"8B41684183F8027F288B493083F801751683F9050F95C2"},{"name":"OnExtensionSystemReady startup loop","kind":"short","jgRVA":"0x01618C4C","jgOff":4,"expectedMatches":1,"sig":"837950027F2D488B91280200008B423080B90802000000750C"},{"name":"MaybeReEnableExtension","kind":"short","jgRVA":"0x08301436","jgOff":4,"expectedMatches":1,"sig":"837E50027F2D488B8E280200008B413080BE08020000007508"},{"name":"UserMayInstall (inlined)","kind":"short","jgRVA":"0x08E736BA","jgOff":6,"expectedMatches":1,"sig":"8B416883FA027F3B8B493083F8010F851A01000083F905742A"},{"name":"MustRemainDisabled (inlined)","kind":"short","jgRVA":"0x016448AA","jgOff":6,"expectedMatches":1,"sig":"8B416883FA027F788B493083F801756631FF83F905740583F9"}]},
{"name":"152","container":"pe","sites":[{"name":"manifest_v2_util::IsExtensionAffected (free predicate; covers install thunk)","kind":"short","jgRVA":"0x082D26F5","jgOff":3,"expectedMatches":1,"sig":"83F9027F1F83FA08771AB90A0100000FA3D173104183F805"},{"name":"ShouldBlockExtensionEnable / IsExtensionAffected (shared body)","kind":"short","jgRVA":"0x03348754","jgOff":4,"expectedMatches":2,"sig":"837A50027F34488B8A280200008B413080BA080200000075"},{"name":"OnExtensionSystemReady startup loop","kind":"short","jgRVA":"0x0124109C","jgOff":4,"expectedMatches":1,"sig":"837950027F2D488B91280200008B423080B90802000000750C"},{"name":"MaybeReEnableExtension","kind":"short","jgRVA":"0x082D24D6","jgOff":4,"expectedMatches":1,"sig":"837E50027F2D488B8E280200008B413080BE08020000007508"},{"name":"UserMayInstall (inlined)","kind":"short","jgRVA":"0x08DDC241","jgOff":4,"expectedMatches":1,"sig":"837F50027F4E488B8F280200008B413080BF0802000000750C"},{"name":"MustRemainDisabled (inlined, near jg)","kind":"near","jgRVA":"0x015A8D31","jgOff":4,"expectedMatches":1,"sig":"837F50020F8F8B000000488B8F280200008B413080BF080200000075"}]},
{"name":"151-x86","container":"pe32","sites":[{"name":"OnExtensionSystemReady startup loop","kind":"short","jgRVA":"0x00B20DB9","jgOff":4,"expectedMatches":1,"sig":"837928027F2C8B91640100008B421880B95401000000750C8B"},{"name":"MustRemainDisabled (inlined)","kind":"short","jgRVA":"0x0111E3EC","jgOff":3,"expectedMatches":1,"sig":"83FA027F728B491883F801756031DB83F905740583F90A752B"},{"name":"ShouldBlockExtensionEnable","kind":"short","jgRVA":"0x029E11BE","jgOff":3,"expectedMatches":1,"sig":"83FA027F2B8B491883F801751983F9050F95C283F90A0F95C0"},{"name":"IsExtensionAffected","kind":"short","jgRVA":"0x07022F9A","jgOff":4,"expectedMatches":1,"sig":"837A28027F368B8A640100008B411880BA540100000075088B"},{"name":"ShouldBlockExtensionInstallation","kind":"short","jgRVA":"0x07022FE7","jgOff":4,"expectedMatches":1,"sig":"837D08027F278B450C83F80175158B451083F8050F95C183F8"},{"name":"MaybeReEnableExtension","kind":"short","jgRVA":"0x0702310D","jgOff":4,"expectedMatches":1,"sig":"837E28027F248B8E640100008B411880BE540100000075088B"},{"name":"UserMayInstall (inlined)","kind":"short","jgRVA":"0x079D46E7","jgOff":3,"expectedMatches":1,"sig":"83FA027F338B491883F8010F85FD00000083F905742283F90A"}]},
{"name":"151-linux","container":"elf","sites":[{"name":"MV2DeprecationImpactChecker::IsExtensionAffected (shared predicate; covers the ManifestV2Handler thunk, OnExtensionSystemReady and MaybeReEnableExtension, which call it out-of-line)","kind":"short","jgRVA":"0x041900D4","jgOff":4,"expectedMatches":1,"sig":"837E50027F2F554889E5488B8E280200008B413080BE080200"},{"name":"ManifestV2Handler::ShouldBlockExtensionInstallation","kind":"short","jgRVA":"0x09972677","jgOff":3,"expectedMatches":1,"sig":"83FE027F1F83FA01751083F9050F95C283F90A0F95C020D05D"},{"name":"ManifestV2Handler::ShouldBlockExtensionEnable","kind":"short","jgRVA":"0x099726BD","jgOff":3,"expectedMatches":1,"sig":"83FA027F298B493083F801751783F9050F95C283F90A0F95C0"},{"name":"StandardManagementPolicyProvider::UserMayInstall (inlined, near jg; Load-Unpacked gate)","kind":"near","jgRVA":"0x0A3B7893","jgOff":3,"expectedMatches":1,"sig":"83FA020F8FBE0000008B493083F8010F856402000083F9050F84A900"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled (inlined)","kind":"short","jgRVA":"0x05572994","jgOff":3,"expectedMatches":1,"sig":"83FA027F7A8B493083F80175684531F683F905740583F90A75"}]},
{"name":"152-linux","container":"elf","sites":[{"name":"manifest_v2_util::IsExtensionAffected (free predicate; covers the ShouldBlockExtensionInstallation thunk, which tail-jumps here)","kind":"short","jgRVA":"0x0985B449","jgOff":3,"expectedMatches":1,"sig":"83FF027F1D83FE087718B90A0100000FA3F1730E83FA050F95"},{"name":"ManifestV2Handler::IsExtensionAffected / ShouldBlockExtensionEnable (shared body; also covers OnExtensionSystemReady and MaybeReEnableExtension's calls out to it)","kind":"short","jgRVA":"0x0985B0F4","jgOff":4,"expectedMatches":1,"sig":"837E50027F2F554889E5488B8E280200008B413080BE080200"},{"name":"ManifestV2Handler::MaybeReEnableExtension (inlined)","kind":"short","jgRVA":"0x0985B238","jgOff":4,"expectedMatches":1,"sig":"837B50027F30488B8B280200008B413080BB08020000007508"},{"name":"StandardManagementPolicyProvider::UserMayInstall (inlined, near jg; Load-Unpacked gate)","kind":"near","jgRVA":"0x0A256BAA","jgOff":4,"expectedMatches":1,"sig":"837B50020F8FD1000000488B8B280200008B413080BB080200000075"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled (inlined, near jg)","kind":"near","jgRVA":"0x0599A69A","jgOff":4,"expectedMatches":1,"sig":"837E50020F8F8E000000498B8E280200008B41304180BE0802000000"}]},
{"name":"151-linux-arm64","container":"elf-arm64","sites":[{"name":"ManifestV2Handler::ShouldBlockExtensionInstallation","kind":"bcond","jgRVA":"0x05E6C0CC","jgOff":4,"expectedMatches":1,"sig":"3F0800716C0100545F040071A10000547F14007164184A7AE0079F1AC0035FD6"},{"name":"StandardManagementPolicyProvider::UserMayInstall (inlined)","kind":"bcond","jgRVA":"0x06086804","jgOff":4,"expectedMatches":1,"sig":"5F0900710C010054293140B91F050071611300543F150071600000543F290071"},{"name":"StandardManagementPolicyProvider::UserMayInstall (inlined, 2nd call site)","kind":"bcond","jgRVA":"0x06A71584","jgOff":4,"expectedMatches":1,"sig":"5F0900710C010054293140B91F050071A11300543F150071600000543F290071"},{"name":"MV2DeprecationImpactChecker::IsExtensionAffected (shared predicate; OnExtensionSystemReady / MaybeReEnableExtension / ShouldBlockExtensionEnable call it out-of-line)","kind":"bcond","jgRVA":"0x0A525764","jgOff":4,"expectedMatches":1,"sig":"1F0900710C020054291441F92A204839283140B98A000037296940B93F050071"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled (inlined)","kind":"bcond","jgRVA":"0x0A69570C","jgOff":4,"expectedMatches":1,"sig":"5F090071EC030054293140B91F050071010300543F150071F4031F2A60000054"}]},
{"name":"152-linux-arm64","container":"elf-arm64","sites":[{"name":"ManifestV2Handler::MaybeReEnableExtension (shared body)","kind":"bcond","jgRVA":"0x05D64DD8","jgOff":4,"expectedMatches":2,"sig":"1F0900712C020054691641F96A224839283140B98A000037296940B93F050071"},{"name":"ManifestV2Handler::IsExtensionAffected / ShouldBlockExtensionEnable (shared body)","kind":"bcond","jgRVA":"0x05D64F9C","jgOff":4,"expectedMatches":1,"sig":"1F0900710C020054091441F90A204839283140B98A000037296940B93F050071"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled / UserMayInstall (shared body)","kind":"bcond","jgRVA":"0x05F78874","jgOff":4,"expectedMatches":2,"sig":"1F0900718C010054891641F98A224839283140B98A000037296940B93F050071"},{"name":"ManifestV2Handler::OnExtensionSystemReady (shared body)","kind":"bcond","jgRVA":"0x0696E3C8","jgOff":4,"expectedMatches":2,"sig":"3F090071EC4A0054091541F90A214839283140B98A000037296940B93F050071"}]},
{"name":"152-x86","container":"pe32","sites":[{"name":"manifest_v2_util::IsExtensionAffected (free predicate; covers install thunk)","kind":"short","jgRVA":"0x06FB7547","jgOff":4,"expectedMatches":1,"sig":"837D08027F278B4D0C31C083F908771FBA0A0100000FA3CA73"},{"name":"ShouldBlockExtensionEnable / IsExtensionAffected (shared body)","kind":"short","jgRVA":"0x0299ED6A","jgOff":4,"expectedMatches":2,"sig":"837A28027F368B8A640100008B411880BA540100000075088B"},{"name":"OnExtensionSystemReady startup loop","kind":"short","jgRVA":"0x00A580A6","jgOff":4,"expectedMatches":1,"sig":"837928027F2C8B91640100008B421880B95401000000750C8B"},{"name":"MaybeReEnableExtension","kind":"short","jgRVA":"0x06FB736D","jgOff":4,"expectedMatches":1,"sig":"837E28027F248B8E640100008B411880BE540100000075088B"},{"name":"UserMayInstall (inlined)","kind":"short","jgRVA":"0x0791012F","jgOff":4,"expectedMatches":1,"sig":"837F28027F458B8F640100008B411880BF5401000000750C8B"},{"name":"MustRemainDisabled (inlined, near jg)","kind":"near","jgRVA":"0x010851A8","jgOff":4,"expectedMatches":1,"sig":"837B28020F8F840000008B8B640100008B411880BB54010000007508"}]},
{"name":"151-macos-x64","container":"macho-x64","sites":[{"name":"StandardManagementPolicyProvider::MustRemainDisabled","kind":"short","jgRVA":"0x01B652F7","jgOff":3,"expectedMatches":1,"sig":"83FA027F5B8B493083F80175494531F683F905740583F90A75"},{"name":"ManifestV2Handler::OnExtensionSystemReady","kind":"short","jgRVA":"0x030822AA","jgOff":4,"expectedMatches":1,"sig":"837950027F2D488B91280200008B423080B90802000000750C"},{"name":"ManifestV2Handler::ShouldBlockExtensionEnable","kind":"short","jgRVA":"0x04727A9D","jgOff":3,"expectedMatches":1,"sig":"83FA027F298B493083F801751783F9050F95C283F90A0F95C0"},{"name":"ManifestV2Handler::IsExtensionAffected","kind":"short","jgRVA":"0x071364A4","jgOff":4,"expectedMatches":1,"sig":"837E50027F2F554889E5488B8E280200008B413080BE080200"},{"name":"ManifestV2Handler::ShouldBlockExtensionInstallation","kind":"short","jgRVA":"0x071364F7","jgOff":3,"expectedMatches":1,"sig":"83FE027F1F83FA01751083F9050F95C283F90A0F95C020D05D"},{"name":"ManifestV2Handler::MaybeReEnableExtension","kind":"short","jgRVA":"0x07136608","jgOff":4,"expectedMatches":1,"sig":"837B50027F30488B8B280200008B413080BB08020000007508"},{"name":"StandardManagementPolicyProvider::UserMayInstall","kind":"near","jgRVA":"0x07B4CFF9","jgOff":3,"expectedMatches":1,"sig":"83FA020F8FA40000008B493083F8010F850F02000083F9050F848F00"}]},
{"name":"151-macos-arm64","container":"macho-arm64","sites":[{"name":"ManifestV2Handler::OnExtensionSystemReady","kind":"bcond","jgRVA":"0x0178A5E8","jgOff":4,"expectedMatches":1,"sig":"1F090071AC0100542A1541F9483140B929214839C9000037496940B93F050071"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled","kind":"bcond","jgRVA":"0x021EFD80","jgOff":4,"expectedMatches":1,"sig":"5F0900716C040054293140B91F05007181030054140080523F15007160000054"},{"name":"ManifestV2Handler::ShouldBlockExtensionEnable","kind":"bcond","jgRVA":"0x03ED7910","jgOff":4,"expectedMatches":1,"sig":"5F090071CC010054293140B91F050071E10000543F15007124194A7AE0079F1A"},{"name":"ManifestV2Handler::IsExtensionAffected","kind":"bcond","jgRVA":"0x0642852C","jgOff":4,"expectedMatches":1,"sig":"1F090071CC010054291441F9283140B92A204839CA000037296940B93F050071"},{"name":"ManifestV2Handler::ShouldBlockExtensionInstallation","kind":"bcond","jgRVA":"0x06428570","jgOff":4,"expectedMatches":1,"sig":"3F0800716C0100545F040071A10000547F14007164184A7AE0079F1AC0035FD6"},{"name":"ManifestV2Handler::MaybeReEnableExtension","kind":"bcond","jgRVA":"0x064286A8","jgOff":4,"expectedMatches":1,"sig":"1F090071AC010054691641F9283140B96A224839CA000037296940B93F050071"},{"name":"StandardManagementPolicyProvider::UserMayInstall","kind":"bcond","jgRVA":"0x06DB8584","jgOff":4,"expectedMatches":1,"sig":"5F090071EC000054293140B91F050071210F00543F15007124194A7AC1060054"}]},
{"name":"151-win-arm64","container":"pe-arm64","sites":[{"name":"ManifestV2Handler::OnExtensionSystemReady","kind":"bcond","jgRVA":"0x01058388","jgOff":4,"expectedMatches":1,"sig":"3F0900718C010054091541F90A214839283140B98A000037296940B93F050071"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled","kind":"bcond","jgRVA":"0x0125352C","jgOff":4,"expectedMatches":1,"sig":"5F0900716C050054293140B91F050071810400543F150071F4031F2A60000054"},{"name":"ManifestV2Handler::ShouldBlockExtensionEnable","kind":"bcond","jgRVA":"0x02C0729C","jgOff":4,"expectedMatches":1,"sig":"5F090071CC010054293140B91F050071E10000543F15007124194A7AE0079F1A"},{"name":"MV2DeprecationImpactChecker::IsExtensionAffected","kind":"bcond","jgRVA":"0x02C07334","jgOff":4,"expectedMatches":1,"sig":"1F0900710C020054291441F92A204839283140B98A000037296940B93F050071"},{"name":"ManifestV2Handler::ShouldBlockExtensionInstallation","kind":"bcond","jgRVA":"0x07836B6C","jgOff":4,"expectedMatches":1,"sig":"3F0800716C0100545F040071A10000547F14007164184A7AE0079F1AC0035FD6"},{"name":"ManifestV2Handler::MaybeReEnableExtension","kind":"bcond","jgRVA":"0x07836C94","jgOff":4,"expectedMatches":1,"sig":"1F0900710C020054691641F96A224839283140B98A000037296940B93F050071"},{"name":"StandardManagementPolicyProvider::UserMayInstall","kind":"bcond","jgRVA":"0x082F94F8","jgOff":4,"expectedMatches":1,"sig":"5F090071EC010054293140B91F050071610700543F150071400100543F290071"}]},
{"name":"152-macos-x64","container":"macho-x64","sites":[{"name":"StandardManagementPolicyProvider::MustRemainDisabled","kind":"short","jgRVA":"0x01BA0A91","jgOff":4,"expectedMatches":1,"sig":"837E50027F6F498B8E280200008B41304180BE080200000075"},{"name":"ManifestV2Handler::OnExtensionSystemReady","kind":"short","jgRVA":"0x0312B1FA","jgOff":4,"expectedMatches":1,"sig":"837950027F2D488B91280200008B423080B90802000000750C"},{"name":"ManifestV2Handler::IsExtensionAffected","kind":"short","jgRVA":"0x048BB6E4","jgOff":4,"expectedMatches":1,"sig":"837E50027F2F554889E5488B8E280200008B413080BE080200"},{"name":"ManifestV2Handler::ShouldBlockExtensionInstallation","kind":"short","jgRVA":"0x075489B8","jgOff":4,"expectedMatches":1,"sig":"837B50027F30488B8B280200008B413080BB08020000007508"},{"name":"ManifestV2Handler::ShouldBlockExtensionInstallation (2)","kind":"short","jgRVA":"0x07548BB9","jgOff":3,"expectedMatches":1,"sig":"83FF027F1D83FE087718B90A0100000FA3F1730E83FA050F95"},{"name":"StandardManagementPolicyProvider::UserMayInstall","kind":"near","jgRVA":"0x07F56A10","jgOff":4,"expectedMatches":1,"sig":"837B50020F8FB7000000488B8B280200008B413080BB080200000075"}]},
{"name":"152-macos-arm64","container":"macho-arm64","sites":[{"name":"StandardManagementPolicyProvider::MustRemainDisabled","kind":"bcond","jgRVA":"0x02218740","jgOff":4,"expectedMatches":1,"sig":"1F090071EC040054891641F9283140B98A2248398A000037296940B93F050071"},{"name":"ManifestV2Handler::OnExtensionSystemReady","kind":"bcond","jgRVA":"0x0320635C","jgOff":4,"expectedMatches":1,"sig":"1F090071AC0100542A1541F9483140B929214839C9000037496940B93F050071"},{"name":"ManifestV2Handler::IsExtensionAffected","kind":"bcond","jgRVA":"0x03FFBD84","jgOff":4,"expectedMatches":1,"sig":"1F090071CC010054291441F9283140B92A204839CA000037296940B93F050071"},{"name":"ManifestV2Handler::ShouldBlockExtensionInstallation / StandardManagementPolicyProvider::UserMayInstall (shared body)","kind":"bcond","jgRVA":"0x066F0E38","jgOff":4,"expectedMatches":2,"sig":"1F090071AC010054691641F9283140B96A224839CA000037296940B93F050071"},{"name":"IsExtensionAffected (type!=PLATFORM_APP variant)","kind":"bcond","jgRVA":"0x026AC410","jgOff":8,"expectedMatches":1,"sig":"C85240B91F0900718C010054C8224839"}]},
{"name":"152-win-arm64","container":"pe-arm64","sites":[{"name":"ManifestV2Handler::OnExtensionSystemReady","kind":"bcond","jgRVA":"0x01014CBC","jgOff":4,"expectedMatches":1,"sig":"3F0900718C010054091541F90A214839283140B98A000037296940B93F050071"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled / StandardManagementPolicyProvider::UserMayInstall (shared body)","kind":"bcond","jgRVA":"0x013591BC","jgOff":4,"expectedMatches":2,"sig":"1F090071EC050054891641F98A224839283140B98A000037296940B93F050071"},{"name":"ManifestV2Handler::ShouldBlockExtensionEnable / ManifestV2Handler::IsExtensionAffected (shared body)","kind":"bcond","jgRVA":"0x02C1FD9C","jgOff":4,"expectedMatches":2,"sig":"1F0900710C020054291441F92A204839283140B98A000037296940B93F050071"},{"name":"ManifestV2Handler::MaybeReEnableExtension","kind":"bcond","jgRVA":"0x07702AEC","jgOff":4,"expectedMatches":1,"sig":"1F0900710C020054691641F96A224839283140B98A000037296940B93F050071"},{"name":"IsExtensionAffected (type!=PLATFORM_APP variant)","kind":"bcond","jgRVA":"0x017E3410","jgOff":8,"expectedMatches":1,"sig":"C85240B91F0900718C010054C8224839"}]},
{"name":"152-chromium-linux","container":"elf","sites":[{"name":"manifest_v2_util::IsExtensionAffected (free predicate)","kind":"short","jgRVA":"0x0923C9D9","jgOff":3,"expectedMatches":1,"sig":"83FF027F1D83FE087718B90A0100000FA3F1730E83FA050F95"}]},
{"name":"152-chromium","container":"pe","sites":[{"name":"manifest_v2_util::IsExtensionAffected (free predicate)","kind":"short","jgRVA":"0x04723915","jgOff":3,"expectedMatches":1,"sig":"83F9027F1F83FA08771AB90A0100000FA3D173104183F8050F"}]},
{"name":"152-chromium-macos-x64","container":"macho-x64","sites":[{"name":"manifest_v2_util::IsExtensionAffected (free predicate)","kind":"short","jgRVA":"0x04814269","jgOff":3,"expectedMatches":1,"sig":"83FF027F1D83FE087718B90A0100000FA3F1730E83FA050F95"}]},
{"name":"151-chromium-linux","container":"elf","sites":[{"name":"manifest_v2_util::IsExtensionAffected (free predicate)","kind":"short","jgRVA":"0x09350E79","jgOff":3,"expectedMatches":1,"sig":"83FE027F1D83FA087718BE0A0100000FA3D6730E83F9050F95"}]},
{"name":"151-chromium-linux-xtradeb","container":"elf","sites":[{"name":"ManifestV2Handler::OnExtensionSystemReady","kind":"near","jgRVA":"0x07A64A55","jgOff":4,"expectedMatches":1,"sig":"837850020F8FD5000000488B90280200008B4A3080B8080200000075"},{"name":"ManifestV2Handler::MaybeReEnableExtension","kind":"short","jgRVA":"0x07A65559","jgOff":4,"expectedMatches":1,"sig":"837B50027F2F488B8B280200008B413080BB08020000007512"},{"name":"ManagementSetEnabledFunction::CheckManifestV2Deprecation (inlined predicate)","kind":"short","jgRVA":"0x07DAC2A3","jgOff":3,"expectedMatches":1,"sig":"83FA027F2083F908771BBA0A0100000FA3CA73118B403083F8"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled (inlined predicate)","kind":"short","jgRVA":"0x08C5DADA","jgOff":3,"expectedMatches":1,"sig":"83FA027F4683F9087741BA0A0100000FA3CA73378B40304531"}]},
{"name":"154","container":"pe","sites":[{"name":"manifest_v2_util::IsExtensionAffected (free predicate; covers install thunk)","kind":"short","jgRVA":"0x08E81945","jgOff":3,"expectedMatches":1,"sig":"83F9027F1F83FA08771AB90A0100000FA3D173104183F805"},{"name":"ShouldBlockExtensionEnable / IsExtensionAffected (shared body)","kind":"short","jgRVA":"0x036B5704","jgOff":4,"expectedMatches":1,"sig":"837A50027F34488B8A280200008B413080BA080200000075"},{"name":"OnExtensionSystemReady startup loop","kind":"short","jgRVA":"0x028891C3","jgOff":4,"expectedMatches":1,"sig":"837950027F2D488B91280200008B423080B90802000000750C"},{"name":"MaybeReEnableExtension","kind":"short","jgRVA":"0x08E81726","jgOff":4,"expectedMatches":1,"sig":"837E50027F2D488B8E280200008B413080BE08020000007508"},{"name":"UserMayInstall (inlined)","kind":"short","jgRVA":"0x0994F021","jgOff":4,"expectedMatches":1,"sig":"837F50027F4E488B8F280200008B413080BF0802000000750C"},{"name":"MustRemainDisabled (inlined, near jg)","kind":"near","jgRVA":"0x01663F71","jgOff":4,"expectedMatches":1,"sig":"837F50020F8F8B000000488B8F280200008B413080BF080200000075"},{"name":"ShouldBlockExtensionEnable / IsExtensionAffected (shared body, 2nd copy, diverged reg)","kind":"short","jgRVA":"0x036B5784","jgOff":4,"expectedMatches":1,"sig":"837950027F34488B91280200008B423080B908020000007508"},{"name":"IsExtensionAffected (type!=PLATFORM_APP variant; +0x208 flag then +0x228 manifest)","kind":"short","jgRVA":"0x01C21E3F","jgOff":4,"expectedMatches":1,"sig":"837F50027F2C80BF08020000000F857E010000488B87280200"}]},
{"name":"154-x86","container":"pe32","sites":[{"name":"manifest_v2_util::IsExtensionAffected (free predicate; covers install thunk)","kind":"short","jgRVA":"0x08BBA217","jgOff":4,"expectedMatches":1,"sig":"837D08027F278B4D0C31C083F908771FBA0A0100000FA3CA73"},{"name":"ShouldBlockExtensionEnable / IsExtensionAffected (shared body)","kind":"short","jgRVA":"0x031C47CA","jgOff":4,"expectedMatches":2,"sig":"837A28027F368B8A640100008B411880BA540100000075088B"},{"name":"OnExtensionSystemReady startup loop","kind":"short","jgRVA":"0x01B51743","jgOff":4,"expectedMatches":2,"sig":"837928027F288B91640100008B421880B95401000000750C8B"},{"name":"MaybeReEnableExtension","kind":"short","jgRVA":"0x08BBA108","jgOff":4,"expectedMatches":1,"sig":"837E28027F248B8E640100008B411880BE540100000075088B"},{"name":"UserMayInstall (inlined)","kind":"short","jgRVA":"0x093997BF","jgOff":4,"expectedMatches":1,"sig":"837F28027F458B8F640100008B411880BF5401000000750C8B"},{"name":"MustRemainDisabled (inlined, near jg)","kind":"near","jgRVA":"0x01205788","jgOff":4,"expectedMatches":1,"sig":"837B28020F8F840000008B8B640100008B411880BB54010000007508"},{"name":"IsExtensionAffected (type!=PLATFORM_APP variant)","kind":"short","jgRVA":"0x014E0239","jgOff":4,"expectedMatches":1,"sig":"837928027F268B45D480B8540100000075628B45D48B806401"}]},
{"name":"154-linux","container":"elf","sites":[{"name":"manifest_v2_util::IsExtensionAffected (free predicate; covers the ShouldBlockExtensionInstallation thunk, which tail-jumps here)","kind":"short","jgRVA":"0x0991AA29","jgOff":3,"expectedMatches":1,"sig":"83FF027F1D83FE087718B90A0100000FA3F1730E83FA050F95"},{"name":"ManifestV2Handler::IsExtensionAffected / ShouldBlockExtensionEnable (shared body; also covers OnExtensionSystemReady and MaybeReEnableExtension's calls out to it)","kind":"short","jgRVA":"0x0991A6D4","jgOff":4,"expectedMatches":1,"sig":"837E50027F2F554889E5488B8E280200008B413080BE080200"},{"name":"ManifestV2Handler::MaybeReEnableExtension (inlined)","kind":"short","jgRVA":"0x0991A818","jgOff":4,"expectedMatches":1,"sig":"837B50027F30488B8B280200008B413080BB08020000007508"},{"name":"StandardManagementPolicyProvider::UserMayInstall (inlined, near jg; Load-Unpacked gate)","kind":"near","jgRVA":"0x0A37E1CA","jgOff":4,"expectedMatches":1,"sig":"837B50020F8FD1000000488B8B280200008B413080BB080200000075"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled (inlined, near jg)","kind":"near","jgRVA":"0x05AB5FFA","jgOff":4,"expectedMatches":1,"sig":"837E50020F8F8E000000498B8E280200008B41304180BE0802000000"},{"name":"IsExtensionAffected / ShouldBlockExtensionEnable (member, 2nd body)","kind":"short","jgRVA":"0x053B0E40","jgOff":4,"expectedMatches":1,"sig":"837950027F2D488B91280200008B423080B90802000000750C"}]},
{"name":"154-macos-x64","container":"macho-x64","sites":[{"name":"StandardManagementPolicyProvider::MustRemainDisabled","kind":"short","jgRVA":"0x01CD2151","jgOff":4,"expectedMatches":1,"sig":"837E50027F6F498B8E280200008B41304180BE080200000075"},{"name":"ManifestV2Handler::OnExtensionSystemReady","kind":"short","jgRVA":"0x0322BD39","jgOff":4,"expectedMatches":1,"sig":"837950027F2D488B91280200008B423080B90802000000750C"},{"name":"ManifestV2Handler::IsExtensionAffected","kind":"short","jgRVA":"0x0497FD04","jgOff":4,"expectedMatches":1,"sig":"837E50027F2F554889E5488B8E280200008B413080BE080200"},{"name":"ManifestV2Handler::ShouldBlockExtensionInstallation","kind":"short","jgRVA":"0x07789FB8","jgOff":4,"expectedMatches":1,"sig":"837B50027F30488B8B280200008B413080BB08020000007508"},{"name":"ManifestV2Handler::ShouldBlockExtensionInstallation (2)","kind":"short","jgRVA":"0x0778A1B9","jgOff":3,"expectedMatches":1,"sig":"83FF027F1D83FE087718B90A0100000FA3F1730E83FA050F95"},{"name":"StandardManagementPolicyProvider::UserMayInstall","kind":"near","jgRVA":"0x081B49B0","jgOff":4,"expectedMatches":1,"sig":"837B50020F8FB7000000488B8B280200008B413080BB080200000075"},{"name":"IsExtensionAffected (type!=PLATFORM_APP variant)","kind":"short","jgRVA":"0x028F0E51","jgOff":4,"expectedMatches":1,"sig":"837F50027F34488B45A880B808020000000F852D010000488B"}]},
{"name":"154-linux-arm64","container":"elf-arm64","sites":[{"name":"ManifestV2Handler::MaybeReEnableExtension (shared body)","kind":"bcond","jgRVA":"0x05E87478","jgOff":4,"expectedMatches":2,"sig":"1F0900712C020054691641F96A224839283140B98A000037296940B93F050071"},{"name":"ManifestV2Handler::IsExtensionAffected / ShouldBlockExtensionEnable (shared body)","kind":"bcond","jgRVA":"0x05E8763C","jgOff":4,"expectedMatches":1,"sig":"1F0900710C020054091441F90A204839283140B98A000037296940B93F050071"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled / UserMayInstall (shared body)","kind":"bcond","jgRVA":"0x0609B370","jgOff":4,"expectedMatches":2,"sig":"1F0900718C010054891641F98A224839283140B98A000037296940B93F050071"},{"name":"ManifestV2Handler::OnExtensionSystemReady (shared body)","kind":"bcond","jgRVA":"0x06AB7470","jgOff":4,"expectedMatches":1,"sig":"3F0900718C010054091541F90A214839283140B98A000037296940B93F050071"},{"name":"ManifestV2Handler member gate (additional inlined copy; +0x228/+0x208)","kind":"bcond","jgRVA":"0x09B77244","jgOff":4,"expectedMatches":1,"sig":"7F0900718C0100544B1541F94C2148396A3140B98C0000376B6940B97F050071"}]},
{"name":"155","container":"pe","sites":[{"name":"OnExtensionSystemReady startup loop","kind":"short","jgRVA":"0x0155EB53","jgOff":4,"expectedMatches":1,"sig":"837950027F30488B91280200008B425080B90802000000750F"},{"name":"MustRemainDisabled (inlined, near jg)","kind":"near","jgRVA":"0x016CB234","jgOff":4,"expectedMatches":1,"sig":"837F50020F8F8E000000488B8F280200008B415080BF080200000075"},{"name":"IsExtensionAffected (type!=PLATFORM_APP variant; +0x208 flag then +0x228 manifest)","kind":"short","jgRVA":"0x01C91ED1","jgOff":4,"expectedMatches":1,"sig":"837F50027F2F80BF08020000000F8501010000488B87280200"},{"name":"ShouldBlockExtensionEnable / IsExtensionAffected (shared body)","kind":"short","jgRVA":"0x03269A44","jgOff":4,"expectedMatches":2,"sig":"837A50027F37488B8A280200008B415080BA0802000000750B"},{"name":"MaybeReEnableExtension","kind":"short","jgRVA":"0x084DEA66","jgOff":4,"expectedMatches":1,"sig":"837E50027F30488B8E280200008B415080BE0802000000750B"},{"name":"manifest_v2_util::IsExtensionAffected (free predicate; covers install thunk)","kind":"short","jgRVA":"0x084DEC85","jgOff":3,"expectedMatches":1,"sig":"83F9027F1F83FA08771AB90A0100000FA3D173104183F8050F"},{"name":"UserMayInstall (inlined)","kind":"short","jgRVA":"0x090A7931","jgOff":4,"expectedMatches":1,"sig":"837F50027F51488B8F280200008B415080BF0802000000750F"}]},
{"name":"155-x86","container":"pe32","sites":[{"name":"MustRemainDisabled (inlined, near jg)","kind":"near","jgRVA":"0x011D9EB8","jgOff":4,"expectedMatches":1,"sig":"837B28020F8F840000008B8B640100008B412880BB54010000007508"},{"name":"IsExtensionAffected (type!=PLATFORM_APP variant)","kind":"short","jgRVA":"0x014BC549","jgOff":4,"expectedMatches":1,"sig":"837928027F268B45D480B8540100000075628B45D48B806401"},{"name":"OnExtensionSystemReady startup loop","kind":"short","jgRVA":"0x01AFBEF3","jgOff":4,"expectedMatches":2,"sig":"837928027F288B91640100008B422880B95401000000750C8B"},{"name":"ShouldBlockExtensionEnable / IsExtensionAffected (shared body)","kind":"short","jgRVA":"0x032F125A","jgOff":4,"expectedMatches":2,"sig":"837A28027F368B8A640100008B412880BA540100000075088B"},{"name":"MaybeReEnableExtension","kind":"short","jgRVA":"0x08F66848","jgOff":4,"expectedMatches":1,"sig":"837E28027F248B8E640100008B412880BE540100000075088B"},{"name":"manifest_v2_util::IsExtensionAffected (free predicate; covers install thunk)","kind":"short","jgRVA":"0x08F66957","jgOff":4,"expectedMatches":1,"sig":"837D08027F278B4D0C31C083F908771FBA0A0100000FA3CA73"},{"name":"UserMayInstall (inlined)","kind":"short","jgRVA":"0x097626DF","jgOff":4,"expectedMatches":1,"sig":"837F28027F458B8F640100008B412880BF5401000000750C8B"}]},
{"name":"155-linux","container":"elf","sites":[{"name":"IsExtensionAffected / ShouldBlockExtensionEnable (member, 2nd body)","kind":"short","jgRVA":"0x041AAAE0","jgOff":4,"expectedMatches":1,"sig":"837950027F30488B91280200008B425080B90802000000750F"},{"name":"IsExtensionAffected (type!=PLATFORM_APP variant)","kind":"short","jgRVA":"0x0644CEE2","jgOff":4,"expectedMatches":1,"sig":"837F50027F324180BC2408020000000F85D6000000498B8424"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled (inlined, near jg)","kind":"near","jgRVA":"0x06835F7D","jgOff":4,"expectedMatches":1,"sig":"837E50020F8F91000000498B8E280200008B41504180BE0802000000"},{"name":"ManifestV2Handler::IsExtensionAffected / ShouldBlockExtensionEnable (shared body; also covers OnExtensionSystemReady and MaybeReEnableExtension's calls out to it)","kind":"short","jgRVA":"0x099272C4","jgOff":4,"expectedMatches":1,"sig":"837E50027F32554889E5488B8E280200008B415080BE080200"},{"name":"ManifestV2Handler::MaybeReEnableExtension (inlined)","kind":"short","jgRVA":"0x09927408","jgOff":4,"expectedMatches":1,"sig":"837B50027F33488B8B280200008B415080BB0802000000750B"},{"name":"manifest_v2_util::IsExtensionAffected (free predicate; covers the ShouldBlockExtensionInstallation thunk, which tail-jumps here)","kind":"short","jgRVA":"0x09927619","jgOff":3,"expectedMatches":1,"sig":"83FF027F1D83FE087718B90A0100000FA3F1730E83FA050F95"},{"name":"StandardManagementPolicyProvider::UserMayInstall (inlined, near jg; Load-Unpacked gate)","kind":"near","jgRVA":"0x0A3DC86A","jgOff":4,"expectedMatches":1,"sig":"837B50020F8FD4000000488B8B280200008B415080BB080200000075"}]},
{"name":"155-macos-x64","container":"macho-x64","sites":[{"name":"StandardManagementPolicyProvider::MustRemainDisabled","kind":"short","jgRVA":"0x01CF5558","jgOff":4,"expectedMatches":1,"sig":"837E50027F72498B8E280200008B41504180BE080200000075"},{"name":"IsExtensionAffected (type!=PLATFORM_APP variant)","kind":"short","jgRVA":"0x028F526E","jgOff":4,"expectedMatches":1,"sig":"837F50027F324180BC2408020000000F85E1000000498B8424"},{"name":"ManifestV2Handler::OnExtensionSystemReady","kind":"short","jgRVA":"0x0322A6B9","jgOff":4,"expectedMatches":1,"sig":"837950027F30488B91280200008B425080B90802000000750F"},{"name":"ManifestV2Handler::IsExtensionAffected","kind":"short","jgRVA":"0x0496FB64","jgOff":4,"expectedMatches":1,"sig":"837E50027F32554889E5488B8E280200008B415080BE080200"},{"name":"ManifestV2Handler::ShouldBlockExtensionInstallation","kind":"short","jgRVA":"0x07806AE8","jgOff":4,"expectedMatches":1,"sig":"837B50027F33488B8B280200008B415080BB0802000000750B"},{"name":"ManifestV2Handler::ShouldBlockExtensionInstallation (2)","kind":"short","jgRVA":"0x07806CE9","jgOff":3,"expectedMatches":1,"sig":"83FF027F1D83FE087718B90A0100000FA3F1730E83FA050F95"},{"name":"StandardManagementPolicyProvider::UserMayInstall","kind":"near","jgRVA":"0x0827BE80","jgOff":4,"expectedMatches":1,"sig":"837B50020F8FBA000000488B8B280200008B415080BB080200000075"}]},
{"name":"155-macos-arm64","container":"macho-arm64","sites":[{"name":"StandardManagementPolicyProvider::MustRemainDisabled","kind":"bcond","jgRVA":"0x022BD404","jgOff":4,"expectedMatches":1,"sig":"1F090071EC040054891641F9285140B98A2248398A000037298940B93F050071"},{"name":"IsExtensionAffected (type!=PLATFORM_APP variant)","kind":"bcond","jgRVA":"0x026FFEFC","jgOff":8,"expectedMatches":1,"sig":"C85240B91F0900718C010054C8224839"},{"name":"ManifestV2Handler::OnExtensionSystemReady","kind":"bcond","jgRVA":"0x031F4CA4","jgOff":4,"expectedMatches":1,"sig":"1F090071AC0100542A1541F9485140B929214839C9000037498940B93F050071"},{"name":"ManifestV2Handler::IsExtensionAffected","kind":"bcond","jgRVA":"0x0403B248","jgOff":4,"expectedMatches":1,"sig":"1F090071CC010054291441F9285140B92A204839CA000037298940B93F050071"},{"name":"ManifestV2Handler::ShouldBlockExtensionInstallation / StandardManagementPolicyProvider::UserMayInstall (shared body)","kind":"bcond","jgRVA":"0x068F3880","jgOff":4,"expectedMatches":2,"sig":"1F090071AC010054691641F9285140B96A224839CA000037298940B93F050071"}]},
{"name":"155-linux-arm64","container":"elf-arm64","sites":[{"name":"ManifestV2Handler::MaybeReEnableExtension (shared body)","kind":"bcond","jgRVA":"0x05E7E1E4","jgOff":4,"expectedMatches":2,"sig":"1F0900712C020054691641F96A224839285140B98A000037298940B93F050071"},{"name":"ManifestV2Handler::IsExtensionAffected / ShouldBlockExtensionEnable (shared body)","kind":"bcond","jgRVA":"0x05E7E3A8","jgOff":4,"expectedMatches":1,"sig":"1F0900710C020054091441F90A204839285140B98A000037298940B93F050071"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled / UserMayInstall (shared body)","kind":"bcond","jgRVA":"0x06096308","jgOff":4,"expectedMatches":2,"sig":"1F0900718C010054891641F98A224839285140B98A000037298940B93F050071"},{"name":"ManifestV2Handler::OnExtensionSystemReady (shared body)","kind":"bcond","jgRVA":"0x06B05764","jgOff":4,"expectedMatches":1,"sig":"3F0900718C010054091541F90A214839285140B98A000037298940B93F050071"},{"name":"ManifestV2Handler member gate (additional inlined copy; +0x228/+0x208)","kind":"bcond","jgRVA":"0x0A2934B4","jgOff":4,"expectedMatches":1,"sig":"7F0900718C0100544B1541F94C2148396A5140B98C0000376B8940B97F050071"},{"name":"IsExtensionAffected (type!=PLATFORM_APP variant)","kind":"bcond","jgRVA":"0x0A298B7C","jgOff":8,"expectedMatches":1,"sig":"C85240B91F0900718C010054C8224839"}]},
{"name":"154-win-arm64","container":"pe-arm64","sites":[{"name":"ManifestV2Handler::OnExtensionSystemReady","kind":"bcond","jgRVA":"0x010B5620","jgOff":4,"expectedMatches":1,"sig":"5F0900718C0100542A1541F92B214839495140B98B0000374A8940B95F050071"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled / StandardManagementPolicyProvider::UserMayInstall (shared body)","kind":"bcond","jgRVA":"0x01354B40","jgOff":4,"expectedMatches":2,"sig":"1F0900712C060054891641F98A224839285140B98A000037298940B93F050071"},{"name":"IsExtensionAffected (type!=PLATFORM_APP variant)","kind":"bcond","jgRVA":"0x0182F8EC","jgOff":8,"expectedMatches":1,"sig":"C85240B91F0900718C010054C8224839"},{"name":"ManifestV2Handler::ShouldBlockExtensionEnable / ManifestV2Handler::IsExtensionAffected (shared body)","kind":"bcond","jgRVA":"0x02C30AD8","jgOff":4,"expectedMatches":2,"sig":"1F0900710C020054291441F92A204839285140B98A000037298940B93F050071"},{"name":"ManifestV2Handler::MaybeReEnableExtension","kind":"bcond","jgRVA":"0x079DBD98","jgOff":4,"expectedMatches":1,"sig":"1F0900710C020054691641F96A224839285140B98A000037298940B93F050071"}]},
{"name":"154-cft","container":"pe","sites":[{"name":"MustRemainDisabled (inlined, near jg)","kind":"near","jgRVA":"0x01688BA1","jgOff":4,"expectedMatches":1,"sig":"837F50020F8F8B000000488B8F280200008B413080BF080200000075"},{"name":"OnExtensionSystemReady startup loop","kind":"short","jgRVA":"0x01775F73","jgOff":4,"expectedMatches":1,"sig":"837950027F2D488B91280200008B423080B90802000000750C"},{"name":"IsExtensionAffected (type!=PLATFORM_APP variant; +0x208 flag then +0x228 manifest)","kind":"short","jgRVA":"0x01C4A96D","jgOff":4,"expectedMatches":1,"sig":"837F50027F2C80BF08020000000F857E010000488B87280200"},{"name":"ShouldBlockExtensionEnable / IsExtensionAffected (shared body)","kind":"short","jgRVA":"0x033B71F4","jgOff":4,"expectedMatches":2,"sig":"837A50027F34488B8A280200008B413080BA08020000007508"},{"name":"MaybeReEnableExtension","kind":"short","jgRVA":"0x085A9A16","jgOff":4,"expectedMatches":1,"sig":"837E50027F2D488B8E280200008B413080BE08020000007508"},{"name":"manifest_v2_util::IsExtensionAffected (free predicate; covers install thunk)","kind":"short","jgRVA":"0x085A9C35","jgOff":3,"expectedMatches":1,"sig":"83F9027F1F83FA08771AB90A0100000FA3D173104183F8050F"},{"name":"UserMayInstall (inlined)","kind":"short","jgRVA":"0x09119E71","jgOff":4,"expectedMatches":1,"sig":"837F50027F4E488B8F280200008B413080BF0802000000750C"}]}
]}'''

KIND_SHORT, KIND_NEAR, KIND_BCOND = 0, 1, 2
VALID_CONTAINERS = ("pe", "pe32", "pe-arm64", "elf", "elf-arm64", "macho-x64", "macho-arm64")
ARM64_CONTAINERS = ("pe-arm64", "elf-arm64", "macho-arm64")


class Mv2Error(Exception):
    """A user-facing failure: caught at the command boundary, printed as [-]."""


# ============================================================================
# Console colour + tags. Empty strings when colour is off, so every caller can
# interpolate them unconditionally.
# ============================================================================
C = {k: "" for k in ("reset", "red", "grn", "yel", "cyn", "dim", "bold")}
TAG = {}


def _enable_win_vt():
    try:
        import ctypes
        k = ctypes.windll.kernel32
        for handle in (-11,):  # STD_OUTPUT_HANDLE
            h = k.GetStdHandle(handle)
            mode = ctypes.c_uint32()
            if k.GetConsoleMode(h, ctypes.byref(mode)):
                k.SetConsoleMode(h, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass


def init_colors():
    vt = sys.stdout.isatty()
    if os.environ.get("FORCE_COLOR"):
        vt = True
    if os.environ.get("NO_COLOR"):
        vt = False
    if vt and IS_WIN:
        _enable_win_vt()
    e = "\x1b"
    if vt:
        C.update(reset=e + "[0m", red=e + "[91m", grn=e + "[92m",
                 yel=e + "[93m", cyn=e + "[96m", dim=e + "[90m", bold=e + "[1m")
    else:
        for key in C:
            C[key] = ""
    TAG["ok"] = f"{C['grn']}[+]{C['reset']}"
    TAG["err"] = f"{C['red']}[-]{C['reset']}"
    TAG["info"] = f"{C['cyn']}[*]{C['reset']}"
    TAG["warn"] = f"{C['yel']}[!]{C['reset']}"
    TAG["success"] = f"{C['bold']}{C['grn']}[SUCCESS]{C['reset']}"
    TAG["warning"] = f"{C['bold']}{C['yel']}[WARNING]{C['reset']}"


def infof(m):    print(f"{TAG.get('info', '[*]')} {m}")
def okf(m):      print(f"{TAG.get('ok', '[+]')} {m}")
def warnf(m):    print(f"{TAG.get('warn', '[!]')} {m}")
def errf(m):     print(f"{TAG.get('err', '[-]')} {m}")
def successf(m): print(f"{TAG.get('success', '[SUCCESS]')} {m}")
def rule():      print(f"{C['cyn']}=========================================================={C['reset']}")


def banner():
    rule()
    print(f"{C['bold']}                    MV2 Patcher v{APP_VERSION}                    {C['reset']}")
    rule()


# ============================================================================
# Small helpers
# ============================================================================
def sha256_bytes(b):
    return hashlib.sha256(bytes(b)).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def file_size(path):
    return os.path.getsize(path)


def within(offset, count, size):
    return offset >= 0 and count >= 0 and offset <= size and count <= size - offset


def script_path():
    p = globals().get("__file__")
    if p:
        try:
            return os.path.abspath(p)
        except Exception:
            return None
    return None


def script_dir():
    p = script_path()
    return os.path.dirname(p) if p else None


# ============================================================================
# Signature loading + strict validation (port of Import-Milestones /
# json_to_tokens). Every table this engine will act on is checked here: the
# container is known, the kind matches the container architecture, jgOff points
# at a stock jump opcode, and expectedMatches >= 1. Anything off is a hard error.
# ============================================================================
class Site:
    __slots__ = ("name", "kind", "jg_rva", "sig", "jg_off", "expected")

    def __init__(self, name, kind, jg_rva, sig, jg_off, expected):
        self.name = name
        self.kind = kind
        self.jg_rva = jg_rva
        self.sig = sig
        self.jg_off = jg_off
        self.expected = expected


class Milestone:
    __slots__ = ("name", "container", "sites")

    def __init__(self, name, container, sites):
        self.name = name
        self.container = container
        self.sites = sites


def _get_signatures_path(override):
    if override:
        if not os.path.isfile(override):
            raise Mv2Error(f"signature file does not exist: {override}")
        return os.path.abspath(override)
    d = script_dir()
    if d:
        beside = os.path.join(d, SIGNATURES_FILE)
        if os.path.isfile(beside):
            return beside
    return None


def _read_signature_doc(override):
    path = _get_signatures_path(override)
    if path:
        try:
            raw = open(path, "r", encoding="utf-8").read()
        except Exception as e:
            raise Mv2Error(f"reading {path}: {e}")
        label = path
    else:
        raw = EMBEDDED_SIGNATURES
        label = "embedded tables"
    try:
        return json.loads(raw), label
    except Exception as e:
        raise Mv2Error(f"parsing {label}: {e}")


def import_milestones(override):
    doc, label = _read_signature_doc(override)
    ms = doc.get("milestones") if isinstance(doc, dict) else None
    if not isinstance(ms, list) or not ms:
        raise Mv2Error("signature document contains no milestones")
    out = []
    seen = set()
    for rm in ms:
        name = str(rm.get("name", ""))
        container = str(rm.get("container", ""))
        if not name.strip() or re.search(r"[\r\n|]", name):
            raise Mv2Error("milestone name is empty or contains a reserved character")
        if name in seen:
            raise Mv2Error(f"duplicate milestone name '{name}'")
        seen.add(name)
        if container not in VALID_CONTAINERS:
            raise Mv2Error(f"milestone {name} has unsupported container '{container}'")
        sites_raw = rm.get("sites")
        if not isinstance(sites_raw, list) or not sites_raw:
            raise Mv2Error(f"milestone {name} contains no sites")
        sites = []
        snames = set()
        for rs in sites_raw:
            sname = str(rs.get("name", ""))
            if not sname.strip() or re.search(r"[\r\n|]", sname):
                raise Mv2Error(f"milestone {name} has an invalid site name")
            if sname in snames:
                raise Mv2Error(f"milestone {name} has duplicate site '{sname}'")
            snames.add(sname)
            kraw = rs.get("kind")
            kind = {"short": KIND_SHORT, "near": KIND_NEAR, "bcond": KIND_BCOND}.get(kraw)
            if kind is None:
                raise Mv2Error(f"milestone {name} site '{sname}': unknown kind '{kraw}'")
            is_arm = container in ARM64_CONTAINERS
            if kind == KIND_BCOND and not is_arm:
                raise Mv2Error(f"milestone {name} site '{sname}': 'bcond' is only valid in an arm64 milestone")
            if kind != KIND_BCOND and is_arm:
                raise Mv2Error(f"milestone {name} site '{sname}': arm64 milestones use the 'bcond' kind, not '{kraw}'")
            sig_text = str(rs.get("sig", ""))
            if not sig_text or len(sig_text) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", sig_text):
                raise Mv2Error(f"milestone {name} site '{sname}': sig must be non-empty hexadecimal bytes")
            sig = bytes.fromhex(sig_text)
            jg_off = rs.get("jgOff")
            if not isinstance(jg_off, int) or isinstance(jg_off, bool) or jg_off < 0 or jg_off >= len(sig):
                raise Mv2Error(f"milestone {name} site '{sname}': jgOff out of range (sig len {len(sig)})")
            need = {KIND_SHORT: 2, KIND_NEAR: 6, KIND_BCOND: 4}[kind]
            if jg_off + need > len(sig):
                raise Mv2Error(f"milestone {name} site '{sname}': jump runs past the sig")
            if kind == KIND_SHORT and sig[jg_off] != 0x7F:
                raise Mv2Error(f"milestone {name} site '{sname}': jgOff points at 0x{sig[jg_off]:02X}, not a short jg")
            if kind == KIND_NEAR and sig[jg_off:jg_off + 2] != b"\x0f\x8f":
                raise Mv2Error(f"milestone {name} site '{sname}': near jg is not 0F 8F")
            if kind == KIND_BCOND:
                w = int.from_bytes(sig[jg_off:jg_off + 4], "little")
                if (w & 0xFF00001F) != 0x5400000C:
                    raise Mv2Error(f"milestone {name} site '{sname}': jgOff is not a stock b.gt (GT) word (0x{w:08X})")
            expected = rs.get("expectedMatches")
            if not isinstance(expected, int) or isinstance(expected, bool) or expected < 1:
                raise Mv2Error(f"milestone {name} site '{sname}': expectedMatches must be >= 1")
            jg_rva_raw = str(rs.get("jgRVA", ""))
            if not re.fullmatch(r"0[xX][0-9A-Fa-f]+", jg_rva_raw):
                raise Mv2Error(f"milestone {name} site '{sname}': bad jgRVA")
            sites.append(Site(sname, kind, int(jg_rva_raw, 16), sig, jg_off, expected))
        out.append(Milestone(name, container, sites))
    return out, label


# ============================================================================
# Matching engine. Exact on every byte except the masked jump:
#   short : jgOff in {7F,EB}; jgOff+1 (disp8) wild
#   near  : jgOff,+1 the pair {0F 8F | 90 E9}; +2..+5 (disp32) wild
#   bcond : the 4-byte LE word at jgOff - 0x54 + bit4=0 fixed, cond in {0xC,0xE},
#           imm19 wild. Accepting the patched form (EB / 90 E9 / AL) is what makes
#           a re-run idempotent instead of "no known layout matched".
# ============================================================================
def sig_matches_at(buf, start, sig, jg_off, kind):
    n = len(sig)
    if start < 0 or start + n > len(buf):
        return False
    if kind == KIND_BCOND:
        w0 = start + jg_off
        word = buf[w0] | (buf[w0 + 1] << 8) | (buf[w0 + 2] << 16) | (buf[w0 + 3] << 24)
        if (word & 0xFF000010) != 0x54000000:
            return False
        cond = word & 0xF
        if cond != 0x0C and cond != 0x0E:
            return False
    for k in range(n):
        p = buf[start + k]
        if kind == KIND_SHORT:
            if k == jg_off:
                if p != 0x7F and p != 0xEB:
                    return False
            elif k == jg_off + 1:
                pass
            elif p != sig[k]:
                return False
        elif kind == KIND_NEAR:
            if k == jg_off:
                p1 = buf[start + jg_off + 1]
                if not ((p == 0x0F and p1 == 0x8F) or (p == 0x90 and p1 == 0xE9)):
                    return False
            elif k == jg_off + 1:
                pass
            elif jg_off + 2 <= k <= jg_off + 5:
                pass
            elif p != sig[k]:
                return False
        else:  # bcond: the 4 branch-word bytes were validated above
            if jg_off <= k <= jg_off + 3:
                pass
            elif p != sig[k]:
                return False
    return True


def _build_anchor(sig, jg_off, kind):
    """Longest fixed (unmasked) run in the sig -> a raw anchor for bytes.find.
    The two maximal runs are [0, jgOff) and [jgOff+masklen, len); pick the longer.
    Returns (anchor_bytes, anchor_off_within_sig)."""
    mask_len = {KIND_SHORT: 2, KIND_NEAR: 6, KIND_BCOND: 4}[kind]
    mask_end = jg_off + mask_len
    a_len, a_start = jg_off, 0
    tail = len(sig) - mask_end
    if tail > a_len:
        a_len, a_start = tail, mask_end
    if a_len <= 0:
        return b"", 0
    return sig[a_start:a_start + a_len], a_start


def scan_text(buf, text_raw, text_size, sig, jg_off, kind, expected):
    """Full .text scan (used when the recorded RVA missed): hop candidates by a
    raw anchor via bytes.find, verify each with the full masked matcher. Returns
    file offsets of each jg opcode byte; stops once it exceeds expectedMatches."""
    n = len(sig)
    limit = min(text_raw + text_size, len(buf))
    anchor, aoff = _build_anchor(sig, jg_off, kind)
    if not anchor:
        return []
    found = []
    pos = text_raw
    while True:
        i = buf.find(anchor, pos, limit)
        if i < 0:
            break
        pos = i + 1
        s = i - aoff
        if s >= text_raw and s + n <= limit and sig_matches_at(buf, s, sig, jg_off, kind):
            off = s + jg_off
            if off not in found:
                found.append(off)
                if len(found) > expected:
                    break
    return found


# ============================================================================
# Image layer -> a common "slice" model so the engine is container-agnostic.
# ELF/PE are a single slice; a fat Mach-O has one slice per CPU. For every
# container: text_vaddr is the RVA/vmaddr the table's jgRVA is relative to, and
# text_raw is the ABSOLUTE file offset of .text/__text.
# ============================================================================
ELF_MAGIC = b"\x7fELF"
_MACHO_MAGICS = {
    "cffaedfe", "cefaedfe", "feedfacf", "feedface",
    "cafebabe", "cafebabf", "bebafeca", "bfbafeca",
}


class Slice:
    __slots__ = ("container", "base", "text_vaddr", "text_raw", "text_size", "uuid")

    def __init__(self, container, base, text_vaddr, text_raw, text_size, uuid):
        self.container = container
        self.base = base
        self.text_vaddr = text_vaddr
        self.text_raw = text_raw
        self.text_size = text_size
        self.uuid = uuid


class Image:
    def __init__(self, kind, slices):
        self.kind = kind          # 'pe' | 'elf' | 'macho'
        self.slices = slices
        self.length = 0
        # PE extras:
        self.pe_checksum_at = 0
        self.pe_secdir_at = 0
        self.pe_machine = 0
        self.pe_timestamp = 0
        self.pe_is32 = False


def detect_container(data):
    if len(data) >= 2 and data[0] == 0x4D and data[1] == 0x5A:
        return "pe"
    if data[:4] == ELF_MAGIC:
        return "elf"
    if data[:4].hex() in _MACHO_MAGICS:
        return "macho"
    return ""


def detect_container_file(path):
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except Exception:
        return ""
    return detect_container(head)


def open_pe(buf):
    if len(buf) < 64:
        raise Mv2Error("not a valid Chrome file: file too small")
    e_lfanew = int.from_bytes(buf[0x3C:0x40], "little")
    if e_lfanew + 24 > len(buf):
        raise Mv2Error("not a valid Chrome file: truncated NT headers")
    if buf[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise Mv2Error("not a valid Chrome file: bad NT signature")
    num_sections = int.from_bytes(buf[e_lfanew + 6:e_lfanew + 8], "little")
    size_opt = int.from_bytes(buf[e_lfanew + 20:e_lfanew + 22], "little")
    opt_off = e_lfanew + 24
    if opt_off + size_opt > len(buf):
        raise Mv2Error("not a valid Chrome file: optional header out of bounds")
    magic = int.from_bytes(buf[opt_off:opt_off + 2], "little")
    if magic == 0x20B:
        fixed, is32 = 112, False
    elif magic == 0x10B:
        fixed, is32 = 96, True
    else:
        raise Mv2Error(f"not a valid Chrome file: unsupported optional header magic 0x{magic:X}")
    if size_opt < fixed + 5 * 8:
        raise Mv2Error("not a valid Chrome file: optional header too small for data directories")
    sec_off = opt_off + size_opt
    if sec_off + num_sections * 40 > len(buf):
        raise Mv2Error("not a valid Chrome file: section table out of bounds")
    text_rva = text_raw = text_size = 0
    for i in range(num_sections):
        sh = sec_off + i * 40
        name = buf[sh:sh + 8].split(b"\x00", 1)[0]
        if name == b".text":
            text_rva = int.from_bytes(buf[sh + 12:sh + 16], "little")
            text_size = int.from_bytes(buf[sh + 16:sh + 20], "little")
            text_raw = int.from_bytes(buf[sh + 20:sh + 24], "little")
            break
    if text_size == 0:
        raise Mv2Error("not a valid Chrome file: missing code section")
    if text_raw < 0 or text_raw + text_size > len(buf):
        raise Mv2Error("not a valid Chrome file: .text raw data is out of bounds")
    machine = int.from_bytes(buf[e_lfanew + 4:e_lfanew + 6], "little")
    fmt = "pe32" if is32 else ("pe-arm64" if machine == 0xAA64 else "pe")
    img = Image("pe", [Slice(fmt, 0, text_rva, text_raw, text_size, "")])
    img.pe_checksum_at = opt_off + 64
    img.pe_secdir_at = opt_off + fixed + 4 * 8
    img.pe_machine = machine
    img.pe_timestamp = int.from_bytes(buf[e_lfanew + 8:e_lfanew + 12], "little")
    img.pe_is32 = is32
    img.length = len(buf)
    return img


def _elf_section_table(buf):
    fsize = len(buf)
    shoff = int.from_bytes(buf[0x28:0x30], "little")
    shentsize = int.from_bytes(buf[0x3A:0x3C], "little")
    shnum = int.from_bytes(buf[0x3C:0x3E], "little")
    shstrndx = int.from_bytes(buf[0x3E:0x40], "little")
    if shoff < 64 or shoff > fsize or shnum == 0 or shstrndx == 0xFFFF:
        return None
    if shentsize < 64 or shstrndx >= shnum:
        return None
    if shnum > (fsize - shoff) // shentsize:
        return None
    strhdr = shoff + shstrndx * shentsize
    stroff = int.from_bytes(buf[strhdr + 0x18:strhdr + 0x20], "little")
    strsize = int.from_bytes(buf[strhdr + 0x20:strhdr + 0x28], "little")
    if not within(stroff, strsize, fsize):
        return None
    return shoff, shentsize, shnum, shstrndx, stroff, strsize


def open_elf(buf):
    if len(buf) < 64 or buf[:4] != ELF_MAGIC:
        raise Mv2Error("That doesn't look like a Chrome file.")
    if buf[4] != 2:
        raise Mv2Error("That's not a 64-bit Chrome file.")
    if buf[5] != 1:
        raise Mv2Error("That doesn't look like a valid Chrome file.")
    e_machine = int.from_bytes(buf[0x12:0x14], "little")
    container = "elf-arm64" if e_machine == 0xB7 else "elf"
    st = _elf_section_table(buf)
    if not st:
        raise Mv2Error("That doesn't look like a valid Chrome file.")
    shoff, shentsize, shnum, shstrndx, stroff, strsize = st
    text_vaddr = text_raw = text_size = 0
    for i in range(shnum):
        sh = shoff + i * shentsize
        name_off = int.from_bytes(buf[sh:sh + 4], "little")
        if name_off >= strsize:
            continue
        name = buf[stroff + name_off:stroff + name_off + 8].split(b"\x00", 1)[0]
        if name == b".text":
            text_vaddr = int.from_bytes(buf[sh + 0x10:sh + 0x18], "little")
            text_raw = int.from_bytes(buf[sh + 0x18:sh + 0x20], "little")
            text_size = int.from_bytes(buf[sh + 0x20:sh + 0x28], "little")
            break
    if text_size == 0:
        raise Mv2Error("That doesn't look like a valid Chrome file (missing code section).")
    if not within(text_raw, text_size, len(buf)):
        raise Mv2Error("That doesn't look like a valid Chrome file.")
    img = Image("elf", [Slice(container, 0, text_vaddr, text_raw, text_size, "")])
    img.length = len(buf)
    return img


def get_elf_build_id(buf):
    if len(buf) < 64 or buf[:4] != ELF_MAGIC or buf[4] != 2 or buf[5] != 1:
        return ""
    st = _elf_section_table(buf)
    if not st:
        return ""
    shoff, shentsize, shnum, shstrndx, stroff, strsize = st
    want = b".note.gnu.build-id"
    for i in range(shnum):
        sh = shoff + i * shentsize
        name_off = int.from_bytes(buf[sh:sh + 4], "little")
        if name_off >= strsize:
            continue
        name = buf[stroff + name_off:stroff + name_off + 24].split(b"\x00", 1)[0]
        if name != want:
            continue
        sec_off = int.from_bytes(buf[sh + 0x18:sh + 0x20], "little")
        sec_size = int.from_bytes(buf[sh + 0x20:sh + 0x28], "little")
        if sec_size < 16 or not within(sec_off, sec_size, len(buf)):
            return ""
        namesz = int.from_bytes(buf[sec_off:sec_off + 4], "little")
        descsz = int.from_bytes(buf[sec_off + 4:sec_off + 8], "little")
        note_type = int.from_bytes(buf[sec_off + 8:sec_off + 12], "little")
        if note_type == 3 and namesz == 4 and 0 < descsz <= 64:
            if buf[sec_off + 12:sec_off + 16] != b"GNU\x00":
                return ""
            name_padded = ((namesz + 3) // 4) * 4
            desc_off = sec_off + 12 + name_padded
            if not within(desc_off, descsz, len(buf)) or desc_off + descsz > sec_off + sec_size:
                return ""
            return buf[desc_off:desc_off + descsz].hex()
        return ""
    return ""


def _macho_thin(buf, base, declared_size=0):
    if not within(base, 32, len(buf)):
        return None
    if int.from_bytes(buf[base:base + 4], "little") != 0xFEEDFACF:
        return None
    cputype = int.from_bytes(buf[base + 4:base + 8], "little")
    ncmds = int.from_bytes(buf[base + 16:base + 20], "little")
    if cputype == 0x01000007:
        container = "macho-x64"
    elif cputype == 0x0100000C:
        container = "macho-arm64"
    else:
        return None
    p = base + 32
    t_addr = t_off = t_size = None
    uuid = ""
    for _ in range(ncmds):
        if not within(p, 8, len(buf)):
            return None
        cmd = int.from_bytes(buf[p:p + 4], "little")
        cmdsize = int.from_bytes(buf[p + 4:p + 8], "little")
        if cmdsize < 8 or not within(p, cmdsize, len(buf)):
            return None
        if cmd == 0x19:  # LC_SEGMENT_64
            if buf[p + 8:p + 15] == b"__TEXT\x00":
                nsects = int.from_bytes(buf[p + 64:p + 68], "little")
                sec = p + 72
                for _ in range(nsects):
                    if buf[sec:sec + 7] == b"__text\x00":
                        t_addr = int.from_bytes(buf[sec + 32:sec + 40], "little")
                        t_size = int.from_bytes(buf[sec + 40:sec + 48], "little")
                        t_off = int.from_bytes(buf[sec + 48:sec + 52], "little")
                    sec += 80
        elif cmd == 0x1B:  # LC_UUID
            uuid = buf[p + 8:p + 24].hex()
        p += cmdsize
    if t_addr is None:
        return None
    raw = base + t_off
    if not within(raw, t_size, len(buf)):
        return None
    return Slice(container, base, t_addr, raw, t_size, uuid)


def open_macho(buf):
    if len(buf) < 32:
        raise Mv2Error("That doesn't look like a Chrome app file.")
    be = int.from_bytes(buf[0:4], "big")
    le = int.from_bytes(buf[0:4], "little")
    slices = []
    if be in (0xCAFEBABE, 0xCAFEBABF):
        is64 = be == 0xCAFEBABF
        nfat = int.from_bytes(buf[4:8], "big")
        if nfat < 1 or nfat > 32:
            raise Mv2Error("That doesn't look like a valid Chrome app file.")
        entry = 32 if is64 else 20
        off = 8
        for _ in range(nfat):
            if not within(off, entry, len(buf)):
                break
            if is64:
                soff = int.from_bytes(buf[off + 8:off + 16], "big")
            else:
                soff = int.from_bytes(buf[off + 8:off + 12], "big")
            off += entry
            s = _macho_thin(buf, soff)
            if s:
                slices.append(s)
    elif le == 0xFEEDFACF:
        s = _macho_thin(buf, 0)
        if s:
            slices.append(s)
    else:
        raise Mv2Error("That doesn't look like a Chrome app file.")
    if not slices:
        raise Mv2Error("This Chrome app isn't a supported type.")
    img = Image("macho", slices)
    img.length = len(buf)
    return img


def open_image(buf):
    if buf[:2] == b"MZ":
        return open_pe(buf)
    if buf[:4] == ELF_MAGIC:
        return open_elf(buf)
    if detect_container(buf) == "macho":
        return open_macho(buf)
    raise Mv2Error("That doesn't look like a Chrome file (this tool only works on chrome.dll / chrome / the Chrome framework).")


# ============================================================================
# PE finalize: clear the Authenticode Security Directory + recompute the PE
# checksum (16-bit ones-complement sum over the file, skipping the CheckSum
# field, plus the file size). Ones-complement folding is associative, so summing
# all 32-bit words once and folding at the end matches the incremental form.
# ============================================================================
def pe_checksum(data, checksum_off):
    length = len(data)
    dwords = length // 4
    skip = checksum_off // 4
    a = array.array("I")
    a.frombytes(bytes(data[:dwords * 4]))
    if sys.byteorder != "little":
        a.byteswap()
    total = sum(a)
    if 0 <= skip < dwords:
        total -= a[skip]
    rem = length % 4
    if rem:
        last = 0
        for k in range(rem):
            last |= data[dwords * 4 + k] << (8 * k)
        total += last
    while (total >> 16) != 0:
        total = (total & 0xFFFF) + (total >> 16)
    return (total + length) & 0xFFFFFFFF


def test_likely_stock_pe(img, buf):
    off = img.pe_secdir_at
    va = int.from_bytes(buf[off:off + 4], "little")
    sz = int.from_bytes(buf[off + 4:off + 8], "little")
    return va != 0 and sz != 0


def complete_pe_image(img, buf):
    off = img.pe_secdir_at
    va = int.from_bytes(buf[off:off + 4], "little")
    sz = int.from_bytes(buf[off + 4:off + 8], "little")
    if va != 0 or sz != 0:
        buf[off:off + 8] = b"\x00" * 8
    s = pe_checksum(buf, img.pe_checksum_at)
    buf[img.pe_checksum_at:img.pe_checksum_at + 4] = struct.pack("<I", s)


# ============================================================================
# Atomic write. Temp in the target's dir -> flush+fsync -> read-back hash verify
# -> optional race-guard re-check of the target -> os.replace (atomic on all
# platforms on the same volume). Never leaves a half-written target.
# ============================================================================
def write_atomic(target, data, expected_current_hash="", preserve_from="", known_hash=""):
    full = os.path.abspath(target)
    d = os.path.dirname(full) or os.getcwd()
    fd, tmp = tempfile.mkstemp(prefix=".chrome-mv2-", dir=d)
    ok = False
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        written = read_file(tmp)
        buf_hash = known_hash or sha256_bytes(data)
        if len(written) != len(data) or sha256_bytes(written) != buf_hash:
            raise Mv2Error(f"Couldn't write to {target} safely - nothing was changed.")
        if preserve_from and os.path.isfile(preserve_from):
            try:
                shutil.copymode(preserve_from, tmp)
            except Exception:
                pass
        if expected_current_hash:
            if not os.path.isfile(full):
                raise Mv2Error("The file went missing before we could update it.")
            now = sha256_file(full)
            if now != expected_current_hash.lower():
                raise Mv2Error("Chrome changed while we were working - nothing was changed. Try again.")
        os.replace(tmp, full)
        ok = True
    finally:
        if not ok and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


# ============================================================================
# Patching engine: probe the best milestone for a slice, then apply the flips.
# ============================================================================
class Probe:
    __slots__ = ("ms_name", "satisfied", "total", "full", "ties", "flips")

    def __init__(self, ms_name, satisfied, total, full, ties, flips):
        self.ms_name = ms_name
        self.satisfied = satisfied
        self.total = total
        self.full = full
        self.ties = ties
        self.flips = flips   # list of (site, jg_offset, relocated)


def find_site_matches(buf, sl, site, fast_only):
    tvaddr, traw, tsize = sl.text_vaddr, sl.text_raw, sl.text_size
    n = len(site.sig)
    if site.expected == 1 and site.jg_rva >= tvaddr:
        rva_in = site.jg_rva - tvaddr
        if rva_in < tsize:
            jg_raw = traw + rva_in
            sig_start = jg_raw - site.jg_off
            if sig_start >= traw and sig_start + n <= traw + tsize and \
               sig_matches_at(buf, sig_start, site.sig, site.jg_off, site.kind):
                return [jg_raw], False
    if fast_only or tsize < n:
        return [], False
    hits = scan_text(buf, traw, tsize, site.sig, site.jg_off, site.kind, site.expected)
    return hits, (len(hits) > 0)


def _probe_pass(buf, sl, milestones, fast_only):
    best = None
    for ms in milestones:
        if ms.container != sl.container:
            continue
        satisfied = 0
        total = 0
        flips = []
        for s in ms.sites:
            total += 1
            found, reloc = find_site_matches(buf, sl, s, fast_only)
            if len(found) == s.expected:
                satisfied += 1
                for off in found:
                    flips.append((s, off, reloc))
        if satisfied == 0:
            continue
        cand_full = satisfied == total
        best_full = best is not None and best.satisfied == best.total
        take = tie = False
        if best is None:
            take = True
        elif cand_full and not best_full:
            take = True
        elif cand_full and best_full and total > best.total:
            take = True
        elif (not cand_full) and (not best_full) and satisfied > best.satisfied:
            take = True
        elif (cand_full and best_full and total == best.total) or \
             ((not cand_full) and (not best_full) and satisfied == best.satisfied):
            tie = True
        if take:
            best = Probe(ms.name, satisfied, total, cand_full, 1, flips)
        elif tie:
            best.ties += 1
    if best is not None:
        best.full = best.satisfied == best.total and best.total > 0
    return best


def probe_slice(buf, sl, milestones):
    best = _probe_pass(buf, sl, milestones, fast_only=True)
    if best is not None and best.full:
        return best
    return _probe_pass(buf, sl, milestones, fast_only=False)


def apply_flips(buf, flips, apply=True, verbose=False):
    applied = already = stock = 0
    written = []
    for (site, off, _reloc) in flips:
        k = site.kind
        if k == KIND_SHORT:
            cur = buf[off]
            if cur == 0xEB:
                already += 1
                written.append((off, b"\xEB"))
                continue
            if cur != 0x7F:
                if verbose:
                    print(f"    {TAG['warn']} Skipped one change - it didn't look the way we expected.")
                continue
            stock += 1
            if apply:
                buf[off] = 0xEB
            applied += 1
            written.append((off, b"\xEB"))
        elif k == KIND_NEAR:
            o0, o1 = buf[off], buf[off + 1]
            if o0 == 0x90 and o1 == 0xE9:
                already += 1
                written.append((off, b"\x90\xE9"))
                continue
            if not (o0 == 0x0F and o1 == 0x8F):
                if verbose:
                    print(f"    {TAG['warn']} Skipped one change - it didn't look the way we expected.")
                continue
            stock += 1
            if apply:
                buf[off] = 0x90
                buf[off + 1] = 0xE9
            applied += 1
            written.append((off, b"\x90\xE9"))
        else:  # bcond
            cur = buf[off]
            cond = cur & 0x0F
            patched = (cur & 0xF0) | 0x0E
            if cond == 0x0E:
                already += 1
                written.append((off, bytes([patched])))
                continue
            if cond != 0x0C:
                if verbose:
                    print(f"    {TAG['warn']} Skipped one change - it didn't look the way we expected.")
                continue
            stock += 1
            if apply:
                buf[off] = patched
            applied += 1
            written.append((off, bytes([patched])))
    return {"applied": applied, "already": already, "stock": stock, "written": written}


def classify_flip_states(buf, flips):
    """(stock, patched) over the located gates, or raise on a mixed/damaged one."""
    stock = patched = 0
    for (site, off, _reloc) in flips:
        k = site.kind
        if k == KIND_SHORT:
            o0 = buf[off]
            if o0 == 0x7F:
                stock += 1
            elif o0 == 0xEB:
                patched += 1
            else:
                raise Mv2Error("mixed")
        elif k == KIND_NEAR:
            o0, o1 = buf[off], buf[off + 1]
            if o0 == 0x0F and o1 == 0x8F:
                stock += 1
            elif o0 == 0x90 and o1 == 0xE9:
                patched += 1
            else:
                raise Mv2Error("mixed")
        else:
            nib = buf[off] & 0x0F
            if nib == 0x0C:
                stock += 1
            elif nib == 0x0E:
                patched += 1
            else:
                raise Mv2Error("mixed")
    return stock, patched


class PatchResult:
    def __init__(self):
        self.status = 0        # 0 nothing/tie/partial; 1 flipped; 2 already patched
        self.milestone = ""
        self.located = 0
        self.total = 0
        self.full = False
        self.flips = 0
        self.stock = 0
        self.already = 0
        self.written = []      # (abs_off, bytes)
        self.relocated = False
        self.reason = ""


def patch_milestones(buf, sl, milestones, allow_partial=False, apply=True, version=""):
    """Single-slice engine (PE / ELF / one Mach-O slice). Mirrors the ps1
    Invoke-PatchMilestones semantics; PE checksum finalize is a separate step."""
    best = probe_slice(buf, sl, milestones)
    res = PatchResult()
    if best is None or best.satisfied == 0:
        return res
    res.milestone = best.ms_name
    res.located = best.satisfied
    res.total = best.total
    res.full = best.full
    if best.ties > 1:
        res.reason = f"{best.ties} possible Chrome versions tied - can't tell which one this is"
        return res
    if not res.full and not allow_partial:
        res.reason = f"only {res.located} of {res.total} changes matched; a partial patch needs --allow-partial"
        return res
    if apply:
        infof(f"Applying {len(best.flips)} change(s)...")
    r = apply_flips(buf, best.flips, apply=apply, verbose=apply)
    res.stock = r["stock"]
    res.already = r["already"]
    res.written = r["written"]
    res.relocated = any(f[2] for f in best.flips)
    res.flips = r["applied"] + r["already"]
    res.status = 1 if r["applied"] > 0 else 2
    return res


def get_clean_stock(buf, sl, milestones, allow_partial=False):
    probe = patch_milestones(buf, sl, milestones, allow_partial=allow_partial, apply=False)
    clean = (probe.status != 0 and probe.stock > 0 and probe.already == 0 and
             (probe.full or allow_partial) and not probe.reason)
    return clean, probe


def test_patch_output(buf, patch):
    for (off, wbytes) in patch.written:
        if off < 0 or off + len(wbytes) > len(buf):
            return False
        if bytes(buf[off:off + len(wbytes)]) != wbytes:
            return False
    return len(patch.written) > 0


def report_layout_candidates(buf, sl):
    if sl.text_size < 8:
        return
    infof("This Chrome version isn't recognized yet. Looking for clues to help add support...")
    marker = b"\x02\x7f"
    end = sl.text_raw + sl.text_size
    pos = sl.text_raw
    total = shown = 0
    maxd = 20
    while True:
        m = buf.find(marker, pos, end)
        if m < 0:
            break
        pos = m + 1
        if m < sl.text_raw + 2 or m + 2 > end:
            continue
        cmp_back = 0
        valid = False
        if buf[m - 2] == 0x83 and (buf[m - 1] & 0xF8) == 0xF8:
            valid, cmp_back = True, 2
        if not valid and m >= sl.text_raw + 3 and buf[m - 3] == 0x83 and (buf[m - 2] & 0xF8) == 0x78:
            valid, cmp_back = True, 3
        if not valid:
            continue
        fstart = m + 2
        fcount = min(40, end - fstart)
        region = bytes(buf[fstart:fstart + fcount])
        follow = False
        for j in range(0, max(0, len(region) - 2)):
            b0, b1, b2 = region[j], region[j + 1], region[j + 2]
            if b0 == 0x83 and (b1 & 0xF8) == 0xF8 and (b2 == 0x01 or b2 == 0x05):
                follow = True
                break
            if b0 == 0x80 and (b1 & 0xF8) == 0xB8 and j + 6 < len(region) and region[j + 6] == 0x00:
                follow = True
                break
        if not follow:
            continue
        total += 1
        if shown < maxd:
            rva = sl.text_vaddr + (m - cmp_back) - sl.text_raw
            print(f"    [candidate] RVA 0x{rva:X}")
            shown += 1
    extra = f" ({total - shown} not shown)" if total > shown else ""
    infof(f"Found {total} possible spot(s){extra}. Nothing was changed - "
          "please share this and your Chrome version with the developer.")


def chrome_label(version, milestone):
    if not version:
        return milestone
    major = version.split(".")[0]
    if re.match(rf"^{re.escape(major)}(\D|$)", milestone):
        return version
    return f"{version} (using the Chrome {milestone} changes)"


# ============================================================================
# Identity + backups. Sidecar formats match the existing tools so a binary
# patched by ps1/sh restores under py and vice-versa:
#   PE   : <file>.bak + <file>.bak.json  (JSON)
#   ELF  : <file>.bak + <file>.bak.meta  (key=value)
#   MachO: <file>.bak + <file>.bak.meta  (real .app: under Application Support)
# ============================================================================
def pe_identity(buf, img):
    return {
        "Format": img.slices[0].container,
        "Machine": img.pe_machine,
        "TimeStamp": img.pe_timestamp,
        "Length": len(buf),
        "SHA256": sha256_bytes(buf),
    }


def pe_same_build(a, b):
    return (a["Format"] == b["Format"] and int(a["Machine"]) == int(b["Machine"]) and
            int(a["TimeStamp"]) == int(b["TimeStamp"]) and int(a["Length"]) == int(b["Length"]))


def backup_path(target):
    return target + ".bak"


def _pe_meta_path(backup):
    return backup + ".json"


def _unix_meta_path(backup):
    return backup + ".meta"


def save_backup_pe(target, backup, buf, identity):
    write_atomic(backup, buf, preserve_from=target, known_hash=identity["SHA256"])
    meta = {
        "Schema": 1, "Format": identity["Format"], "Machine": identity["Machine"],
        "TimeStamp": identity["TimeStamp"], "Length": identity["Length"], "SHA256": identity["SHA256"],
    }
    text = json.dumps(meta, separators=(",", ":")) + "\n"
    write_atomic(_pe_meta_path(backup), text.encode("utf-8"))


class Backup:
    def __init__(self, buf, img, identity=None, build_id="", macho_identity="", legacy=False):
        self.buf = buf
        self.img = img
        self.identity = identity
        self.build_id = build_id
        self.macho_identity = macho_identity
        self.legacy = legacy
        self.size = len(buf)
        self.sha256 = sha256_bytes(buf)


def read_validated_backup_pe(backup):
    if not os.path.isfile(backup):
        raise Mv2Error(f"No backup found at: {backup}")
    buf = bytearray(read_file(backup))
    if len(buf) == 0:
        raise Mv2Error("The backup file is empty.")
    img = open_image(buf)
    identity = pe_identity(buf, img)
    meta_path = _pe_meta_path(backup)
    legacy = not os.path.isfile(meta_path)
    if not legacy:
        try:
            meta = json.loads(open(meta_path, "r", encoding="utf-8").read())
        except Exception:
            raise Mv2Error(f"The backup's info file looks wrong: {meta_path}")
        if (int(meta.get("Schema", 0)) != 1 or meta.get("Format") != identity["Format"] or
                int(meta.get("Machine", -1)) != identity["Machine"] or
                int(meta.get("TimeStamp", -1)) != identity["TimeStamp"] or
                int(meta.get("Length", -1)) != identity["Length"] or
                str(meta.get("SHA256", "")).lower() != identity["SHA256"]):
            raise Mv2Error("The backup doesn't match its saved info - it may be damaged.")
    b = Backup(buf, img, identity=identity, legacy=legacy)
    return b


def remove_backup_files(backup, meta_path):
    for p in (backup, meta_path):
        if os.path.isfile(p):
            try:
                os.remove(p)
            except Exception:
                warnf(f"Couldn't delete a backup file: {p}")


# ---- ELF / Mach-O key=value meta -------------------------------------------
def save_backup_meta_unix(backup, source, container, identity):
    os.makedirs(os.path.dirname(os.path.abspath(backup)) or ".", exist_ok=True)
    prev = sha256_file(backup) if os.path.isfile(backup) else ""
    data = read_file(source)
    write_atomic(backup, data, expected_current_hash=prev, known_hash=sha256_bytes(data))
    size = file_size(backup)
    h = sha256_file(backup)
    meta = _unix_meta_path(backup)
    if container == "elf":
        text = f"schema=1\ncontainer=elf\nbuild_id={identity}\nsize={size}\nsha256={h}\n"
    else:
        text = f"schema=1\ncontainer=macho\nidentity={identity}\nsize={size}\nsha256={h}\n"
    write_atomic(meta, text.encode("utf-8"))


def validate_backup_meta_unix(backup, container, build_id="", macho_identity=""):
    """Returns (ok, legacy). Mirrors validate_backup_snapshot's field checks."""
    if not os.path.isfile(backup):
        return False, False
    size = file_size(backup)
    h = sha256_file(backup)
    meta = _unix_meta_path(backup)
    if not os.path.isfile(meta):
        return True, True
    fields = {}
    try:
        for line in open(meta, "r", encoding="utf-8").read().splitlines():
            if line == "":
                continue
            if "=" not in line:
                return False, False
            key, value = line.split("=", 1)
            if "=" in value:
                return False, False
            fields[key] = value
    except Exception:
        return False, False
    if container == "elf":
        ok = (fields.get("schema") == "1" and fields.get("container") == "elf" and
              fields.get("build_id") == build_id and fields.get("size") == str(size) and
              fields.get("sha256") == h)
    else:
        ok = (fields.get("schema") == "1" and fields.get("container") == "macho" and
              fields.get("identity") == macho_identity and fields.get("size") == str(size) and
              fields.get("sha256") == h)
    return ok, False


# ============================================================================
# Host CPU (Mach-O). The universal framework carries two slices but only ONE
# runs on this Mac; patching the other edits code that never executes.
# ============================================================================
HOST_CONTAINER = ""


def detect_host_container():
    global HOST_CONTAINER
    forced = os.environ.get("MV2_TEST_HOST_ARCH", "")
    if forced in ("arm64", "aarch64"):
        HOST_CONTAINER = "macho-arm64"
        return
    if forced in ("x86_64", "amd64", "x64"):
        HOST_CONTAINER = "macho-x64"
        return
    try:
        out = subprocess.run(["sysctl", "-n", "hw.optional.arm64"], capture_output=True, text=True)
        if out.stdout.strip() == "1":
            HOST_CONTAINER = "macho-arm64"
            return
    except Exception:
        pass
    import platform
    HOST_CONTAINER = "macho-arm64" if platform.machine() in ("arm64", "aarch64") else "macho-x64"


def host_arch_label():
    return "Apple Silicon (arm64)" if HOST_CONTAINER == "macho-arm64" else "Intel (x86_64)"


def macho_identity_string(img):
    return ",".join(f"{s.container}:{s.uuid}" for s in img.slices)


def _format_uuid(h):
    if len(h) == 32:
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"
    return h


def macho_identity_token(identity_uuids):
    uuid = ""
    for pair in identity_uuids.split(","):
        if pair.startswith(HOST_CONTAINER + ":"):
            uuid = pair.split(":", 1)[1]
            break
    if not uuid and identity_uuids:
        uuid = identity_uuids.rsplit(":", 1)[-1]
    uuid = re.sub(r"[^0-9A-Fa-f]", "", uuid)
    if not uuid:
        uuid = hashlib.sha256(identity_uuids.encode()).hexdigest()[:32]
    return _format_uuid(uuid)


def slice_decision(container, satisfied, ties, full, allow_partial):
    """(ok, reason). An ELF slice is always eligible; a Mach-O slice only when it
    matches this Mac."""
    if satisfied == 0:
        return False, "Chrome version not recognized"
    if ties > 1:
        return False, "couldn't tell which Chrome version this is"
    if container not in ("elf", "elf-arm64") and HOST_CONTAINER != container:
        return False, "not the version your Mac runs"
    if not full and not allow_partial:
        return False, f"only {satisfied} changes matched; needs --allow-partial"
    return True, ""


# ============================================================================
# Common process/terminal helpers.
# ============================================================================
def prompt_read(prompt=""):
    """Read one line, from /dev/tty when stdin is not a terminal (the
    `curl … | python` case). Returns None on EOF/cancel."""
    if prompt:
        sys.stdout.write(prompt)
        sys.stdout.flush()
    try:
        if not sys.stdin.isatty() and os.path.exists("/dev/tty"):
            with open("/dev/tty", "r") as tty:
                line = tty.readline()
                if line == "":
                    return None
                return line.rstrip("\n")
        line = sys.stdin.readline()
        if line == "":
            return None
        return line.rstrip("\n")
    except Exception:
        return None


def select_browser_user_args(cmdline):
    """Keep the switches that say how the user starts this browser
    (--profile-directory, --user-data-dir, ...) and drop the ones that only
    describe the launch being replaced. Port of Select-BrowserUserArgs /
    capture_reopen_linux's filter. `cmdline` includes argv[0]; it is dropped."""
    toks = re.findall(r'(?:[^\s"]|"[^"]*")+', cmdline)
    keep = []
    in_block = False
    for tok in toks[1:]:
        if tok == "--flag-switches-begin":
            in_block = True
            continue
        if tok == "--flag-switches-end":
            in_block = False
            continue
        if in_block:
            continue
        if not tok.startswith("-"):
            continue
        if tok in ("--restart", "--no-startup-window", "--restore-last-session"):
            continue
        if tok.startswith("--original-process-start-time="):
            continue
        keep.append(tok)
    return keep


# Windows reopen state, captured while the browser is still running (see run()).
WIN_REOPEN_EXE = ""
WIN_REOPEN_ARGS = []


def test_dir_writable(target):
    d = os.path.dirname(os.path.abspath(target)) or os.getcwd()
    probe = os.path.join(d, ".chrome-mv2-write-probe-" + os.urandom(8).hex())
    try:
        fd = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
        return True
    except Exception:
        return False
    finally:
        try:
            if os.path.exists(probe):
                os.remove(probe)
        except Exception:
            pass


# ============================================================================
# Windows platform glue (ctypes). Every entry point degrades to a no-op off
# Windows so the engine still runs when patching a copied PE elsewhere.
# ============================================================================
if IS_WIN:
    import ctypes
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _u32 = ctypes.WinDLL("user32", use_last_error=True)
    _sh32 = ctypes.WinDLL("shell32", use_last_error=True)

    _k32.CreateFileW.restype = wintypes.HANDLE
    _k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                 wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.OpenProcess.restype = wintypes.HANDLE
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                                wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    _k32.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME),
                                     ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME),
                                     ctypes.POINTER(wintypes.FILETIME)]
    _sh32.IsUserAnAdmin.restype = wintypes.BOOL

    _INVALID_HANDLE = wintypes.HANDLE(-1).value
    CCH_RM_SESSION_KEY = 32

    class _PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]

    class _RM_UNIQUE_PROCESS(ctypes.Structure):
        _fields_ = [("dwProcessId", wintypes.DWORD), ("ProcessStartTime", wintypes.FILETIME)]

    class _RM_PROCESS_INFO(ctypes.Structure):
        _fields_ = [("Process", _RM_UNIQUE_PROCESS), ("strAppName", ctypes.c_wchar * 256),
                    ("strServiceShortName", ctypes.c_wchar * 64), ("ApplicationType", ctypes.c_int),
                    ("AppStatus", ctypes.c_uint), ("TSSessionId", ctypes.c_uint),
                    ("bRestartable", wintypes.BOOL)]

    def win_is_admin():
        try:
            return bool(_sh32.IsUserAnAdmin())
        except Exception:
            return False

    def is_file_locked(path):
        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        OPEN_EXISTING = 3
        FILE_ATTRIBUTE_NORMAL = 0x80
        h = _k32.CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, None,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
        if h and h != _INVALID_HANDLE:
            _k32.CloseHandle(h)
            return False
        err = ctypes.get_last_error()
        return err in (32, 33)  # SHARING_VIOLATION / LOCK_VIOLATION

    def rm_get_holders(path):
        try:
            rm = ctypes.WinDLL("rstrtmgr", use_last_error=True)
        except Exception:
            return []
        session = wintypes.DWORD(0)
        key = ctypes.create_unicode_buffer(CCH_RM_SESSION_KEY + 1)
        if rm.RmStartSession(ctypes.byref(session), 0, key) != 0:
            return []
        try:
            files = (ctypes.c_wchar_p * 1)(path)
            if rm.RmRegisterResources(session, 1, files, 0, None, 0, None) != 0:
                return []
            needed = wintypes.UINT(0)
            count = wintypes.UINT(0)
            reason = wintypes.UINT(0)
            rm.RmGetList(session, ctypes.byref(needed), ctypes.byref(count), None, ctypes.byref(reason))
            if needed.value == 0:
                return []
            info = (_RM_PROCESS_INFO * needed.value)()
            count = wintypes.UINT(needed.value)
            if rm.RmGetList(session, ctypes.byref(needed), ctypes.byref(count), info, ctypes.byref(reason)) != 0:
                return []
            out = []
            for i in range(count.value):
                pi = info[i]
                ft = ((pi.Process.ProcessStartTime.dwHighDateTime & 0xFFFFFFFF) << 32) | \
                     (pi.Process.ProcessStartTime.dwLowDateTime & 0xFFFFFFFF)
                out.append((int(pi.Process.dwProcessId), ft, pi.strAppName))
            return out
        finally:
            rm.RmEndSession(session)

    def _win_proc_path(pid):
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        h = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return None
        try:
            buf = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(32768)
            if _k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                return buf.value
            return None
        finally:
            _k32.CloseHandle(h)

    def _win_proc_start_ft(pid):
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        h = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return 0
        try:
            c = wintypes.FILETIME()
            e = wintypes.FILETIME()
            kn = wintypes.FILETIME()
            u = wintypes.FILETIME()
            if _k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(kn), ctypes.byref(u)):
                return ((c.dwHighDateTime & 0xFFFFFFFF) << 32) | (c.dwLowDateTime & 0xFFFFFFFF)
            return 0
        finally:
            _k32.CloseHandle(h)

    def _win_process_list():
        TH32CS_SNAPPROCESS = 0x2
        snap = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not snap or snap == _INVALID_HANDLE:
            return []
        out = []
        try:
            entry = _PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
            if not _k32.Process32FirstW(snap, ctypes.byref(entry)):
                return []
            while True:
                out.append((int(entry.th32ProcessID), entry.szExeFile.lower()))
                if not _k32.Process32NextW(snap, ctypes.byref(entry)):
                    break
        finally:
            _k32.CloseHandle(snap)
        return out

    def browser_exe_path(target_path):
        try:
            ver_dir = os.path.dirname(os.path.abspath(target_path))
            for d in (ver_dir, os.path.dirname(ver_dir)):
                if not d:
                    continue
                exe = os.path.join(d, "chrome.exe")
                if os.path.isfile(exe):
                    return exe
        except Exception:
            pass
        return ""

    def get_browser_processes(target_path):
        exe = browser_exe_path(target_path)
        exe_l = os.path.normcase(os.path.abspath(exe)) if exe else ""
        found = {}
        if exe:
            for pid, name in _win_process_list():
                if name not in ("chrome.exe", "chromium.exe"):
                    continue
                p = _win_proc_path(pid)
                if p and os.path.normcase(p) == exe_l:
                    found[pid] = True
        for (pid, start_ft, _app) in rm_get_holders(target_path):
            if pid in found:
                continue
            p = _win_proc_path(pid)
            if not p:
                continue
            base = os.path.basename(p).lower()
            if base not in ("chrome.exe", "chromium.exe"):
                continue
            if start_ft and _win_proc_start_ft(pid) and _win_proc_start_ft(pid) != start_ft:
                continue
            if exe and os.path.normcase(p) != exe_l:
                continue
            found[pid] = True
        return list(found.keys())

    _WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    _u32.EnumWindows.argtypes = [_WNDENUMPROC, wintypes.LPARAM]
    _u32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    _u32.IsWindowVisible.argtypes = [wintypes.HWND]
    _u32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]

    def _enum_owned_visible(pids, action):
        want = set(pids)
        n = [0]

        def cb(hwnd, _lparam):
            owner = wintypes.DWORD(0)
            _u32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
            if owner.value in want and _u32.IsWindowVisible(hwnd):
                if action(hwnd):
                    n[0] += 1
            return True
        _u32.EnumWindows(_WNDENUMPROC(cb), 0)
        return n[0]

    def close_windows(pids):
        WM_CLOSE = 0x0010
        return _enum_owned_visible(pids, lambda h: bool(_u32.PostMessageW(h, WM_CLOSE, 0, 0)))

    def count_windows(pids):
        return _enum_owned_visible(pids, lambda h: True)

    def _win_tick():
        return int(time.monotonic() * 1000)

    def wait_target_unlocked(target_path, timeout_ms):
        deadline = _win_tick() + timeout_ms
        while True:
            if not is_file_locked(target_path) and not get_browser_processes(target_path):
                return True
            if _win_tick() >= deadline:
                return False
            time.sleep(0.25)

    def close_file_holders(target_path):
        live = get_browser_processes(target_path)
        if not live:
            return wait_target_unlocked(target_path, 0)
        close_windows(live)
        deadline = _win_tick() + 15000
        windows_gone_at = 0
        while True:
            if wait_target_unlocked(target_path, 0):
                return True
            if _win_tick() >= deadline:
                break
            if count_windows(live) == 0:
                if windows_gone_at == 0:
                    windows_gone_at = _win_tick()
                elif _win_tick() - windows_gone_at >= 3000:
                    break
            else:
                windows_gone_at = 0
            time.sleep(0.25)
        warnf("Chrome is not closing on its own - closing it the hard way.")
        for pid in get_browser_processes(target_path):
            try:
                h = _k32.OpenProcess(0x0001, False, pid)  # PROCESS_TERMINATE
                if h:
                    _k32.TerminateProcess(h, 1)
                    _k32.CloseHandle(h)
            except Exception:
                pass
        return wait_target_unlocked(target_path, 5000)

    def _quoted(s):
        if s == "" or re.search(r'[\s"]', s):
            return '"' + s.replace('"', '\\"') + '"'
        return s

    def self_elevate(argv_after_script):
        """Re-launch this .py elevated via ShellExecuteEx 'runas'; wait; return the
        child's exit code, or None if elevation was declined/impossible."""
        sp = script_path()
        if not sp or not os.path.isfile(sp):
            warnf("Cannot ask for administrator access this way; re-run from an admin terminal.")
            return None

        class SHELLEXECUTEINFOW(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong),
                        ("hwnd", wintypes.HWND), ("lpVerb", wintypes.LPCWSTR),
                        ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                        ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int),
                        ("hInstApp", wintypes.HINSTANCE), ("lpIDList", wintypes.LPVOID),
                        ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                        ("dwHotKey", wintypes.DWORD), ("hIcon", wintypes.HANDLE),
                        ("hProcess", wintypes.HANDLE)]
        params = " ".join([_quoted(sp)] + argv_after_script + ["--relaunched"])
        SEE_MASK_NOCLOSEPROCESS = 0x00000040
        info = SHELLEXECUTEINFOW()
        info.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
        info.fMask = SEE_MASK_NOCLOSEPROCESS
        info.lpVerb = "runas"
        info.lpFile = sys.executable
        info.lpParameters = params
        info.lpDirectory = os.getcwd()
        info.nShow = 1
        infof("Asking for admin access...")
        _sh32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
        _sh32.ShellExecuteExW.restype = wintypes.BOOL
        if not _sh32.ShellExecuteExW(ctypes.byref(info)) or not info.hProcess:
            warnf("Admin access was declined - nothing was changed.")
            return None
        _k32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)
        code = wintypes.DWORD(0)
        _k32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
        _k32.CloseHandle(info.hProcess)
        return int(code.value)

    def _win_create_shortcut(lnk, target, arguments, workdir):
        """Create a .lnk via IShellLinkW + IPersistFile (pure ctypes COM)."""
        ole = ctypes.WinDLL("ole32")

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                        ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]

            def __init__(self, s):
                super().__init__()
                ole.CLSIDFromString(s, ctypes.byref(self))
        CLSID_ShellLink = GUID("{00021401-0000-0000-C000-000000000046}")
        IID_IShellLinkW = GUID("{000214F9-0000-0000-C000-000000000046}")
        IID_IPersistFile = GUID("{0000010B-0000-0000-C000-000000000046}")
        CLSCTX_INPROC_SERVER = 1
        ole.CoInitialize(None)
        try:
            psl = ctypes.c_void_p()
            if ole.CoCreateInstance(ctypes.byref(CLSID_ShellLink), None, CLSCTX_INPROC_SERVER,
                                    ctypes.byref(IID_IShellLinkW), ctypes.byref(psl)) != 0:
                return False

            def vcall(ptr, index, argtypes, *args):
                vtbl = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_void_p))[0]
                fp = ctypes.cast(vtbl, ctypes.POINTER(ctypes.c_void_p))[index]
                proto = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, *argtypes)
                return proto(fp)(ptr, *args)
            try:
                # IShellLinkW: 20 SetPath, 9 SetWorkingDirectory, 11 SetArguments
                if vcall(psl, 20, [wintypes.LPCWSTR], target) != 0:
                    return False
                vcall(psl, 9, [wintypes.LPCWSTR], workdir)
                vcall(psl, 11, [wintypes.LPCWSTR], arguments)
                ppf = ctypes.c_void_p()
                # IShellLinkW::QueryInterface (index 0) -> IPersistFile
                if vcall(psl, 0, [ctypes.c_void_p, ctypes.c_void_p],
                         ctypes.byref(IID_IPersistFile), ctypes.byref(ppf)) != 0:
                    return False
                try:
                    # IPersistFile::Save (index 6)
                    ok = vcall(ppf, 6, [wintypes.LPCWSTR, wintypes.BOOL], lnk, True) == 0
                finally:
                    vcall(ppf, 2, [])  # Release
                return ok
            finally:
                vcall(psl, 2, [])  # Release
        finally:
            ole.CoUninitialize()

    def start_as_desktop_user(exe, arguments):
        """From an elevated process, launch as the desktop user by having
        explorer.exe open a shortcut that carries the args (so Chrome does NOT
        inherit our admin token)."""
        lnk = os.path.join(tempfile.gettempdir(), "chrome-mv2-reopen-" + os.urandom(8).hex() + ".lnk")
        try:
            if not _win_create_shortcut(lnk, exe, arguments, os.path.dirname(exe)):
                return False
        except Exception:
            return False
        ok = True
        try:
            subprocess.Popen(["explorer.exe", lnk])
            time.sleep(2)
        except Exception:
            ok = False
        try:
            os.remove(lnk)
        except Exception:
            pass
        return ok

    class _PROCESS_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [("Reserved1", ctypes.c_void_p), ("PebBaseAddress", ctypes.c_void_p),
                    ("Reserved2", ctypes.c_void_p * 2), ("UniqueProcessId", ctypes.c_void_p),
                    ("Reserved3", ctypes.c_void_p)]

    _k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID,
                                       ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    _k32.ReadProcessMemory.restype = wintypes.BOOL

    def win_read_process_cmdline(pid):
        """The full command line of a process, read from its PEB (read-only).
        64-bit host reading a 64-bit target; returns '' on any failure."""
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            return ""
        try:
            nt = ctypes.WinDLL("ntdll", use_last_error=True)
        except Exception:
            return ""
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        h = _k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h:
            return ""
        try:
            pbi = _PROCESS_BASIC_INFORMATION()
            if nt.NtQueryInformationProcess(h, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None) != 0:
                return ""
            if not pbi.PebBaseAddress:
                return ""

            def rd(addr, size):
                buf = (ctypes.c_char * size)()
                n = ctypes.c_size_t(0)
                if not _k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(n)):
                    return None
                return buf.raw[:n.value]
            pp = rd(pbi.PebBaseAddress + 0x20, 8)         # PEB.ProcessParameters
            if not pp or len(pp) < 8:
                return ""
            params = int.from_bytes(pp, "little")
            hdr = rd(params + 0x70, 16)                   # RTL_..._PARAMETERS.CommandLine (UNICODE_STRING)
            if not hdr or len(hdr) < 16:
                return ""
            length = int.from_bytes(hdr[0:2], "little")
            buffer = int.from_bytes(hdr[8:16], "little")
            if not length or not buffer:
                return ""
            raw = rd(buffer, length)
            if not raw:
                return ""
            return raw.decode("utf-16-le", "replace")
        finally:
            _k32.CloseHandle(h)

    def capture_reopen_win(target_path):
        """Record the launcher and the user's flags before the browser is closed,
        so the reopen keeps its profile. Best effort: '' args on any failure."""
        global WIN_REOPEN_EXE, WIN_REOPEN_ARGS
        WIN_REOPEN_EXE = browser_exe_path(target_path)
        WIN_REOPEN_ARGS = []
        for pid in get_browser_processes(target_path):
            cl = win_read_process_cmdline(pid)
            if not cl or "--type=" in cl:
                continue                                  # child process, not the browser
            WIN_REOPEN_ARGS = select_browser_user_args(cl)
            return True
        return False

else:
    def win_is_admin():
        return False

    def is_file_locked(path):
        return False

    def get_browser_processes(target_path):
        return []

    def browser_exe_path(target_path):
        return ""

    def close_file_holders(target_path):
        return True

    def self_elevate(argv_after_script):
        return None

    def capture_reopen_win(target_path):
        return False


# ============================================================================
# Linux platform glue - /proc process handling, reopen with the captured session.
# ============================================================================
def linux_pids_holding(binary):
    want = binary
    try:
        want = os.path.realpath(binary)
    except Exception:
        pass
    pids = []
    for exe in glob.glob("/proc/[0-9]*/exe"):
        try:
            target = os.readlink(exe)
        except Exception:
            continue
        if target in (want, binary, want + " (deleted)", binary + " (deleted)"):
            pid = exe[len("/proc/"):].split("/", 1)[0]
            pids.append(int(pid))
    return pids


def linux_proc_holders(binary):
    return len(linux_pids_holding(binary))


REOPEN_ARGV = []
REOPEN_ENV = []
REOPEN_UID = ""


def capture_reopen_linux(binary):
    global REOPEN_ARGV, REOPEN_ENV, REOPEN_UID
    REOPEN_ARGV = []
    REOPEN_ENV = []
    REOPEN_UID = ""
    for pid in linux_pids_holding(binary):
        cmdline_path = f"/proc/{pid}/cmdline"
        if not os.access(cmdline_path, os.R_OK):
            continue
        try:
            raw = open(cmdline_path, "rb").read()
        except Exception:
            continue
        args = [a.decode("utf-8", "replace") for a in raw.split(b"\x00") if a]
        if not args:
            continue
        if any(a.startswith("--type=") for a in args):
            continue
        argv = [args[0]]
        in_flag_block = False
        for a in args[1:]:
            if a == "--flag-switches-begin":
                in_flag_block = True
                continue
            if a == "--flag-switches-end":
                in_flag_block = False
                continue
            if in_flag_block:
                continue
            if a in ("--restart", "--no-startup-window", "--restore-last-session"):
                continue
            if a.startswith("--original-process-start-time="):
                continue
            if a.startswith("-"):
                argv.append(a)
        REOPEN_ARGV = argv
        try:
            REOPEN_UID = str(os.stat(f"/proc/{pid}").st_uid)
        except Exception:
            REOPEN_UID = ""
        keep = ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS",
                "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP", "HOME",
                "USER", "LOGNAME", "LANG", "CHROME_WRAPPER", "CHROME_DESKTOP", "CHROME_VERSION_EXTRA")
        try:
            env_raw = open(f"/proc/{pid}/environ", "rb").read()
            for kv in env_raw.split(b"\x00"):
                if not kv:
                    continue
                s = kv.decode("utf-8", "replace")
                if s.split("=", 1)[0] in keep:
                    REOPEN_ENV.append(s)
        except Exception:
            pass
        return True
    return False


def kill_chrome_processes(binary):
    import signal
    for pid in linux_pids_holding(binary):
        try:
            os.kill(pid, signal.SIGTERM)
        except Exception:
            pass
    for _ in range(60):
        if linux_proc_holders(binary) == 0:
            return True
        time.sleep(0.25)
    warnf("Chrome is not closing on its own - closing it the hard way.")
    for pid in linux_pids_holding(binary):
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
    for _ in range(20):
        if linux_proc_holders(binary) == 0:
            return True
        time.sleep(0.25)
    return False


def reopen_browser_linux(binary):
    if not REOPEN_ARGV:
        return False
    argv = list(REOPEN_ARGV) + ["--restore-last-session"]
    runner = []
    if os.geteuid() == 0 and REOPEN_UID and REOPEN_UID != "0":
        if not shutil.which("sudo"):
            return False
        runner = ["sudo", "-u", "#" + REOPEN_UID, "--"]
    launcher = []
    if shutil.which("setsid"):
        launcher = ["setsid"]
    elif shutil.which("nohup"):
        launcher = ["nohup"]
    env_prefix = ["env"] + REOPEN_ENV
    try:
        subprocess.Popen(launcher + runner + env_prefix + argv,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         stdin=subprocess.DEVNULL, start_new_session=True)
    except Exception:
        return False
    for _ in range(60):
        if linux_proc_holders(binary) > 0:
            return True
        time.sleep(0.25)
    return False


# ============================================================================
# macOS platform glue - process handling, reopen, inside-out ad-hoc re-sign.
# ============================================================================
def macos_proc_holders_app(app):
    if not shutil.which("pgrep"):
        return 0
    try:
        r = subprocess.run(["pgrep", "-f", f"{app}/Contents/MacOS/"], capture_output=True, text=True)
        return len([l for l in r.stdout.splitlines() if l.strip()])
    except Exception:
        return 0


def macos_quit_app(app):
    if shutil.which("osascript"):
        try:
            subprocess.run(["osascript", "-e", f'quit app "{app}"'], capture_output=True)
        except Exception:
            pass
    for _ in range(60):
        if macos_proc_holders_app(app) == 0:
            return True
        time.sleep(0.25)
    warnf("Chrome is not closing on its own - closing it the hard way.")
    if shutil.which("pkill"):
        try:
            subprocess.run(["pkill", "-f", f"{app}/Contents/MacOS/"], capture_output=True)
        except Exception:
            pass
    for _ in range(20):
        if macos_proc_holders_app(app) == 0:
            return True
        time.sleep(0.25)
    return False


def reopen_browser_macos(app):
    if not shutil.which("open"):
        return False
    try:
        if os.geteuid() == 0 and os.environ.get("SUDO_USER"):
            subprocess.run(["sudo", "-u", os.environ["SUDO_USER"], "--", "open", "-a", app,
                            "--args", "--restore-last-session"], capture_output=True)
        else:
            subprocess.run(["open", "-a", app, "--args", "--restore-last-session"], capture_output=True)
    except Exception:
        return False
    for _ in range(60):
        if macos_proc_holders_app(app) > 0:
            return True
        time.sleep(0.25)
    return False


def have_codesign():
    return bool(shutil.which("codesign"))


def _resign_one(comp):
    q = subprocess.DEVNULL if not os.environ.get("MV2_DEBUG_SIGN") else None
    r = subprocess.run(["codesign", "--force", "--sign", "-",
                        "--preserve-metadata=entitlements,flags", comp], stderr=q)
    if r.returncode == 0:
        return True
    r = subprocess.run(["codesign", "--force", "--sign", "-", comp], stderr=q)
    if r.returncode == 0:
        return True
    errf(f"Couldn't re-sign part of the app: {comp}")
    return False


def resign_inside_out(app_path):
    if not app_path or not os.path.isdir(app_path):
        errf(f"Couldn't find the app to re-sign: {app_path}")
        return False
    infof("Re-signing the app so it opens normally...")
    items = []
    for root, dirs, files in os.walk(app_path):
        for name in dirs:
            if name.endswith((".app", ".framework", ".xpc")):
                items.append(os.path.join(root, name))
        for name in files:
            p = os.path.join(root, name)
            if name.endswith((".dylib", ".so")) or "/MacOS/" in p or "/Helpers/" in p or "/Libraries/" in p:
                items.append(p)
    items = sorted(set(items), key=lambda p: p.count("/"), reverse=True)
    rc = True
    for p in items:
        if p == app_path:
            continue
        if p.startswith(app_path + "/Contents/MacOS/"):
            continue
        if os.path.isfile(p) and detect_container_file(p) != "macho":
            continue
        if not _resign_one(p):
            rc = False
    if not _resign_one(app_path):
        rc = False
    return rc


def verify_signature(app_path):
    if app_path and os.path.isdir(app_path):
        return subprocess.run(["codesign", "--verify", "--deep", "--strict", app_path],
                              capture_output=True).returncode == 0
    return True


def macos_app_version(app):
    plist = os.path.join(app, "Contents", "Info.plist")
    if not os.path.isfile(plist):
        return ""
    if shutil.which("defaults"):
        r = subprocess.run(["defaults", "read", os.path.join(app, "Contents", "Info"),
                            "CFBundleShortVersionString"], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.strip()
    if shutil.which("plutil"):
        r = subprocess.run(["plutil", "-extract", "CFBundleShortVersionString", "raw", "-o", "-", plist],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.strip()
    return ""


def resolve_framework_from_app(app):
    fw = ""
    for d in glob.glob(os.path.join(app, "Contents", "Frameworks", "*Framework.framework")):
        if os.path.isdir(d):
            fw = d
            break
    if not fw:
        return None
    base = os.path.basename(fw)[:-len(".framework")]
    versions = os.path.join(fw, "Versions")
    vdir = ""
    if os.path.isdir(versions):
        for v in sorted(glob.glob(os.path.join(versions, "*"))):
            if not os.path.isdir(v) or os.path.islink(v) or os.path.basename(v) == "Current":
                continue
            vdir = v
    if vdir and os.path.isfile(os.path.join(vdir, base)):
        target_file = os.path.join(vdir, base)
    elif os.path.isfile(os.path.join(versions, "Current", base)):
        target_file = os.path.join(versions, "Current", base)
    else:
        return None
    return fw, target_file


def support_base():
    if os.access("/Library/Application Support", os.W_OK):
        return "/Library/Application Support"
    return os.path.join(os.environ.get("HOME", "/tmp"), "Library", "Application Support")


# ============================================================================
# Install discovery + interactive selection.
# ============================================================================
WIN_CHANNELS = [("Stable", r"Google\Chrome"), ("Beta", r"Google\Chrome Beta"),
                ("Dev", r"Google\Chrome Dev"), ("Canary", r"Google\Chrome SxS"),
                ("Chromium", "Chromium")]

LINUX_CHANNELS = ["Stable", "Beta", "Dev"]
LINUX_DIRS = ["/opt/google/chrome", "/opt/google/chrome-beta", "/opt/google/chrome-unstable"]
CHROMIUM_BINS = ["/usr/lib/chromium/chromium", "/usr/lib/chromium/chrome",
                 "/usr/lib/chromium-browser/chromium-browser", "/usr/lib/chromium-browser/chrome",
                 "/usr/lib64/chromium/chromium", "/usr/lib64/chromium-browser/chromium-browser",
                 "/opt/chromium.org/chromium/chrome", "/opt/chromium/chrome"]
MAC_APPS = ["Google Chrome.app", "Google Chrome Beta.app", "Google Chrome Dev.app",
            "Google Chrome Canary.app", "Chromium.app"]
MAC_LABELS = ["Stable", "Beta", "Dev", "Canary", "Chromium"]


def display_name(channel):
    if channel in ("Stable", "Beta", "Dev", "Canary"):
        return f"Chrome {channel}"
    return channel


def looks_like_version(name):
    parts = name.split(".")
    if len(parts) < 3:
        return False
    return all(p.isdigit() for p in parts)


def _version_lt(a, b):
    pa = [int(re.sub(r"\D", "0", x) or 0) for x in a.split(".")]
    pb = [int(re.sub(r"\D", "0", x) or 0) for x in b.split(".")]
    for i in range(4):
        x = pa[i] if i < len(pa) else 0
        y = pb[i] if i < len(pb) else 0
        if x != y:
            return x < y
    return False


def find_dll_under_application(app_dir):
    if os.path.isdir(app_dir):
        best = ""
        for entry in os.listdir(app_dir):
            full = os.path.join(app_dir, entry)
            if not os.path.isdir(full):
                continue
            if (best == "" or _version_lt(best, entry)) and \
               os.path.isfile(os.path.join(full, "chrome.dll")):
                best = entry
        if best:
            return os.path.join(app_dir, best, "chrome.dll")
    direct = os.path.join(app_dir, "chrome.dll")
    return direct if os.path.isfile(direct) else ""


def pe_state_quick(path):
    try:
        with open(path, "rb") as f:
            hdr = f.read(8192)
        if len(hdr) < 64 or hdr[0] != 0x4D or hdr[1] != 0x5A:
            return ""
        e = int.from_bytes(hdr[0x3C:0x40], "little")
        if e + 24 > len(hdr) or hdr[e:e + 2] != b"PE":
            return ""
        opt = e + 24
        magic = int.from_bytes(hdr[opt:opt + 2], "little")
        fixed = 112 if magic == 0x20B else (96 if magic == 0x10B else 0)
        if not fixed:
            return ""
        sd = opt + fixed + 4 * 8
        if sd + 8 > len(hdr):
            return ""
        va = int.from_bytes(hdr[sd:sd + 4], "little")
        sz = int.from_bytes(hdr[sd + 4:sd + 8], "little")
        return "not patched" if (va and sz) else "patched"
    except Exception:
        return ""


def elf_state_quick(path, milestones):
    try:
        buf = bytearray(read_file(path))
        img = open_elf(buf)
    except Exception:
        return ""
    best = _probe_pass(buf, img.slices[0], [m for m in milestones if m.container == img.slices[0].container], fast_only=True)
    if best is None or best.satisfied == 0 or best.ties > 1:
        return ""
    try:
        stock, patched = classify_flip_states(buf, best.flips)
    except Exception:
        return ""
    if stock > 0 and patched == 0:
        return "not patched"
    if stock == 0 and patched > 0:
        return "patched"
    return ""


def channel_from_path(target_path):
    hay = "\\" + target_path.replace("/", "\\").strip("\\").lower() + "\\"
    for name, subdir in WIN_CHANNELS:
        if ("\\" + subdir.lower() + "\\") in hay:
            return name
    return "Unknown"


def win_installs(milestones):
    found = []
    seen = set()
    roots = []
    for var in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        val = os.environ.get(var)
        if val:
            roots.append(val)
    for name, subdir in WIN_CHANNELS:
        for root in roots:
            dll = find_dll_under_application(os.path.join(root, subdir, "Application"))
            if not dll:
                continue
            key = dll.lower()
            if key in seen:
                continue
            seen.add(key)
            parent = os.path.basename(os.path.dirname(dll))
            ver = parent if looks_like_version(parent) else ""
            found.append({"channel": name, "path": dll, "version": ver,
                          "state": pe_state_quick(dll), "container": "pe"})
    if not found and os.path.isfile("./chrome.dll"):
        found.append({"channel": "Local file", "path": os.path.abspath("./chrome.dll"),
                      "version": "", "state": pe_state_quick("./chrome.dll"), "container": "pe"})
    return found


def linux_chrome_version(binary):
    pkg = {"/opt/google/chrome/chrome": "google-chrome-stable",
           "/opt/google/chrome-beta/chrome": "google-chrome-beta",
           "/opt/google/chrome-unstable/chrome": "google-chrome-unstable"}.get(binary)
    ver_re = re.compile(r"\d+\.\d+\.\d+\.\d+")

    def first(text):
        m = ver_re.search(text or "")
        return m.group(0) if m else ""
    if pkg and shutil.which("dpkg-query"):
        r = subprocess.run(["dpkg-query", "-W", "-f=${Version}\n", pkg], capture_output=True, text=True)
        v = first(r.stdout)
        if v:
            return v
    if pkg and shutil.which("rpm"):
        r = subprocess.run(["rpm", "-q", "--qf", "%{VERSION}\n", pkg], capture_output=True, text=True)
        v = first(r.stdout)
        if v:
            return v
    for tool, args in (("dpkg-query", ["-W", "-f=${Version}\n"]), ("rpm", ["-q", "--qf", "%{VERSION}\n"])):
        if shutil.which(tool):
            for p in ("chromium", "chromium-browser"):
                r = subprocess.run([tool] + args + [p], capture_output=True, text=True)
                v = first(r.stdout)
                if v:
                    return v
    if os.access(binary, os.X_OK):
        try:
            r = subprocess.run([binary, "--version"], capture_output=True, text=True)
            return first(r.stdout)
        except Exception:
            pass
    return ""


def linux_installs(milestones):
    found = []
    seen = set()
    entries = [(lbl, os.path.join(d, "chrome")) for lbl, d in zip(LINUX_CHANNELS, LINUX_DIRS)]
    entries += [("Chromium", b) for b in CHROMIUM_BINS]
    for label, binary in entries:
        if not os.path.isfile(binary):
            continue
        try:
            open_elf(bytearray(read_file(binary)))
        except Exception:
            continue
        rp = os.path.realpath(binary)
        if rp in seen:
            continue
        seen.add(rp)
        found.append({"channel": label, "path": binary, "version": linux_chrome_version(binary),
                      "state": elf_state_quick(binary, milestones), "container": "elf"})
    return found


def macos_installs(milestones):
    found = []
    for root in ("/Applications", os.path.join(os.environ.get("HOME", ""), "Applications")):
        for i, appname in enumerate(MAC_APPS):
            app = os.path.join(root, appname)
            if not os.path.isdir(app):
                continue
            found.append({"channel": MAC_LABELS[i], "path": app, "app_path": app,
                          "version": macos_app_version(app), "state": "", "container": "macho"})
    return found


def print_install_table(installs):
    print("")
    print(f"{C['bold']}  #  Browser          Version             Status{C['reset']}")
    for i, inst in enumerate(installs):
        status = ""
        if inst.get("state") == "patched":
            status = f"{C['grn']}Patched{C['reset']}"
        elif inst.get("state") == "not patched":
            status = f"{C['dim']}Not patched{C['reset']}"
        print("  %-2s %-17s%-20s%s" % (i + 1, display_name(inst["channel"]), inst.get("version") or "", status))


def read_custom_path():
    while True:
        line = prompt_read(f"{C['bold']}Enter the full path to the Chrome file, blank to cancel: {C['reset']}")
        if line is None:
            return None
        line = line.strip()
        if len(line) >= 2 and ((line[0] == '"' and line[-1] == '"') or (line[0] == "'" and line[-1] == "'")):
            line = line[1:-1]
        line = line.strip()
        if not line:
            return None
        if not os.path.isfile(line):
            errf("That's not a file. Try again, or leave blank to cancel.")
            continue
        return line


def select_install(installs, cmd):
    """Returns (chosen_install_or_path, cmd). chosen may be a dict (an install),
    a str (a custom path), or None to quit. cmd may switch to 'restore'."""
    count = len(installs)
    infof(f"Found {count} browser{'s' if count != 1 else ''}.")
    print_install_table(installs)
    verb = {"check": "Check", "restore": "Restore"}.get(cmd, "Patch")
    allow_restore = cmd == "patch"
    rng = "1" if count == 1 else f"1-{count}"
    print("")
    print(f"{C['bold']}Select command:{C['reset']}")
    print("")
    print(f"  [{rng}]  {verb} browser")
    if allow_restore:
        print("  [r]    Restore patched")
    print("  [c]    Use custom path")
    print("  [q]    Quit")
    while True:
        line = prompt_read(f"\n{C['bold']}Choice: {C['reset']}")
        if line is None:
            return None, cmd
        line = line.strip()
        if line in ("q", "Q"):
            return None, cmd
        if allow_restore and line in ("r", "R"):
            cmd = "restore"
            if count == 1:
                return installs[0], cmd
            while True:
                rl = prompt_read(f"\n{C['bold']}Restore which browser? [1-{count}, q=cancel]: {C['reset']}")
                if rl is None or rl.strip() in ("q", "Q"):
                    infof("Restore cancelled.")
                    return None, cmd
                if rl.strip().isdigit() and 1 <= int(rl) <= count:
                    return installs[int(rl) - 1], cmd
                errf(f"Enter a number between 1 and {count}, or q to cancel.")
        if line in ("c", "C"):
            p = read_custom_path()
            if p:
                return p, cmd
            continue
        if count == 1 and line == "":
            return installs[0], cmd
        if line.isdigit() and 1 <= int(line) <= count:
            return installs[int(line) - 1], cmd
        hint = "r to restore, " if allow_restore else ""
        if count == 1:
            errf(f"Press Enter to accept, {hint}c for a custom path, or q to quit.")
        else:
            errf(f"Enter a number between 1 and {count}, {hint}c for a custom path, or q to quit.")


# ============================================================================
# Target model + resolution.
# ============================================================================
class Target:
    def __init__(self, path, container, channel="", version="", app_path="", framework_bundle=""):
        self.path = path
        self.container = container
        self.channel = channel
        self.version = version
        self.app_path = app_path
        self.framework_bundle = framework_bundle


def target_label(target):
    n = display_name(target.channel)
    if not n or n == "Unknown":
        return "the browser"
    return n


def resolve_macho_target(path):
    """Returns (app_path, framework_bundle, target_file) or raises."""
    if os.path.isdir(path) and path.endswith(".app"):
        res = resolve_framework_from_app(path)
        if not res:
            raise Mv2Error(f"Couldn't find Chrome inside {path}")
        fw, tf = res
        return path, fw, tf
    if os.path.isdir(path) and path.endswith(".framework"):
        base = os.path.basename(path)[:-len(".framework")]
        cur = os.path.join(path, "Versions", "Current", base)
        if os.path.isfile(cur):
            return "", path, cur
        raise Mv2Error(f"Couldn't find Chrome inside {path}")
    if os.path.isfile(path):
        return "", "", path       # a loose Mach-O
    raise Mv2Error(f"That's not a Chrome app or file: {path}")


def resolve_any_target(path):
    if os.path.isdir(path):
        if path.endswith((".app", ".framework")):
            app, fw, tf = resolve_macho_target(path)
            return Target(tf, "macho", app_path=app, framework_bundle=fw)
        raise Mv2Error(f"That folder isn't a Chrome app: {path}")
    if os.path.isfile(path):
        kind = detect_container_file(path)
        if kind == "elf":
            return Target(path, "elf", channel=channel_from_path(path) if IS_WIN else "")
        if kind == "pe":
            return Target(path, "pe", channel=channel_from_path(path))
        if kind == "macho":
            app, fw, tf = resolve_macho_target(path)
            return Target(tf, "macho", app_path=app, framework_bundle=fw)
        raise Mv2Error(f"That doesn't look like a Chrome file: {path}")
    raise Mv2Error(f"That path doesn't exist: {path}")


# ============================================================================
# Orchestration - PE (Windows).
# ============================================================================
def pe_request_unlock(target, assume_yes, quiet, no_reopen):
    if not is_file_locked(target.path) and not get_browser_processes(target.path):
        return True
    label = target_label(target)
    if quiet and not assume_yes:
        errf(f"Can't make the change while {label} is open.")
        print("    Close it, or add -y/--yes to close it automatically.")
        return False
    infof(f"Closing {label} to make the change..." if no_reopen
          else f"Closing {label} - it reopens with the same tabs when this is done...")
    if close_file_holders(target.path):
        okf(f"Closed {label}. Your other browsers are still running.")
        return True
    errf(f"Couldn't close {label}.")
    return False


def cmd_patch_pe(target, milestones, assume_yes, allow_partial, no_reopen, quiet):
    infof("Checking chrome.dll...")
    buf = bytearray(read_file(target.path))
    if len(buf) == 0:
        errf("That file is empty.")
        return 1
    img = open_pe(buf)
    ver = target.version
    ident = pe_identity(buf, img)
    thash = ident["SHA256"]
    ms = [m for m in milestones if m.container == img.slices[0].container]
    if not ms:
        warnf("This kind of Chrome isn't supported yet - nothing was changed.")
        report_layout_candidates(buf, img.slices[0])
        return 1
    infof("Searching for MV2 signatures...")
    recognized = patch_milestones(buf, img.slices[0], ms, allow_partial=allow_partial, apply=False, version=ver)
    if recognized.status != 0 and not recognized.reason:
        okf(f"Found matching signatures ({recognized.milestone}, {recognized.located} gates).")

    backup = backup_path(target.path)
    if not os.path.isfile(backup):
        if not test_likely_stock_pe(img, buf):
            errf("There's no backup yet, and this Chrome has already been changed.")
            print("    Reinstall Chrome first so we can save a clean backup.")
            return 1
        clean, _ = get_clean_stock(buf, img.slices[0], ms, allow_partial)
        if not clean:
            errf("There's no backup yet, and this doesn't look like an untouched Chrome.")
            return 1
        infof("Creating backup...")
        save_backup_pe(target.path, backup, buf, ident)
        bk = read_validated_backup_pe(backup)
    else:
        try:
            bk = read_validated_backup_pe(backup)
        except Mv2Error as e:
            errf(f"The backup couldn't be verified: {e}")
            return 1
        if not test_likely_stock_pe(bk.img, bk.buf):
            errf("The backup doesn't look like an original Chrome, so I won't use it.")
            return 1
        clean, _ = get_clean_stock(bk.buf, bk.img.slices[0], ms, allow_partial)
        if not clean:
            errf("The backup doesn't look like an untouched Chrome.")
            return 1
        if not pe_same_build(ident, bk.identity):
            if not test_likely_stock_pe(img, buf):
                errf("Chrome was updated, but this copy has already been changed.")
                print("    Reinstall or update Chrome so we can start from a clean copy.")
                return 1
            nclean, _ = get_clean_stock(buf, img.slices[0], ms, allow_partial)
            if not nclean:
                errf("This updated Chrome isn't fully supported yet.")
                return 1
            infof("Chrome was updated - saving a fresh backup...")
            save_backup_pe(target.path, backup, buf, ident)
            bk = read_validated_backup_pe(backup)
        elif bk.legacy:
            save_backup_pe(target.path, backup, bk.buf, bk.identity)

    buf = bytearray(bk.buf)
    img = open_pe(buf)
    infof("Applying patch...")
    patch = patch_milestones(buf, img.slices[0], ms, allow_partial=allow_partial, apply=True, version=ver)
    if patch.status == 0:
        errf("Something went wrong while preparing the change - nothing was changed.")
        return 1
    okf("Patch applied successfully." if patch.status == 1 else "Chrome was already patched (no change needed).")
    complete_pe_image(img, buf)
    if not test_patch_output(buf, patch):
        errf("Something went wrong while preparing the change - nothing was changed.")
        return 1
    prepared_hash = sha256_bytes(buf)
    if prepared_hash == thash:
        successf("Already done - no change was needed.")
        return 0
    if thash != bk.identity["SHA256"]:
        errf("This Chrome has other changes we didn't make, so we won't overwrite it.")
        print("    Reinstall Chrome, or check the file yourself, then try again.")
        return 1
    if not pe_request_unlock(target, assume_yes, quiet, no_reopen):
        errf("Chrome is still open - close it and try again.")
        return 1
    write_atomic(target.path, bytes(buf), expected_current_hash=thash,
                 preserve_from=target.path, known_hash=prepared_hash)
    if patch.full:
        okf("Manifest V2 is enabled.")
    else:
        print(f"{TAG['warning']} Only part of the change was applied ({patch.located}/{patch.total}).")
        print(f"          {patch.total - patch.located} part(s) couldn't be found, so this may not fully work.")
        print("          Please report your Chrome version. To undo: python chrome-mv2.py restore")
    return 0


def cmd_restore_pe(target, milestones, assume_yes, force_restore, quiet, no_reopen):
    infof("Checking backup...")
    backup = backup_path(target.path)
    if not os.path.isfile(backup):
        errf("No backup found, so there's nothing to restore.")
        return 1
    try:
        bk = read_validated_backup_pe(backup)
    except Mv2Error as e:
        errf(f"The backup couldn't be verified: {e}")
        return 1
    if not test_likely_stock_pe(bk.img, bk.buf):
        errf("The backup doesn't look like an original Chrome, so I won't use it.")
        return 1
    ms = [m for m in milestones if m.container == bk.img.slices[0].container]
    clean, _ = get_clean_stock(bk.buf, bk.img.slices[0], ms, allow_partial=True)
    if not clean:
        errf("The backup doesn't look like an untouched Chrome.")
        return 1
    okf("Backup found.")
    current = bytearray(read_file(target.path))
    cur_img = open_pe(current)
    cur_ident = pe_identity(current, cur_img)
    if not pe_same_build(cur_ident, bk.identity) and not force_restore:
        errf("This backup is from a different Chrome version, so I won't use it.")
        print("    Add --force-restore only if you really mean to go back to that version.")
        return 1
    if not pe_same_build(cur_ident, bk.identity):
        warnf("Restoring a different Chrome version (--force-restore).")
    if cur_ident["SHA256"] == bk.identity["SHA256"]:
        successf("Chrome is already the original - nothing to undo.")
        remove_backup_files(backup, _pe_meta_path(backup))
        infof("Backup removed - Chrome is back to normal.")
        return 0
    if not pe_request_unlock(target, assume_yes, quiet, no_reopen):
        errf("Chrome is still open - close it and try again.")
        return 1
    infof("Restoring chrome.dll...")
    write_atomic(target.path, bytes(bk.buf), expected_current_hash=cur_ident["SHA256"],
                 preserve_from=target.path, known_hash=bk.identity["SHA256"])
    okf("Restore complete.")
    remove_backup_files(backup, _pe_meta_path(backup))
    print("")
    okf("Original file restored.")
    okf("Manifest V2 patch removed.")
    return 0


def cmd_check_pe(target, milestones):
    buf = bytearray(read_file(target.path))
    if len(buf) == 0:
        errf("That file is empty.")
        return 1
    img = open_pe(buf)
    ver = target.version
    ms = [m for m in milestones if m.container == img.slices[0].container]
    probe = patch_milestones(buf, img.slices[0], ms, allow_partial=True, apply=False, version=ver)
    if probe.status == 0:
        if "tied" in probe.reason:
            warnf("Couldn't tell which Chrome version this is.")
        else:
            warnf("This Chrome version isn't recognized yet.")
    else:
        if probe.stock > 0 and probe.already > 0:
            state = "partly patched"
        elif probe.stock > 0:
            state = "not patched yet"
        else:
            state = "already patched"
        okf(f"This is Chrome {chrome_label(ver, probe.milestone)} - {state}.")
    backup = backup_path(target.path)
    if os.path.isfile(backup):
        try:
            read_validated_backup_pe(backup)
            okf("A backup is saved.")
        except Mv2Error:
            warnf("A backup exists but looks damaged.")
    else:
        infof("No backup saved yet.")
    return 0 if probe.full else 1


# ============================================================================
# Orchestration - ELF (Linux).
# ============================================================================
def elf_request_close(target, assume_yes, quiet, no_reopen):
    if linux_proc_holders(target.path) == 0:
        return True
    label = display_name(os.path.basename(os.path.dirname(target.path)))
    if quiet and not assume_yes:
        errf(f"Can't make the change while {label} is open.")
        print("    Close it, or add -y/--yes to close it automatically.")
        return False
    infof(f"Closing {label} to make the change..." if no_reopen
          else f"Closing {label} - it reopens with the same tabs when this is done...")
    if not kill_chrome_processes(target.path):
        errf("Chrome is still open - close it and try again.")
        print("    Nothing was changed.")
        return False
    return True


def cmd_patch_elf(target, milestones, assume_yes, allow_partial, no_reopen, quiet):
    infof(f"Checking {os.path.basename(target.path)}...")
    if file_size(target.path) == 0:
        errf("That file is empty.")
        return 1
    buf = bytearray(read_file(target.path))
    img = open_elf(buf)
    ms = [m for m in milestones if m.container == img.slices[0].container]
    target_id = get_elf_build_id(buf)
    target_hash = sha256_bytes(buf)
    if not target_id:
        errf("This doesn't look like a valid Chrome file.")
        return 1
    infof("Searching for MV2 signatures...")
    best = probe_slice(buf, img.slices[0], ms)
    if best is None or best.satisfied == 0:
        report_layout_candidates(buf, img.slices[0])
        warnf("This Chrome version isn't recognized - nothing was changed.")
        return 1
    if best.ties > 1:
        warnf("Couldn't tell which Chrome version this is - nothing was changed.")
        return 1
    okf(f"Found matching signatures ({best.ms_name.split('-')[0]}, {best.satisfied} gates).")
    try:
        classify_flip_states(buf, best.flips)
    except Mv2Error:
        errf("Chrome looks partly changed or damaged - nothing was changed.")
        return 1

    backup = backup_path(target.path)
    if not os.path.isfile(backup):
        try:
            stock, patched = classify_flip_states(buf, best.flips)
        except Mv2Error:
            stock, patched = 0, 0
        if best.full and stock == 0 and patched > 0:
            successf("Chrome is already patched - Manifest V2 is already on.")
            print("          There's no backup here, so 'restore' isn't available.")
            print("          Reinstall Chrome if you want a clean, restorable copy.")
            return 0
        if (not best.full and not allow_partial) or patched != 0:
            errf("There's no backup yet, and this doesn't look like an untouched Chrome.")
            print("    Reinstall Chrome first so we can save a clean backup.")
            return 1
        infof("Creating backup...")
        save_backup_meta_unix(backup, target.path, "elf", target_id)
        ok, _ = validate_backup_meta_unix(backup, "elf", build_id=target_id)
        if not ok:
            errf("The backup couldn't be verified.")
            return 1
    else:
        bok, blegacy = validate_backup_meta_unix(backup, "elf", build_id=get_elf_build_id(bytearray(read_file(backup))))
        if not bok:
            errf("The backup couldn't be verified, so I won't overwrite it.")
            return 1
        bbuf = bytearray(read_file(backup))
        bimg = open_elf(bbuf)
        bbest = probe_slice(bbuf, bimg.slices[0], ms)
        try:
            _, bpatched = classify_flip_states(bbuf, bbest.flips) if bbest else (0, 1)
        except Mv2Error:
            errf("The backup looks damaged.")
            return 1
        if bbest is None or (not bbest.full and not allow_partial) or bbest.ties != 1 or bpatched != 0:
            errf("The backup doesn't look like an untouched Chrome.")
            return 1
        backup_build_id = get_elf_build_id(bbuf)
        if target_id != backup_build_id:
            nbest = probe_slice(buf, img.slices[0], ms)
            try:
                _, npatched = classify_flip_states(buf, nbest.flips) if nbest else (0, 1)
            except Mv2Error:
                npatched = 1
            if nbest is None or not nbest.full or nbest.ties != 1 or npatched != 0:
                errf("This updated Chrome isn't fully supported yet.")
                print("    Your backup was kept. Please report this Chrome version.")
                return 1
            infof("Chrome was updated - saving a fresh backup...")
            save_backup_meta_unix(backup, target.path, "elf", target_id)
        elif blegacy:
            save_backup_meta_unix(backup, backup, "elf", backup_build_id)

    work = bytearray(read_file(backup))
    wimg = open_elf(work)
    wbest = probe_slice(work, wimg.slices[0], ms)
    if wbest is None or wbest.satisfied == 0:
        warnf("This Chrome version isn't recognized.")
        return 1
    if wbest.ties > 1:
        warnf("Couldn't tell which Chrome version this is - nothing was changed.")
        return 1
    if not wbest.full and not allow_partial:
        warnf(f"Only {wbest.satisfied} of {wbest.total} changes matched; a partial patch needs --allow-partial.")
        return 1
    infof("Applying patch...")
    apply_flips(work, wbest.flips, apply=True, verbose=True)
    # verify
    wimg = open_elf(work)
    wbest = probe_slice(work, wimg.slices[0], ms)
    if wbest is None or wbest.ties != 1:
        errf("Something went wrong while preparing the change - nothing was changed.")
        return 1
    try:
        stock, patched = classify_flip_states(work, wbest.flips)
    except Mv2Error:
        errf("Something went wrong while preparing the change - nothing was changed.")
        return 1
    if stock != 0 or patched != len(wbest.flips):
        errf("Something went wrong while preparing the change - nothing was changed.")
        return 1
    prepared_hash = sha256_bytes(work)
    backup_hash = sha256_file(backup)
    if prepared_hash == target_hash:
        successf("Already done - no change was needed.")
        return 0
    if target_hash != backup_hash:
        errf("This Chrome has other changes we didn't make, so we won't overwrite it.")
        print("    Reinstall Chrome, or check the file yourself, then try again.")
        return 1
    if not elf_request_close(target, assume_yes, quiet, no_reopen):
        return 1
    if linux_proc_holders(target.path) > 0:
        errf("Chrome reopened before we could finish - nothing was changed.")
        return 1
    write_atomic(target.path, bytes(work), expected_current_hash=target_hash, known_hash=prepared_hash)
    okf("Patch applied successfully.")
    if wbest.full:
        okf("Manifest V2 is enabled.")
    else:
        print(f"{TAG['warning']} Only part of the change was applied ({wbest.satisfied}/{wbest.total}).")
        print(f"          {wbest.total - wbest.satisfied} part(s) couldn't be found, so this may not fully work.")
        print("          Please report your Chrome version. To undo: sudo python3 chrome-mv2.py restore")
    return 0


def cmd_restore_elf(target, milestones, assume_yes, force_restore, quiet, no_reopen):
    backup = backup_path(target.path)
    infof("Checking backup...")
    if not os.path.isfile(backup):
        errf("No backup found, so there's nothing to restore.")
        return 1
    bbuf = bytearray(read_file(backup))
    try:
        bimg = open_elf(bbuf)
    except Mv2Error:
        errf("The backup couldn't be verified.")
        return 1
    build_id = get_elf_build_id(bbuf)
    ok, _ = validate_backup_meta_unix(backup, "elf", build_id=build_id)
    if not ok:
        errf("The backup couldn't be verified.")
        return 1
    ms = [m for m in milestones if m.container == bimg.slices[0].container]
    bbest = probe_slice(bbuf, bimg.slices[0], ms)
    try:
        _, bpatched = classify_flip_states(bbuf, bbest.flips) if bbest else (0, 1)
    except Mv2Error:
        errf("The backup doesn't look like an untouched Chrome.")
        return 1
    if bbest is None or bbest.satisfied == 0 or bbest.ties != 1 or bpatched != 0:
        errf("The backup doesn't look like an untouched Chrome.")
        return 1
    okf("Backup found.")
    buf = bytearray(read_file(target.path))
    open_elf(buf)
    target_id = get_elf_build_id(buf)
    target_hash = sha256_bytes(buf)
    backup_hash = sha256_file(backup)
    if target_id != build_id and not force_restore:
        errf("This backup is from a different Chrome version, so I won't use it.")
        print("    Add --force-restore only if you really mean to go back to that version.")
        return 1
    if target_id != build_id:
        warnf("Restoring a different Chrome version (--force-restore).")
    if target_hash == backup_hash:
        successf("Chrome is already the original - nothing to undo.")
        remove_backup_files(backup, _unix_meta_path(backup))
        infof("Backup removed - Chrome is back to normal.")
        return 0
    if not elf_request_close(target, assume_yes, quiet, no_reopen):
        return 1
    if linux_proc_holders(target.path) > 0:
        errf("Chrome reopened before we could finish - nothing was changed.")
        return 1
    infof(f"Restoring {os.path.basename(target.path)}...")
    write_atomic(target.path, bytes(bbuf), expected_current_hash=target_hash, known_hash=backup_hash)
    okf("Restore complete.")
    remove_backup_files(backup, _unix_meta_path(backup))
    print("")
    okf("Original file restored.")
    okf("Manifest V2 patch removed.")
    return 0


def cmd_check_elf(target, milestones):
    buf = bytearray(read_file(target.path))
    img = open_elf(buf)
    ms = [m for m in milestones if m.container == img.slices[0].container]
    best = probe_slice(buf, img.slices[0], ms)
    full = False
    if best is None or best.satisfied == 0:
        warnf("This Chrome version isn't recognized yet.")
    elif best.ties > 1:
        warnf("Couldn't tell which Chrome version this is.")
    else:
        try:
            stock, patched = classify_flip_states(buf, best.flips)
        except Mv2Error:
            warnf("Chrome looks partly changed or damaged.")
            return 1
        state = "already patched"
        if stock > 0 and patched == 0:
            state = "not patched yet"
        elif stock > 0 and patched > 0:
            state = "partly patched"
        okf(f"This is Chrome {chrome_label(target.version, best.ms_name)} - {state}.")
        full = best.full and best.ties == 1
    backup = backup_path(target.path)
    if os.path.isfile(backup):
        ok, _ = validate_backup_meta_unix(backup, "elf", build_id=get_elf_build_id(bytearray(read_file(backup))))
        okf("A backup is saved.") if ok else warnf("A backup exists but looks damaged.")
    else:
        infof("No backup saved yet.")
    return 0 if full else 1


# ============================================================================
# Orchestration - Mach-O (macOS). Per-slice probe/flip on the host slice,
# UUID-keyed backup outside the bundle, ad-hoc inside-out re-sign.
# ============================================================================
def _macho_backup_paths(target):
    """(backup_dir, backup_path, meta_path) keyed by the host-slice UUID for a
    real .app; beside the file for a loose Mach-O."""
    buf = bytearray(read_file(target.path))
    img = open_macho(buf)
    ident = macho_identity_string(img)
    token = macho_identity_token(ident)
    if target.app_path:
        d = os.path.join(support_base(), "chrome-mv2-patch", token)
        bp = os.path.join(d, os.path.basename(target.path) + ".bak")
    else:
        d = os.path.dirname(target.path)
        bp = target.path + ".bak"
    return d, bp, _unix_meta_path(bp), ident


def cmd_patch_macho(target, milestones, assume_yes, allow_partial, no_reopen, quiet):
    infof(f"Checking {os.path.basename(target.path)}...")
    if file_size(target.path) == 0:
        errf("That file is empty.")
        return 1
    buf = bytearray(read_file(target.path))
    img = open_macho(buf)
    target_id = macho_identity_string(img)
    target_hash = sha256_bytes(buf)
    infof("Searching for MV2 signatures...")
    to_patch = []
    any_ok = False
    for idx, sl in enumerate(img.slices):
        best = probe_slice(buf, sl, [m for m in milestones if m.container == sl.container])
        satisfied = best.satisfied if best else 0
        ties = best.ties if best else 0
        full = best.full if best else False
        ok, reason = slice_decision(sl.container, satisfied, ties, full, allow_partial)
        if ok:
            to_patch.append(idx)
            any_ok = True
            okf(f"  {sl.container[len('macho-'):]}: found matching signatures ({best.ms_name.split('-')[0]}, {satisfied} gates).")
        else:
            warnf(f"  {sl.container[len('macho-'):]}: skipped ({reason}).")
    if not any_ok:
        errf("This Chrome version isn't recognized - nothing was changed.")
        return 1

    _, backup, meta, ident = _macho_backup_paths(target)
    if not os.path.isfile(backup):
        infof("Creating backup...")
        save_backup_meta_unix(backup, target.path, "macho", target_id)
        ok, _ = validate_backup_meta_unix(backup, "macho", macho_identity=target_id)
        if not ok:
            errf("The backup couldn't be verified.")
            return 1
    else:
        bok, blegacy = validate_backup_meta_unix(backup, "macho", macho_identity=target_id)
        if not bok and not blegacy:
            # identity may differ because Chrome updated; re-derive from the backup itself
            bimg = open_macho(bytearray(read_file(backup)))
            bok, blegacy = validate_backup_meta_unix(backup, "macho", macho_identity=macho_identity_string(bimg))
            if not bok and not blegacy:
                errf("The backup couldn't be verified, so I won't overwrite it.")
                return 1
        bimg = open_macho(bytearray(read_file(backup)))
        if macho_identity_string(bimg) != target_id:
            infof("Chrome was updated - saving a fresh backup...")
            save_backup_meta_unix(backup, target.path, "macho", target_id)
        elif blegacy:
            save_backup_meta_unix(backup, backup, "macho", target_id)

    work = bytearray(read_file(backup))
    wimg = open_macho(work)
    for k in to_patch:
        wbest = probe_slice(work, wimg.slices[k], [m for m in milestones if m.container == wimg.slices[k].container])
        if wbest:
            apply_flips(work, wbest.flips, apply=True, verbose=True)
    wimg = open_macho(work)
    for k in to_patch:
        wbest = probe_slice(work, wimg.slices[k], [m for m in milestones if m.container == wimg.slices[k].container])
        try:
            stock, _patched = classify_flip_states(work, wbest.flips) if wbest else (1, 0)
        except Mv2Error:
            errf("Something went wrong while preparing the change - nothing was changed.")
            return 1
        if stock != 0:
            errf("Something went wrong while preparing the change - nothing was changed.")
            return 1
    prepared_hash = sha256_bytes(work)
    backup_hash = sha256_file(backup)
    if prepared_hash == target_hash:
        successf("Already done - no change was needed.")
        return 0
    if target_hash != backup_hash:
        errf("This Chrome has other changes we didn't make, so we won't overwrite it.")
        print("    Reinstall Chrome, or check the file yourself, then try again.")
        return 1
    if target.app_path:
        if not macos_quit_app(target.app_path):
            errf("Chrome is still open - close it and try again.")
            return 1
    write_atomic(target.path, bytes(work), expected_current_hash=target_hash, known_hash=prepared_hash)
    if target.app_path:
        if have_codesign():
            if not resign_inside_out(target.app_path) or not verify_signature(target.app_path):
                errf("Re-signing failed - putting the original Chrome back.")
                try:
                    write_atomic(target.path, bytes(read_file(backup)))
                except Exception:
                    pass
                if resign_inside_out(target.app_path) and verify_signature(target.app_path):
                    infof("Restored the original Chrome. It should open normally.")
                else:
                    warnf("Chrome may not open. Run a full restore to be safe.")
                    print(f"    To restore: python3 chrome-mv2.py restore \"{target.app_path}\"")
                return 1
            okf("Re-signed and verified.")
        else:
            errf("Couldn't find 'codesign' (it normally comes with macOS).")
            print("    Chrome was changed but isn't signed, so it may not open.")
            print(f"    To restore: python3 chrome-mv2.py restore \"{target.app_path}\"")
            return 1
    rule()
    okf("Patch applied successfully.")
    okf("Manifest V2 is enabled.")
    if target.app_path:
        print(f"          Restart Chrome. To undo: python3 chrome-mv2.py restore \"{target.app_path}\"")
    rule()
    return 0


def cmd_restore_macho(target, milestones, assume_yes, force_restore, quiet, no_reopen):
    infof("Checking backup...")
    buf = bytearray(read_file(target.path))
    img = open_macho(buf)
    target_id = macho_identity_string(img)
    bdir, backup, meta, _ = _macho_backup_paths(target)
    if not os.path.isfile(backup):
        errf("No backup found, so there's nothing to restore.")
        return 1
    bimg = open_macho(bytearray(read_file(backup)))
    bok, blegacy = validate_backup_meta_unix(backup, "macho", macho_identity=macho_identity_string(bimg))
    if not bok and not blegacy:
        errf("The backup couldn't be verified.")
        return 1
    okf("Backup found.")
    backup_identity = macho_identity_string(bimg)
    target_hash = sha256_bytes(buf)
    backup_hash = sha256_file(backup)
    if target_id != backup_identity and not force_restore:
        errf("This backup is from a different Chrome version, so I won't use it.")
        print("    Add --force-restore only if you really mean to go back to that version.")
        return 1
    if target_hash == backup_hash:
        successf("Chrome is already the original - nothing to undo.")
        _remove_macho_backup(target, backup, meta, bdir)
        infof("Backup removed - Chrome is back to normal.")
        return 0
    if target.app_path:
        if not macos_quit_app(target.app_path):
            errf("Chrome is still open - close it and try again.")
            return 1
    infof(f"Restoring {os.path.basename(target.path)}...")
    write_atomic(target.path, bytes(read_file(backup)), expected_current_hash=target_hash, known_hash=backup_hash)
    if target.app_path and have_codesign():
        if not resign_inside_out(target.app_path):
            warnf(f"Re-signing failed. Try again: python3 chrome-mv2.py restore \"{target.app_path}\"")
    okf("Restore complete.")
    _remove_macho_backup(target, backup, meta, bdir)
    print("")
    okf("Original file restored.")
    okf("Manifest V2 patch removed.")
    return 0


def _remove_macho_backup(target, backup, meta, bdir):
    remove_backup_files(backup, meta)
    if target.app_path:
        for d in (bdir, os.path.dirname(bdir)):
            try:
                os.rmdir(d)
            except Exception:
                pass


def cmd_check_macho(target, milestones):
    buf = bytearray(read_file(target.path))
    img = open_macho(buf)
    for sl in img.slices:
        c = sl.container[len("macho-"):]
        best = probe_slice(buf, sl, [m for m in milestones if m.container == sl.container])
        if best is None or best.satisfied == 0:
            warnf(f"  {c}: this Chrome version isn't recognized yet.")
        elif best.ties > 1:
            warnf(f"  {c}: couldn't tell which Chrome version this is.")
        else:
            try:
                stock, patched = classify_flip_states(buf, best.flips)
                state = "not patched yet"
                if patched > 0 and stock == 0:
                    state = "already patched"
                elif patched > 0 and stock > 0:
                    state = "partly patched"
                okf(f"  {c}: Chrome {chrome_label(target.version, best.ms_name)} - {state}.")
            except Mv2Error:
                warnf(f"  {c}: looks partly changed or damaged.")
    _, backup, _meta, _ = _macho_backup_paths(target)
    if os.path.isfile(backup):
        bimg = open_macho(bytearray(read_file(backup)))
        ok, _ = validate_backup_meta_unix(backup, "macho", macho_identity=macho_identity_string(bimg))
        okf("A backup is saved.") if ok else warnf("A backup exists but looks damaged.")
    else:
        infof("No backup saved yet.")
    return 0


# ============================================================================
# Entry point
# ============================================================================
USAGE = """Usage: python chrome-mv2.py [command] [path] [options]

Turns Manifest V2 extension support back on in Google Chrome or Chromium. One
script for Windows (chrome.dll), Linux (the chrome binary), and macOS (Google
Chrome.app). On macOS it also re-signs the app so it opens normally.

Commands:
  patch                  Turn Manifest V2 back on (default).
  restore                Undo the change and put the original Chrome back.
  check                  Show the current status. Changes nothing.

Arguments:
  path                   Path to Chrome/Chromium (chrome.dll / chrome / a .app).
                         If left out, an installed browser is found automatically.

Options:
  -y, --yes              Allow closing a running Chrome under --quiet.
  -q, --quiet            Don't ask any questions (for scripts).
      --no-reopen        Leave the browser closed instead of reopening it.
      --allow-partial    Developer option: allow an incomplete patch.
      --force-restore    Restore a backup from a different Chrome version.
      --signatures PATH  Use an external signatures.json.
  -v, --version          Show the version and exit.
  -h, --help             Show this help and exit.

Environment:
  MV2_TEST_NO_ELEVATION  Skip the write-permission / elevation check (tests only).
  MV2_TEST_HOST_ARCH     Force the detected Mac host CPU (arm64/x86_64; tests).
  NO_COLOR / FORCE_COLOR Disable / force ANSI colour.
"""


class Args:
    def __init__(self):
        self.cmd = "patch"
        self.path = ""
        self.yes = False
        self.quiet = False
        self.no_reopen = False
        self.allow_partial = False
        self.force_restore = False
        self.signatures = ""
        self.relaunched = False


def parse_args(argv):
    a = Args()
    positional = []
    i = 0
    while i < len(argv):
        t = argv[i]
        if t in ("-y", "--yes"):
            a.yes = True
        elif t in ("-q", "--quiet"):
            a.quiet = True
        elif t == "--no-reopen":
            a.no_reopen = True
        elif t == "--allow-partial":
            a.allow_partial = True
        elif t == "--force-restore":
            a.force_restore = True
        elif t == "--relaunched":
            a.relaunched = True
        elif t == "--signatures":
            if i + 1 >= len(argv):
                errf("--signatures needs a path.")
                sys.exit(2)
            a.signatures = argv[i + 1]
            i += 1
        elif t in ("-v", "--version"):
            print(f"chrome-mv2-patch (Python) {APP_VERSION}")
            sys.exit(0)
        elif t in ("-h", "--help"):
            print(USAGE)
            sys.exit(0)
        elif t == "--":
            positional.extend(argv[i + 1:])
            break
        elif t.startswith("-"):
            errf(f"Unknown option: {t}")
            print(USAGE)
            sys.exit(2)
        else:
            positional.append(t)
        i += 1
    if positional:
        if positional[0] in ("patch", "restore", "check"):
            a.cmd = positional[0]
            if len(positional) >= 2:
                a.path = positional[1]
        else:
            a.path = positional[0]
    if len(positional) > 2:
        errf("Too many arguments.")
        print(USAGE)
        sys.exit(2)
    return a


def _elevation_argv(a):
    out = [a.cmd]
    if a.path:
        out.append(a.path)
    if a.yes:
        out.append("--yes")
    if a.quiet:
        out.append("--quiet")
    if a.allow_partial:
        out.append("--allow-partial")
    if a.force_restore:
        out.append("--force-restore")
    if a.no_reopen:
        out.append("--no-reopen")
    if a.signatures:
        out.extend(["--signatures", os.path.abspath(a.signatures)])
    return out


def resolve_target(a, milestones, interactive):
    if a.path:
        if not os.path.exists(a.path):
            errf("That path doesn't exist.")
            return None
        return resolve_any_target(a.path)
    infof("Searching for supported browsers...")
    if IS_WIN:
        installs = win_installs(milestones)
    elif IS_MAC:
        installs = macos_installs(milestones)
    else:
        installs = linux_installs(milestones)
    if not installs:
        if not interactive:
            errf("Couldn't find Chrome on this computer.")
            print("    Give the path to the Chrome file, e.g. python chrome-mv2.py patch /path/to/chrome")
            return None
        warnf("Couldn't find Chrome on this computer.")
        p = read_custom_path()
        if p:
            return resolve_any_target(p)
        infof("No path entered - nothing was changed.")
        return None
    if not interactive:
        if len(installs) > 1:
            errf(f"Found {len(installs)} browsers, and --quiet can't ask which one.")
            print_install_table(installs)
            print("    Re-run with the path of the one you want.")
            return None
        chosen = installs[0]
        return _install_to_target(chosen)
    picked, a.cmd = select_install(installs, a.cmd)
    if picked is None:
        infof("Nothing selected - nothing was changed.")
        return None
    if isinstance(picked, str):
        return resolve_any_target(picked)
    return _install_to_target(picked)


def _install_to_target(inst):
    if inst["container"] == "macho":
        app = inst.get("app_path", inst["path"])
        res = resolve_framework_from_app(app)
        if not res:
            raise Mv2Error(f"Couldn't find Chrome inside {app}")
        fw, tf = res
        return Target(tf, "macho", channel=inst["channel"], version=inst.get("version", ""),
                      app_path=app, framework_bundle=fw)
    return Target(inst["path"], inst["container"], channel=inst["channel"], version=inst.get("version", ""))


def run(a):
    init_colors()
    try:
        milestones, _label = import_milestones(a.signatures)
    except Mv2Error as e:
        errf(str(e))
        return 1
    banner()

    target = resolve_target(a, milestones, interactive=not a.quiet)
    if target is None:
        return 1

    sel = display_name(target.channel) if target.channel else os.path.basename(target.path)
    if target.version:
        okf(f"Selected browser: {sel} {target.version}")
    else:
        okf(f"Selected browser: {sel}")

    if target.container == "macho":
        detect_host_container()
        infof(f"Your Mac: {host_arch_label()}.")

    if a.cmd == "check":
        if target.container == "pe":
            return cmd_check_pe(target, milestones)
        if target.container == "elf":
            return cmd_check_elf(target, milestones)
        return cmd_check_macho(target, milestones)

    # Elevation / writability gate (skipped for check above).
    if not os.environ.get("MV2_TEST_NO_ELEVATION"):
        if IS_WIN and target.container == "pe":
            if not test_dir_writable(target.path) and not win_is_admin():
                if not a.relaunched:
                    code = self_elevate(_elevation_argv(a))
                    if code is not None:
                        if code == 0:
                            okf("Finished with administrator access.")
                        else:
                            errf("The run with administrator access did not succeed.")
                        return code
                    return 1
                warnf("This needs administrator access to change Chrome.")
                print("    Re-run from an elevated terminal, then try again.")
                return 1
        elif not IS_WIN:
            d = os.path.dirname(os.path.abspath(target.path)) or "."
            if not os.access(target.path, os.W_OK) or not os.access(d, os.W_OK):
                errf("Can't write to Chrome here.")
                print("    Re-run with sudo, or use a copy you can write to.")
                return 1

    # Capture what it takes to reopen, while the browser is still running.
    was_running = False
    if not a.no_reopen:
        if target.container == "macho":
            if target.app_path and macos_proc_holders_app(target.app_path) > 0:
                was_running = True
        elif target.container == "elf":
            if linux_proc_holders(target.path) > 0:
                was_running = True
                capture_reopen_linux(target.path)
        elif target.container == "pe":
            if get_browser_processes(target.path):
                was_running = True
                capture_reopen_win(target.path)

    if a.cmd == "restore":
        if target.container == "pe":
            rc = cmd_restore_pe(target, milestones, a.yes, a.force_restore, a.quiet, a.no_reopen)
        elif target.container == "elf":
            rc = cmd_restore_elf(target, milestones, a.yes, a.force_restore, a.quiet, a.no_reopen)
        else:
            rc = cmd_restore_macho(target, milestones, a.yes, a.force_restore, a.quiet, a.no_reopen)
    else:
        if target.container == "pe":
            rc = cmd_patch_pe(target, milestones, a.yes, a.allow_partial, a.no_reopen, a.quiet)
        elif target.container == "elf":
            rc = cmd_patch_elf(target, milestones, a.yes, a.allow_partial, a.no_reopen, a.quiet)
        else:
            rc = cmd_patch_macho(target, milestones, a.yes, a.allow_partial, a.no_reopen, a.quiet)

    if was_running:
        _reopen(target)
    return rc


def _reopen(target):
    label = display_name(target.channel) if target.channel else os.path.basename(target.path)
    if target.container == "macho":
        if not target.app_path or macos_proc_holders_app(target.app_path) > 0:
            return
        infof(f"Reopening {label} with your tabs...")
        if reopen_browser_macos(target.app_path):
            okf(f"Reopened {label} with your tabs.")
            return
    elif target.container == "elf":
        if linux_proc_holders(target.path) > 0:
            return
        if not REOPEN_ARGV:
            warnf(f"Left {label} closed - start it again when you want it.")
            return
        infof(f"Reopening {label} with your tabs...")
        if reopen_browser_linux(target.path):
            okf(f"Reopened {label} with your tabs.")
            return
    elif target.container == "pe":
        if get_browser_processes(target.path):
            return
        exe = WIN_REOPEN_EXE or browser_exe_path(target.path)
        if not exe:
            warnf(f"Left {label} closed - start it again when you want it.")
            return
        infof(f"Reopening {label} with your tabs...")
        arg_line = " ".join(WIN_REOPEN_ARGS + ["--restore-last-session"])
        try:
            if win_is_admin():
                started = start_as_desktop_user(exe, arg_line)
            else:
                subprocess.Popen('"%s" %s' % (exe, arg_line))
                started = True
        except Exception:
            started = False
        if started:
            for _ in range(60):
                if get_browser_processes(target.path):
                    okf(f"Reopened {label} with your tabs.")
                    return
                time.sleep(0.25)
    warnf(f"Couldn't reopen {label} - start it yourself.")
    print("    Your tabs are under History > Recently closed.")


def main(argv):
    a = parse_args(argv)
    try:
        rc = run(a)
    except Mv2Error as e:
        errf(str(e))
        rc = 1
    # Interactive pause so a double-clicked window keeps the result visible.
    if not a.quiet and sys.stdin.isatty() and sys.stdout.isatty():
        try:
            input("\nPress Enter to exit.")
        except Exception:
            pass
    return rc


if __name__ == "__main__" and not os.environ.get("MV2_TEST_LIBRARY_ONLY"):
    sys.exit(main(sys.argv[1:]))
