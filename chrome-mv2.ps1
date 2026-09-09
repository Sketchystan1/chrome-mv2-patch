<#
.SYNOPSIS
    Chrome / Chromium Manifest V2 Patcher - single-file, self-contained PowerShell
    port for Windows (chrome.dll only; x64, x86, and arm64).

.DESCRIPTION
    Re-enables Manifest V2 extension support in Google Chrome or Chromium (both
    ship chrome.dll) by flipping the inlined IsExtensionAffected manifest-version
    checks. Same milestone engine, same match/decline semantics, same .bak
    handling. Handles x64/x86 (PE, PE32) and Windows-on-ARM (PE32+ arm64, machine
    0xAA64).

    Self-contained: the Windows signature tables are EMBEDDED in this file
    ($EmbeddedSignatures below), so the script needs no signatures.json and no
    other file to run. A signatures.json installed next to the script takes
    precedence; another file must be selected explicitly with -Signatures.
    Being self-contained is also what lets
    it run straight from a URL (see the irm|iex example).

    HOW IT PATCHES: for each gate, first probe the RVA recorded in the table -
    cheap, and exact for the build the table was derived from. On a miss, scan
    the whole .text section for the gate's byte signature; that is what relocates
    a gate cleanly across point releases. A site counts as located only when its
    signature matches EXACTLY expectedMatches times: a different count means the
    layout moved, so the site is declined rather than guessed at. The milestone
    with the most located sites wins; one that locates none is declined outright.
    Then flip the gates, clear the Authenticode directory and recompute the PE
    checksum.

    CARDINAL RULE: never delete or blank a call and never invent control flow -
    only flip the direction of an existing branch to its EXISTING target.

      JG_SHORT  0x7F disp8       -> 0xEB disp8        (jmp short, same disp8)
      JG_NEAR   0x0F 0x8F disp32 -> 0x90 0xE9 disp32  (nop ; jmp near, same disp32)
      BCOND     arm64 b.gt (cond GT 0xC) -> b.al (cond AL 0xE), imm19 preserved
                (the low nibble of the B.cond word's byte0; one byte changes)

    PERFORMANCE NOTE - why this file is shaped the way it is:
    chrome.dll is ~285 MB. A per-byte loop in PowerShell is ~1000x slower than a
    compiled scan, so every hot loop lives in inline C# compiled via Add-Type.
    That compile is lazy - paid once per run, by the first operation that needs
    it (a full .text scan or a checksum pass). Trying to beat the scan with
    [Array]::IndexOf as a native memchr does NOT work: the signatures' first byte
    0x83 occurs ~3,000,000 times in .text (once per 84 bytes) and each candidate
    costs a ~36 us PowerShell-to-.NET round trip - ~109 s per signature versus a
    ~4.5 s compiled full-section scan. The remaining cost is the ~285 MB file
    being read/copied/written a few times; see the README for which passes are
    structural and which could be traded against safety.

    FILE MAP, top to bottom: parameters -> embedded signature tables -> console
    output -> inline C# hot loops -> signature loading + validation -> PE image
    layer -> patching engine -> Windows host glue (file locks, elevation) ->
    install discovery -> interactive prompts -> orchestration -> entry point.

    .PARAMETER Command
    patch (default), restore, or check. Check is read-only and never elevates.

.PARAMETER Path
    Target chrome.dll. Omitted: installed channels are listed to pick from.

.PARAMETER Yes
    Allow closing a running Chrome under -Quiet. An interactive run needs no
    permission: it closes the selected browser and reopens it with the same tabs.

    .PARAMETER Quiet
    Do not pause on error ('Press any key to exit') (for scripting).

    .PARAMETER NoReopen
    Leave the browser closed after the change instead of reopening it with the
    tabs it had.

    .PARAMETER AllowPartial
    Developer-only override which permits writing a milestone when only some of
    its sites were located. The safe default is to decline partial layouts.

    .PARAMETER ForceRestore
    Restore even when the backup identity does not match the installed binary.

    .PARAMETER Signatures
    Explicit external signatures.json path. External data is never loaded from
    the current directory implicitly.

.EXAMPLE
    .\chrome-mv2.ps1
.EXAMPLE
    .\chrome-mv2.ps1 patch "C:\Program Files\Google\Chrome\Application\151.0.7922.109\chrome.dll" -Yes
.EXAMPLE
    .\chrome-mv2.ps1 restore
.EXAMPLE
    # Run directly from a URL (self-elevates via UAC; keep the window open):
    powershell -ExecutionPolicy Bypass -c "irm https://example.com/chrome-mv2.ps1 | iex"
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('patch', 'restore', 'check')]
    [string]$Command = 'patch',

    [Parameter(Position = 1)]
    [string]$Path,

    [Alias('y')]
    [switch]$Yes,

    [Alias('q')]
    [switch]$Quiet,

    [switch]$AllowPartial,

    [switch]$ForceRestore,

    [switch]$NoReopen,

    [string]$Signatures,

    [Alias('v')]
    [switch]$Version,

    # Internal: set on the elevated relaunch so a failed elevation cannot loop.
    [switch]$Relaunched
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AppVersion      = '1.10.1'
$SignaturesFile  = 'signatures.json'
$script:CsLoaded = $false

# Embedded Windows signature tables - see the .DESCRIPTION note. An external
# signatures.json next to the script overrides this if present.
#
# Schema. Per milestone: name (label used in output), container ("pe" = PE32+/x64,
# "pe32" = PE32/x86, "pe-arm64" = PE32+/arm64 - milestones whose container does
# not match the target are skipped), sites[]. Per site:
#   name            label used in output
#   kind            "short" (7F disp8), "near" (0F 8F disp32), or "bcond"
#                   (arm64 B.cond GT->AL, low nibble of the 4-byte branch word)
#   jgRVA           RVA of the jg / b.cond opcode byte in the build this entry was
#                   derived from - a shortcut to try first, NOT a requirement
#   jgOff           index of that opcode byte within sig
#   expectedMatches how many times sig must occur in .text; >1 means one shared
#                   body the linker folded, and every copy gets flipped
#   sig             hex bytes, jg / b.cond opcode included at jgOff
$EmbeddedSignatures = @'
{
  "milestones": [
    {"name":"152","container":"pe","sites":[{"name":"manifest_v2_util::IsExtensionAffected (free predicate; covers install thunk)","kind":"short","jgRVA":"0x082D26F5","jgOff":3,"expectedMatches":1,"sig":"83F9027F1F83FA08771AB90A0100000FA3D173104183F805"},{"name":"ShouldBlockExtensionEnable / IsExtensionAffected (shared body)","kind":"short","jgRVA":"0x03348754","jgOff":4,"expectedMatches":2,"sig":"837A50027F34488B8A280200008B413080BA080200000075"},{"name":"OnExtensionSystemReady startup loop","kind":"short","jgRVA":"0x0124109C","jgOff":4,"expectedMatches":1,"sig":"837950027F2D488B91280200008B423080B90802000000750C"},{"name":"MaybeReEnableExtension","kind":"short","jgRVA":"0x082D24D6","jgOff":4,"expectedMatches":1,"sig":"837E50027F2D488B8E280200008B413080BE08020000007508"},{"name":"UserMayInstall (inlined)","kind":"short","jgRVA":"0x08DDC241","jgOff":4,"expectedMatches":1,"sig":"837F50027F4E488B8F280200008B413080BF0802000000750C"},{"name":"MustRemainDisabled (inlined, near jg)","kind":"near","jgRVA":"0x015A8D31","jgOff":4,"expectedMatches":1,"sig":"837F50020F8F8B000000488B8F280200008B413080BF080200000075"},{"name":"LoadChromePolicy: skip FilterSensitivePolicies (honor off-store ExtensionSettings on unmanaged Chrome)","kind":"short","jgRVA":"0x0205653F","jgOff":12,"expectedMatches":1,"sig":"488BBC2420010000837E18017F0A488D4C2448"}]},
    {"name":"152-x86","container":"pe32","sites":[{"name":"manifest_v2_util::IsExtensionAffected (free predicate; covers install thunk)","kind":"short","jgRVA":"0x06FB7547","jgOff":4,"expectedMatches":1,"sig":"837D08027F278B4D0C31C083F908771FBA0A0100000FA3CA73"},{"name":"ShouldBlockExtensionEnable / IsExtensionAffected (shared body)","kind":"short","jgRVA":"0x0299ED6A","jgOff":4,"expectedMatches":2,"sig":"837A28027F368B8A640100008B411880BA540100000075088B"},{"name":"OnExtensionSystemReady startup loop","kind":"short","jgRVA":"0x00A580A6","jgOff":4,"expectedMatches":1,"sig":"837928027F2C8B91640100008B421880B95401000000750C8B"},{"name":"MaybeReEnableExtension","kind":"short","jgRVA":"0x06FB736D","jgOff":4,"expectedMatches":1,"sig":"837E28027F248B8E640100008B411880BE540100000075088B"},{"name":"UserMayInstall (inlined)","kind":"short","jgRVA":"0x0791012F","jgOff":4,"expectedMatches":1,"sig":"837F28027F458B8F640100008B411880BF5401000000750C8B"},{"name":"MustRemainDisabled (inlined, near jg)","kind":"near","jgRVA":"0x010851A8","jgOff":4,"expectedMatches":1,"sig":"837B28020F8F840000008B8B640100008B411880BB54010000007508"},{"name":"LoadChromePolicy: skip FilterSensitivePolicies (honor off-store ExtensionSettings on unmanaged Chrome)","kind":"short","jgRVA":"0x018CF394","jgOff":7,"expectedMatches":1,"sig":"8B7D10837810017F0953E8"}]},
    {"name":"152-win-arm64","container":"pe-arm64","sites":[{"name":"ManifestV2Handler::OnExtensionSystemReady","kind":"bcond","jgRVA":"0x01014CBC","jgOff":4,"expectedMatches":1,"sig":"3F0900718C010054091541F90A214839283140B98A000037296940B93F050071"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled / StandardManagementPolicyProvider::UserMayInstall (shared body)","kind":"bcond","jgRVA":"0x013591BC","jgOff":4,"expectedMatches":2,"sig":"1F090071EC050054891641F98A224839283140B98A000037296940B93F050071"},{"name":"ManifestV2Handler::ShouldBlockExtensionEnable / ManifestV2Handler::IsExtensionAffected (shared body)","kind":"bcond","jgRVA":"0x02C1FD9C","jgOff":4,"expectedMatches":2,"sig":"1F0900710C020054291441F92A204839283140B98A000037296940B93F050071"},{"name":"ManifestV2Handler::MaybeReEnableExtension","kind":"bcond","jgRVA":"0x07702AEC","jgOff":4,"expectedMatches":1,"sig":"1F0900710C020054691641F96A224839283140B98A000037296940B93F050071"}]},
    {"name":"152-chromium","container":"pe","sites":[{"name":"manifest_v2_util::IsExtensionAffected (free predicate)","kind":"short","jgRVA":"0x04723915","jgOff":3,"expectedMatches":1,"sig":"83F9027F1F83FA08771AB90A0100000FA3D173104183F8050F"}]},
    {"name":"154-x86","container":"pe32","sites":[{"name":"manifest_v2_util::IsExtensionAffected (free predicate; covers install thunk)","kind":"short","jgRVA":"0x08BBA217","jgOff":4,"expectedMatches":1,"sig":"837D08027F278B4D0C31C083F908771FBA0A0100000FA3CA73"},{"name":"ShouldBlockExtensionEnable / IsExtensionAffected (shared body)","kind":"short","jgRVA":"0x031C47CA","jgOff":4,"expectedMatches":2,"sig":"837A28027F368B8A640100008B411880BA540100000075088B"},{"name":"OnExtensionSystemReady startup loop","kind":"short","jgRVA":"0x01B51743","jgOff":4,"expectedMatches":2,"sig":"837928027F288B91640100008B421880B95401000000750C8B"},{"name":"MaybeReEnableExtension","kind":"short","jgRVA":"0x08BBA108","jgOff":4,"expectedMatches":1,"sig":"837E28027F248B8E640100008B411880BE540100000075088B"},{"name":"UserMayInstall (inlined)","kind":"short","jgRVA":"0x093997BF","jgOff":4,"expectedMatches":1,"sig":"837F28027F458B8F640100008B411880BF5401000000750C8B"},{"name":"MustRemainDisabled (inlined, near jg)","kind":"near","jgRVA":"0x01205788","jgOff":4,"expectedMatches":1,"sig":"837B28020F8F840000008B8B640100008B411880BB54010000007508"},{"name":"LoadChromePolicy: skip FilterSensitivePolicies (honor off-store ExtensionSettings on unmanaged Chrome)","kind":"short","jgRVA":"0x018B41B4","jgOff":7,"expectedMatches":1,"sig":"8B7D10837810017F0953E8"}]},
    {"name":"155","container":"pe","sites":[{"name":"OnExtensionSystemReady startup loop","kind":"short","jgRVA":"0x0155EB53","jgOff":4,"expectedMatches":1,"sig":"837950027F30488B91280200008B425080B90802000000750F"},{"name":"MustRemainDisabled (inlined, near jg)","kind":"near","jgRVA":"0x016CB234","jgOff":4,"expectedMatches":1,"sig":"837F50020F8F8E000000488B8F280200008B415080BF080200000075"},{"name":"ShouldBlockExtensionEnable / IsExtensionAffected (shared body)","kind":"short","jgRVA":"0x03269A44","jgOff":4,"expectedMatches":2,"sig":"837A50027F37488B8A280200008B415080BA0802000000750B"},{"name":"MaybeReEnableExtension","kind":"short","jgRVA":"0x084DEA66","jgOff":4,"expectedMatches":1,"sig":"837E50027F30488B8E280200008B415080BE0802000000750B"},{"name":"manifest_v2_util::IsExtensionAffected (free predicate; covers install thunk)","kind":"short","jgRVA":"0x084DEC85","jgOff":3,"expectedMatches":1,"sig":"83F9027F1F83FA08771AB90A0100000FA3D173104183F8050F"},{"name":"UserMayInstall (inlined)","kind":"short","jgRVA":"0x090A7931","jgOff":4,"expectedMatches":1,"sig":"837F50027F51488B8F280200008B415080BF0802000000750F"},{"name":"LoadChromePolicy: skip FilterSensitivePolicies (honor off-store ExtensionSettings on unmanaged Chrome)","kind":"short","jgRVA":"0x01FF3FFF","jgOff":12,"expectedMatches":1,"sig":"488BBC2420010000837E18017F0A488D4C2448"}]},
    {"name":"155-x86","container":"pe32","sites":[{"name":"MustRemainDisabled (inlined, near jg)","kind":"near","jgRVA":"0x011D9EB8","jgOff":4,"expectedMatches":1,"sig":"837B28020F8F840000008B8B640100008B412880BB54010000007508"},{"name":"OnExtensionSystemReady startup loop","kind":"short","jgRVA":"0x01AFBEF3","jgOff":4,"expectedMatches":2,"sig":"837928027F288B91640100008B422880B95401000000750C8B"},{"name":"ShouldBlockExtensionEnable / IsExtensionAffected (shared body)","kind":"short","jgRVA":"0x032F125A","jgOff":4,"expectedMatches":2,"sig":"837A28027F368B8A640100008B412880BA540100000075088B"},{"name":"MaybeReEnableExtension","kind":"short","jgRVA":"0x08F66848","jgOff":4,"expectedMatches":1,"sig":"837E28027F248B8E640100008B412880BE540100000075088B"},{"name":"manifest_v2_util::IsExtensionAffected (free predicate; covers install thunk)","kind":"short","jgRVA":"0x08F66957","jgOff":4,"expectedMatches":1,"sig":"837D08027F278B4D0C31C083F908771FBA0A0100000FA3CA73"},{"name":"UserMayInstall (inlined)","kind":"short","jgRVA":"0x097626DF","jgOff":4,"expectedMatches":1,"sig":"837F28027F458B8F640100008B412880BF5401000000750C8B"},{"name":"LoadChromePolicy: skip FilterSensitivePolicies (honor off-store ExtensionSettings on unmanaged Chrome)","kind":"short","jgRVA":"0x0189B504","jgOff":7,"expectedMatches":1,"sig":"8B7D10837810017F0953E8"}]},
    {"name":"154-win-arm64","container":"pe-arm64","sites":[{"name":"ManifestV2Handler::OnExtensionSystemReady","kind":"bcond","jgRVA":"0x010B5620","jgOff":4,"expectedMatches":1,"sig":"5F0900718C0100542A1541F92B214839495140B98B0000374A8940B95F050071"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled / StandardManagementPolicyProvider::UserMayInstall (shared body)","kind":"bcond","jgRVA":"0x01354B40","jgOff":4,"expectedMatches":2,"sig":"1F0900712C060054891641F98A224839285140B98A000037298940B93F050071"},{"name":"ManifestV2Handler::ShouldBlockExtensionEnable / ManifestV2Handler::IsExtensionAffected (shared body)","kind":"bcond","jgRVA":"0x02C30AD8","jgOff":4,"expectedMatches":2,"sig":"1F0900710C020054291441F92A204839285140B98A000037298940B93F050071"},{"name":"ManifestV2Handler::MaybeReEnableExtension","kind":"bcond","jgRVA":"0x079DBD98","jgOff":4,"expectedMatches":1,"sig":"1F0900710C020054691641F96A224839285140B98A000037298940B93F050071"},{"name":"LoadChromePolicy: skip FilterSensitivePolicies (honor off-store ExtensionSettings on unmanaged Chrome)","kind":"bcond","jgRVA":"0x01B0E0E8","jgOff":8,"expectedMatches":1,"sig":"881A40B91F0500716C000054E0A30091"}]}
  ]
}
'@

# ============================================================================
# Console colour + tags. $script:C holds the escape sequences (all empty strings
# when colour is off), so every caller can interpolate them unconditionally.
# ============================================================================

$script:C = @{}
# Set for the elevated relaunch (Invoke-Main): Initialize-Colors then bakes a
# black background into every ANSI code it emits. Under Windows Terminal the
# window background comes from the terminal profile - Windows PowerShell's is
# the classic blue - and a plain reset ($e[0m) would fall back to it around
# the text, leaving blue behind the words.
$script:ForceBlackBg = $false

# Decides once whether to emit ANSI colour, then builds $C and the [+]/[!] tags.
# Must run before any output: the tags are empty until it does.
function Initialize-Colors {
    $vt = $false
    if ($Host.UI.SupportsVirtualTerminal) { $vt = $true }
    # PS7 on a real console always handles VT; redirected output should not.
    if (-not [Console]::IsOutputRedirected -and $PSVersionTable.PSVersion.Major -ge 6) { $vt = $true }
    if ($env:FORCE_COLOR) { $vt = $true }
    if ($env:NO_COLOR)    { $vt = $false }   # checked last so it always wins

    if ($vt) {
        $e = [char]27
        # 24-bit black background, appended to every colour code (and Reset) so
        # no write ever falls back to the terminal profile's background.
        $bg = if ($script:ForceBlackBg) { ';48;2;0;0;0' } else { '' }
        $script:C = @{
            Reset = "$e[0${bg}m"; Red = "$e[91${bg}m"; Grn = "$e[92${bg}m"
            Yel   = "$e[93${bg}m"; Cyn = "$e[96${bg}m"; Dim = "$e[90${bg}m"; Bold = "$e[1m"
        }
    } else {
        $script:C = @{ Reset=''; Red=''; Grn=''; Yel=''; Cyn=''; Dim=''; Bold='' }
    }

    $script:TagOK      = "$($C.Grn)[+]$($C.Reset)"
    $script:TagErr     = "$($C.Red)[-]$($C.Reset)"
    $script:TagInfo    = "$($C.Cyn)[*]$($C.Reset)"
    $script:TagWarn    = "$($C.Yel)[!]$($C.Reset)"
    $script:TagSuccess = "$($C.Bold)$($C.Grn)[SUCCESS]$($C.Reset)"
    $script:TagWarning = "$($C.Bold)$($C.Yel)[WARNING]$($C.Reset)"
}

function Write-Info    { param([string]$m) Write-Host "$script:TagInfo $m" }
function Write-Ok      { param([string]$m) Write-Host "$script:TagOK $m" }
function Write-Warn    { param([string]$m) Write-Host "$script:TagWarn $m" }
function Write-Err     { param([string]$m) Write-Host "$script:TagErr $m" }
function Write-Success { param([string]$m) Write-Host "$script:TagSuccess $m" }
function Write-Rule    { Write-Host "$($C.Cyn)==========================================================$($C.Reset)" }

function Write-Banner {
    Write-Rule
    Write-Host "$($C.Bold)                    MV2 Patcher v$AppVersion                    $($C.Reset)"
    Write-Rule
}

# "7F 34 EB" - byte dumps for the candidate listing.
function Format-HexUpper {
    param([byte[]]$Bytes)
    ($Bytes | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
}

# ============================================================================
# Console QuickEdit
#
# QuickEdit turns a click in the console window into a text selection, and while
# one is open conhost SUSPENDS the console app: output stops mid-line and typing
# does nothing until Enter (copy) or Esc clears it. Clicking back into the window
# after switching away is enough to trigger it, so a run that closed the browser
# can sit frozen with the file half written and no sign of why.
#
# It is on by default per-executable - HKCU\Console\<exe>\QuickEdit overrides the
# global HKCU\Console\QuickEdit - so the setting cannot be assumed off, and the
# elevated child gets a brand new console that reads those same keys. Clearing
# the bit for the duration of the run is the only reliable fix; the original mode
# is put back on exit so the user's console keeps whatever they chose. Windows
# Terminal does its own selection, which does not suspend anything, so nothing is
# lost there either.
#
# ENABLE_EXTENDED_FLAGS must be set in the same call: without it SetConsoleMode
# ignores the QuickEdit/insert bits entirely.
# ============================================================================

$script:SavedConsoleMode = $null

function Initialize-ConsoleMode {
    if (('Mv2ConsoleMode' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class Mv2ConsoleMode
{
    const int  STD_INPUT_HANDLE        = -10;
    const uint ENABLE_QUICK_EDIT_MODE  = 0x0040;
    const uint ENABLE_EXTENDED_FLAGS   = 0x0080;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetStdHandle(int nStdHandle);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    // Returns the mode that was in effect so the caller can restore it, or -1
    // when there is no console input to change (redirected, or a non-console
    // host) - not an error, just nothing to do.
    public static long DisableQuickEdit()
    {
        IntPtr h = GetStdHandle(STD_INPUT_HANDLE);
        if (h == IntPtr.Zero || h == new IntPtr(-1)) return -1;
        uint mode;
        if (!GetConsoleMode(h, out mode)) return -1;
        uint wanted = (mode | ENABLE_EXTENDED_FLAGS) & ~ENABLE_QUICK_EDIT_MODE;
        if (!SetConsoleMode(h, wanted)) return -1;
        return (long)mode;
    }

    public static void RestoreMode(long mode)
    {
        if (mode < 0) return;
        IntPtr h = GetStdHandle(STD_INPUT_HANDLE);
        if (h == IntPtr.Zero || h == new IntPtr(-1)) return;
        SetConsoleMode(h, (uint)mode | ENABLE_EXTENDED_FLAGS);
    }
}
'@
}

# Best effort throughout: a console whose mode cannot be read or set is one where
# the freeze cannot happen either, and no failure here is worth aborting a patch.
function Disable-ConsoleQuickEdit {
    if ([Console]::IsInputRedirected) { return }
    try {
        Initialize-ConsoleMode
        $prev = [Mv2ConsoleMode]::DisableQuickEdit()
        if ($prev -ge 0) { $script:SavedConsoleMode = $prev }
    } catch { }
}

function Restore-ConsoleQuickEdit {
    if ($null -eq $script:SavedConsoleMode) { return }
    try { [Mv2ConsoleMode]::RestoreMode($script:SavedConsoleMode) } catch { }
    $script:SavedConsoleMode = $null
}

# ============================================================================
# Lazy native helpers (scan hot loop + PE checksum)
#
# Compiled ONLY when a full .text scan or a checksum pass is actually required.
# The signature match and the checksum must stay byte-for-byte exact, so both hot
# loops live in inline C#. Add-Type cannot redefine a type in the same session,
# hence the $script:CsLoaded guard.
# ============================================================================

function Initialize-NativeHelpers {
    if ($script:CsLoaded) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;

public static class Mv2Native
{
    public const int KindShort = 0;
    public const int KindNear  = 1;
    public const int KindBcond = 2;
    public const int KindCbz   = 4;

    // Signature match at one position. Exact match on every byte
    // except the jump opcode and its displacement, which are masked per encoding:
    //   short: [jgOff] in {sig stock byte (7F jg default),EB}; [jgOff+1] disp8 wild
    //   near : opcode pair is {sig stock pair (0F 8F jg default), 90 E9};
    //          [jgOff+2..+5] wild
    //   bcond: the 4-byte LE arm64 B.cond word at [jgOff] - opcode 0x54 + bit4=0
    //          fixed, cond nibble in {0xC stock GT, 0xE patched AL}, imm19 wild
    //   cbz  : the 4-byte LE arm64 word at [jgOff] is the stock 32-bit CBZ
    //          (0x34, Rt = the sig's, imm19 wild) or the patched unconditional
    //          B (0x14) whose resolved target equals the sig CBZ's
    static int SignExtend(int v, int bits)
    {
        if ((v & (1 << (bits - 1))) != 0) v -= (1 << bits);
        return v;
    }

    static bool CbzWordOk(uint cand, uint sigWord)
    {
        if ((cand & 0xFF000000u) == 0x34000000u)
            return (cand & 0x1Fu) == (sigWord & 0x1Fu);
        if ((cand & 0xFC000000u) == 0x14000000u)
        {
            int dispCand = SignExtend((int)(cand & 0x03FFFFFFu), 26);
            int dispRef  = SignExtend((int)((sigWord >> 5) & 0x7FFFFu), 19);
            return dispCand == dispRef;
        }
        return false;
    }

    public static bool SigMatchesAt(byte[] buf, long start, byte[] sig, int jgOff, int kind)
    {
        if (start < 0 || start + sig.Length > buf.LongLength) return false;
        if (kind == KindBcond)
        {
            // Validate the whole branch word once (little-endian) before the byte loop.
            long w0 = start + jgOff;
            uint word = (uint)(buf[w0] | (buf[w0 + 1] << 8) | (buf[w0 + 2] << 16) | (buf[w0 + 3] << 24));
            if ((word & 0xFF000010u) != 0x54000000u) return false;
            uint cond = word & 0xFu;
            if (cond != 0x0Cu && cond != 0x0Eu) return false;
        }
        else if (kind == KindCbz)
        {
            long w0 = start + jgOff;
            uint word = (uint)(buf[w0] | (buf[w0 + 1] << 8) | (buf[w0 + 2] << 16) | (buf[w0 + 3] << 24));
            uint sigWord = (uint)(sig[jgOff] | (sig[jgOff + 1] << 8) | (sig[jgOff + 2] << 16) | (sig[jgOff + 3] << 24));
            if (!CbzWordOk(word, sigWord)) return false;
        }
        for (int k = 0; k < sig.Length; k++)
        {
            byte p = buf[start + k];
            if (kind == KindShort)
            {
                if (k == jgOff)          { if (p != sig[k] && p != 0xEB) return false; }
                else if (k == jgOff + 1) { /* disp8 wildcard */ }
                else if (p != sig[k])    { return false; }
            }
            else if (kind == KindNear)
            {
                if (k == jgOff)
                {
                    byte p1 = buf[start + jgOff + 1];
                    if (!((p == sig[k] && p1 == sig[k + 1]) || (p == 0x90 && p1 == 0xE9))) return false;
                }
                else if (k == jgOff + 1)                   { /* pair checked above */ }
                else if (k >= jgOff + 2 && k <= jgOff + 5) { /* disp32 wildcard */ }
                else if (p != sig[k])                      { return false; }
            }
            else // KindBcond / KindCbz: the 4 branch-word bytes were validated above
            {
                if (k >= jgOff && k <= jgOff + 3) { /* branch word, wild imm19/imm26 */ }
                else if (p != sig[k])            { return false; }
            }
        }
        return true;
    }

    // Full .text scan, used when the recorded RVA missed. Returns file offsets of
    // each jg opcode byte matched. Stops once we exceed expectedMatches: that is
    // already enough for the caller to reject the site as ambiguous.
    public static long[] Scan(byte[] buf, long textRaw, long textSize,
                              byte[] sig, int jgOff, int kind, int expectedMatches)
    {
        var found = new List<long>();
        long textEnd = textRaw + textSize;
        long limit = Math.Min(textEnd, buf.LongLength);
        byte first = sig[0];
        for (long r = textRaw; r + sig.Length <= limit; r++)
        {
            if (buf[r] != first) continue;              // fast filter on first byte
            if (!SigMatchesAt(buf, r, sig, jgOff, kind)) continue;
            found.Add(r + jgOff);
            if (found.Count > expectedMatches) break;
        }
        return found.ToArray();
    }

    // Byte-substring search over [start, end). Returns the first index, or -1.
    // Used by the featurebyte (.rdata) locator to find a feature name literal and
    // the 8-byte pointers to it without a slow pure-PowerShell scan.
    public static long IndexOf(byte[] buf, byte[] needle, long start, long end)
    {
        if (needle.Length == 0) return -1;
        long limit = Math.Min(end, buf.LongLength) - needle.Length;
        byte first = needle[0];
        for (long i = (start < 0 ? 0 : start); i <= limit; i++)
        {
            if (buf[i] != first) continue;
            int k = 1;
            for (; k < needle.Length; k++) { if (buf[i + k] != needle[k]) break; }
            if (k == needle.Length) return i;
        }
        return -1;
    }

    // PE checksum: 16-bit ones-complement-style sum over the whole file
    // (skipping the CheckSum field) plus the file size.
    public static uint PeChecksum(byte[] data, long checksumOffset)
    {
        ulong checksum = 0;
        long dwords = data.LongLength / 4;
        long skip = checksumOffset / 4;
        for (long i = 0; i < dwords; i++)
        {
            if (i == skip) continue;
            checksum += BitConverter.ToUInt32(data, (int)(i * 4));
            if (checksum > 0xFFFFFFFF) checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32);
        }
        int rem = (int)(data.LongLength % 4);
        if (rem != 0)
        {
            uint last = 0; int shift = 0;
            for (int k = 0; k < rem; k++) { last |= (uint)data[dwords * 4 + k] << shift; shift += 8; }
            checksum += last;
            if (checksum > 0xFFFFFFFF) checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32);
        }
        while ((checksum >> 16) != 0) checksum = (checksum & 0xFFFF) + (checksum >> 16);
        return (uint)(checksum + (ulong)data.LongLength);
    }

    // Report-only structural scan for the decline path. Never writes.
    public static long[] SkeletonScan(byte[] buf, long textRaw, long textSize)
    {
        var hits = new List<long>();
        long tsize = Math.Min(textSize, buf.LongLength - textRaw);
        for (long i = 2; i + 2 < tsize; i++)
        {
            if (buf[textRaw + i] != 0x02 || buf[textRaw + i + 1] != 0x7F) continue;

            long cmpStart;
            if (buf[textRaw + i - 2] == 0x83 && (buf[textRaw + i - 1] & 0xF8) == 0xF8)
                cmpStart = i - 2;                                    // 83 F8..FF 02
            else if (i >= 3 && buf[textRaw + i - 3] == 0x83 && (buf[textRaw + i - 2] & 0xF8) == 0x78)
                cmpStart = i - 3;                                    // 83 78..7F disp8 02
            else continue;

            bool follow = false;
            long end = Math.Min(i + 2 + 40, tsize);
            for (long j = i + 2; j + 2 < end; j++)
            {
                byte b0 = buf[textRaw + j], b1 = buf[textRaw + j + 1], b2 = buf[textRaw + j + 2];
                if (b0 == 0x83 && (b1 & 0xF8) == 0xF8 && (b2 == 0x01 || b2 == 0x05)) { follow = true; break; }
                if (b0 == 0x80 && (b1 & 0xF8) == 0xB8 && j + 6 < end && buf[textRaw + j + 6] == 0x00) { follow = true; break; }
            }
            if (follow) hits.Add(cmpStart);
        }
        return hits.ToArray();
    }
}
'@
    $script:CsLoaded = $true
}

# ============================================================================
# Signature loading. The milestone tables are embedded in this
# file ($EmbeddedSignatures); an external signatures.json overrides them if
# present, so new data can be shipped without editing the script. Another path
# must be supplied explicitly with -Signatures.
# ============================================================================

# An explicit -Signatures path wins, followed by signatures.json beside the
# script. $null means neither exists, so the embedded tables are used.
function Get-SignaturesPath {
    if ($Signatures) {
        if (-not (Test-Path -LiteralPath $Signatures -PathType Leaf)) {
            throw "signature file does not exist: $Signatures"
        }
        return (Resolve-Path -LiteralPath $Signatures).Path
    }

    # A file installed beside the script is part of the tool distribution and
    # may override the embedded tables. Never trust an admin's current directory
    # implicitly: an unrelated signatures.json there must have no effect.
    if ($PSScriptRoot) {
        $besideScript = Join-Path $PSScriptRoot $SignaturesFile
        if (Test-Path -LiteralPath $besideScript -PathType Leaf) { return $besideScript }
    }
    return $null
}

# Reads and parses the active signature document (external file if present,
# otherwise the embedded copy).
function Read-SignatureJson {
    $path = Get-SignaturesPath
    if ($path) {
        try   { $raw = Get-Content -LiteralPath $path -Raw }
        catch { throw "reading ${path}: $_" }
        $srcLabel = $path
    } else {
        $raw = $EmbeddedSignatures
        $srcLabel = 'embedded tables'
    }
    try   { return ($raw | ConvertFrom-Json) }
    catch { throw "parsing ${srcLabel}: $_" }
}

# "7F34EB" -> [byte[]](0x7F, 0x34, 0xEB). The leading comma on the return is
# required: PowerShell would otherwise unroll a 1-byte array into a scalar.
function ConvertFrom-HexString {
    param([string]$Hex)
    if ($Hex.Length % 2 -ne 0) { throw "odd-length hex string" }
    $out = [byte[]]::new($Hex.Length / 2)
    for ($i = 0; $i -lt $out.Length; $i++) {
        $out[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    return ,$out
}

# Reads and strictly validates the signature tables:
# the sig must carry the stock jg opcode at jgOff, near jgs need 6 bytes, and
# expectedMatches must be >= 1. Anything off is a hard error, never a guess.
# Kind is normalised to the int the C# helper expects (0 = short, 1 = near).
function Import-Milestones {
    $doc = Read-SignatureJson

    if ($null -eq $doc.milestones -or @($doc.milestones).Count -eq 0) {
        throw 'signature document contains no milestones'
    }

    $out = @()
    $milestoneNames = @{}
    foreach ($rm in $doc.milestones) {
        $msName = [string]$rm.name
        $container = [string]$rm.container
        if ([string]::IsNullOrWhiteSpace($msName) -or $msName -match '[\r\n|]') {
            throw 'milestone name is empty or contains a reserved character'
        }
        if ($milestoneNames.ContainsKey($msName)) { throw "duplicate milestone name '$msName'" }
        $milestoneNames[$msName] = $true
        if ($container -notin 'pe', 'pe32', 'pe-arm64', 'elf', 'elf-arm64', 'macho-arm64') {
            throw "milestone $msName has unsupported container '$container'"
        }
        # This script patches only Windows PE (x64 'pe', x86 'pe32', arm64
        # 'pe-arm64'). A shared signatures.json may also carry the Linux (elf,
        # elf-arm64) and macOS (macho-arm64) tables, so skip any non-PE
        # milestone rather than validate a kind this engine does not implement.
        if ($container -notin 'pe', 'pe32', 'pe-arm64') { continue }
        if ($null -eq $rm.sites -or @($rm.sites).Count -eq 0) {
            throw "milestone $msName contains no sites"
        }

        $sites = @()
        $siteNames = @{}
        foreach ($rs in $rm.sites) {
            $siteName = [string]$rs.name
            if ([string]::IsNullOrWhiteSpace($siteName) -or $siteName -match '[\r\n|]') {
                throw "milestone $msName has an invalid site name"
            }
            if ($siteNames.ContainsKey($siteName)) { throw "milestone $msName has duplicate site '$siteName'" }
            $siteNames[$siteName] = $true
            $optional = $false
            if ($rs.PSObject.Properties['optional']) { $optional = [bool]$rs.optional }
            switch ($rs.kind) {
                'short'       { $kind = 0 }      # Mv2Native.KindShort
                'near'        { $kind = 1 }      # Mv2Native.KindNear
                'bcond'       { $kind = 2 }      # Mv2Native.KindBcond (arm64 B.cond GT->AL)
                'featurebyte' { $kind = 3 }      # .rdata feature-data byte overwrite
                'cbz'         { $kind = 4 }      # Mv2Native.KindCbz (arm64 CBZ->B, same target)
                default { throw "milestone $($rm.name) site '$($rs.name)': unknown kind '$($rs.kind)'" }
            }
            if ($kind -eq 3) {
                if ($container -ne 'pe') {
                    throw "milestone $msName site '$siteName': featurebyte is only supported for the 'pe' container"
                }
                $feature = [string]$rs.feature
                if ([string]::IsNullOrWhiteSpace($feature) -or $feature -match '[\r\n\x00]') {
                    throw "milestone $msName site '$siteName': featurebyte needs a non-empty 'feature' name"
                }
                $patchOff = [int]$rs.patchOff
                if ($patchOff -lt 0) { throw "milestone $msName site '$siteName': featurebyte patchOff must be >= 0" }
                $stockB = [int]$rs.stock; $patchedB = [int]$rs.patched
                if ($stockB -lt 0 -or $stockB -gt 255 -or $patchedB -lt 0 -or $patchedB -gt 255) {
                    throw "milestone $msName site '$siteName': featurebyte stock/patched must be bytes 0..255"
                }
                if ($stockB -eq $patchedB) {
                    throw "milestone $msName site '$siteName': featurebyte stock and patched are identical"
                }
                $verify = @{}
                if ($rs.PSObject.Properties['verify'] -and $null -ne $rs.verify) {
                    foreach ($vp in $rs.verify.PSObject.Properties) {
                        $ko = [int]$vp.Name; $vv = [int]$vp.Value
                        if ($ko -lt 0 -or $vv -lt 0 -or $vv -gt 255) {
                            throw "milestone $msName site '$siteName': bad featurebyte verify entry"
                        }
                        $verify[$ko] = [byte]$vv
                    }
                }
                $structRVA = [uint32]0
                if ($rs.PSObject.Properties['structRVA'] -and -not [string]::IsNullOrWhiteSpace([string]$rs.structRVA)) {
                    $structRVA = [uint32]([Convert]::ToUInt32([string]$rs.structRVA, 16))
                }
                $expected = [int]$rs.expectedMatches
                if ($expected -lt 1) { throw "milestone $msName site '$siteName': expectedMatches must be >= 1" }
                $sites += [pscustomobject]@{
                    Name = $siteName; Kind = 3; Optional = $optional
                    Feature = $feature; StructRVA = $structRVA; PatchOff = $patchOff
                    Stock = [byte]$stockB; Patched = [byte]$patchedB; Verify = $verify
                    ExpectedMatches = $expected
                    JgRVA = [uint32]0; Sig = ([byte[]]@()); JgOff = 0
                }
                continue
            }
            # A bcond/cbz site must sit in an arm64 PE; short/near are x86/x64 only.
            if (($kind -eq 2 -or $kind -eq 4) -and $container -ne 'pe-arm64') {
                throw "milestone $msName site '$siteName': '$($rs.kind)' kind is only valid in a pe-arm64 milestone"
            }
            if (($kind -ne 2 -and $kind -ne 4) -and $container -eq 'pe-arm64') {
                throw "milestone $msName site '$siteName': pe-arm64 milestones use the 'bcond'/'cbz' kinds, not '$($rs.kind)'"
            }

            $sigText = [string]$rs.sig
            if ([string]::IsNullOrWhiteSpace($sigText) -or $sigText -notmatch '^[0-9A-Fa-f]+$') {
                throw "milestone $msName site '$siteName': sig must be non-empty hexadecimal bytes"
            }
            $sig = ConvertFrom-HexString $sigText
            $jgOff = [int]$rs.jgOff
            if ($jgOff -lt 0 -or $jgOff -ge $sig.Length) {
                throw "milestone $($rm.name) site '$($rs.name)': jgOff $jgOff out of range (sig len $($sig.Length))"
            }
            # Stock-opcode validation: the sig's bytes at jgOff must be the stock
            # branch encoding. A stockOpcode field overrides the default (e.g. a
            # near JE site carries 0x0F84); otherwise short must be 0x7F and near
            # must be 0x0F 0x8F. Mirrors chrome-mv2.py so a mis-authored sig is
            # rejected here rather than silently flipped by the patcher.
            if ($kind -eq 0 -and ($jgOff + 1) -ge $sig.Length) {
                throw "milestone $msName site '$siteName': short jg needs 2 bytes but sig ends early"
            }
            if ($kind -eq 1 -and ($jgOff + 5) -ge $sig.Length) {
                throw "milestone $msName site '$siteName': near jg needs 6 bytes but sig ends early"
            }
            if ($kind -eq 0 -or $kind -eq 1) {
                $expStock = $null
                if ($rs.PSObject.Properties['stockOpcode'] -and -not [string]::IsNullOrWhiteSpace([string]$rs.stockOpcode)) {
                    $stockField = [string]$rs.stockOpcode
                    if ($stockField -notmatch '^0[xX][0-9A-Fa-f]+$') {
                        throw "milestone $msName site '$siteName': bad stockOpcode"
                    }
                    $expStock = ConvertFrom-HexString $stockField.Substring(2).PadLeft(2, '0')
                    $wantLen = if ($kind -eq 0) { 1 } else { 2 }
                    if ($expStock.Length -ne $wantLen) {
                        throw "milestone $msName site '$siteName': stockOpcode must be $wantLen byte(s) for '$($rs.kind)'"
                    }
                } elseif ($kind -eq 0) {
                    $expStock = [byte[]]@(0x7F)          # STOCK_SHORT (jg rel8)
                } else {
                    $expStock = [byte[]]@(0x0F, 0x8F)    # STOCK_NEAR  (jg rel32)
                }
                for ($bi = 0; $bi -lt $expStock.Length; $bi++) {
                    if ($sig[$jgOff + $bi] -ne $expStock[$bi]) {
                        throw "milestone $msName site '$siteName': sig at jgOff is not the expected stock opcode"
                    }
                }
            } elseif ($rs.PSObject.Properties['stockOpcode'] -and -not [string]::IsNullOrWhiteSpace([string]$rs.stockOpcode)) {
                throw "milestone $msName site '$siteName': stockOpcode is only valid for the short/near kinds"
            }
            if ($kind -eq 2) {
                if (($jgOff + 3) -ge $sig.Length) {
                    throw "milestone $msName site '$siteName': bcond needs 4 bytes but sig ends early"
                }
                # Stock B.cond word (little-endian) must be a GT branch: 0x54.......C.
                $w = [uint32]$sig[$jgOff] -bor ([uint32]$sig[$jgOff + 1] -shl 8) -bor `
                     ([uint32]$sig[$jgOff + 2] -shl 16) -bor ([uint32]$sig[$jgOff + 3] -shl 24)
                if (($w -band 0xFF00001F) -ne 0x5400000C) {
                    throw ("milestone $msName site '$siteName': jgOff is not a stock b.gt (GT) B.cond word (0x{0:X8})" -f $w)
                }
            }
            if ($kind -eq 4) {
                if (($jgOff + 3) -ge $sig.Length) {
                    throw "milestone $msName site '$siteName': cbz needs 4 bytes but sig ends early"
                }
                if (($jgOff % 4) -ne 0) {
                    throw "milestone $msName site '$siteName': cbz jgOff must be word-aligned (4-byte steps)"
                }
                # Stock CBZ word (little-endian): 32-bit w-register CBZ 0x34.......
                $w = [uint32]$sig[$jgOff] -bor ([uint32]$sig[$jgOff + 1] -shl 8) -bor `
                     ([uint32]$sig[$jgOff + 2] -shl 16) -bor ([uint32]$sig[$jgOff + 3] -shl 24)
                if (($w -band 0xFF000000) -ne 0x34000000) {
                    throw ("milestone $msName site '$siteName': jgOff is not a stock 32-bit CBZ word (0x{0:X8})" -f $w)
                }
            }
            $expected = [int]$rs.expectedMatches
            if ($expected -lt 1) {
                throw "milestone $($rm.name) site '$($rs.name)': expectedMatches must be >= 1"
            }

            $sites += [pscustomobject]@{
                Name            = $siteName
                Kind            = $kind
                Optional        = $optional
                JgRVA           = [uint32]([Convert]::ToUInt32($rs.jgRVA, 16))
                Sig             = $sig
                JgOff           = $jgOff
                ExpectedMatches = $expected
            }
        }
        $out += [pscustomobject]@{ Name = $msName; Container = $container; Sites = $sites }
    }
    return $out
}

# ============================================================================
# Image layer - PE only. chrome.dll is a PE; this Windows-only
# script does not handle the Linux ELF 'chrome'.
# ============================================================================

# Entry point of the image layer: sniff the container and hand off. Only 'MZ' is
# accepted, so a mistyped path to some other file fails here, before any write.
function Open-Image {
    param([byte[]]$Buf)

    if ($Buf.Length -ge 2 -and $Buf[0] -eq 0x4D -and $Buf[1] -eq 0x5A) { return Open-PeImage $Buf }
    throw "That doesn't look like a Chrome file (this tool only works on chrome.dll)."
}

# Validates a PE32 or PE32+ and records only bounds-checked
# offsets, so every later read/write is safe.
function Open-PeImage {
    param([byte[]]$Buf)

    if ($Buf.Length -lt 64) { throw "not a valid Chrome file: file too small" }
    $eLfanew = [BitConverter]::ToUInt32($Buf, 0x3C)

    if (($eLfanew + 24) -gt $Buf.Length) { throw "not a valid Chrome file: truncated NT headers" }
    if ($Buf[$eLfanew] -ne 0x50 -or $Buf[$eLfanew+1] -ne 0x45 -or
        $Buf[$eLfanew+2] -ne 0 -or $Buf[$eLfanew+3] -ne 0) { throw "not a valid Chrome file: bad NT signature" }

    $numSections  = [BitConverter]::ToUInt16($Buf, $eLfanew + 6)
    $sizeOfOptHdr = [BitConverter]::ToUInt16($Buf, $eLfanew + 20)
    $optOff       = [int64]$eLfanew + 24
    if (($optOff + $sizeOfOptHdr) -gt $Buf.Length) { throw "not a valid Chrome file: optional header out of bounds" }

    $magic = [BitConverter]::ToUInt16($Buf, $optOff)
    switch ($magic) {
        0x20B   { $fixedLen = 112; $is32 = $false }   # PE32+ (x86-64)
        0x10B   { $fixedLen = 96;  $is32 = $true  }   # PE32  (x86)
        default { throw ("not a valid Chrome file: unsupported optional header magic 0x{0:X}" -f $magic) }
    }
    if ($sizeOfOptHdr -lt ($fixedLen + 5 * 8)) {
        throw "not a valid Chrome file: optional header too small for data directories"
    }

    $secOff = $optOff + $sizeOfOptHdr
    if (($secOff + [int64]$numSections * 40) -gt $Buf.Length) { throw "not a valid Chrome file: section table out of bounds" }

    $textRVA = 0; $textRaw = 0; $textSize = 0
    $rdataRVA = 0; $rdataRaw = 0; $rdataSize = 0
    for ($i = 0; $i -lt $numSections; $i++) {
        $sh = $secOff + $i * 40
        $name = [Text.Encoding]::ASCII.GetString($Buf, $sh, 8).TrimEnd([char]0)
        if ($name -eq '.text') {
            $textRVA  = [BitConverter]::ToUInt32($Buf, $sh + 12)
            $textSize = [BitConverter]::ToUInt32($Buf, $sh + 16)   # SizeOfRawData
            $textRaw  = [BitConverter]::ToUInt32($Buf, $sh + 20)
        } elseif ($name -eq '.rdata') {
            $rdataRVA  = [BitConverter]::ToUInt32($Buf, $sh + 12)
            $rdataSize = [BitConverter]::ToUInt32($Buf, $sh + 16)  # SizeOfRawData
            $rdataRaw  = [BitConverter]::ToUInt32($Buf, $sh + 20)
        }
    }
    if ($textSize -eq 0) { throw "not a valid Chrome file: missing code section" }
    if ([int64]$textRaw -lt 0 -or [int64]$textRaw + [int64]$textSize -gt $Buf.LongLength) {
        throw "not a valid Chrome file: .text raw data is out of bounds"
    }
    # Clamp the featurebyte .rdata scan window to what's actually in the file.
    if (([int64]$rdataRaw + [int64]$rdataSize) -gt $Buf.LongLength) {
        $rdataSize = [math]::Max(0, $Buf.LongLength - [int64]$rdataRaw)
    }
    $imageBase = if ($is32) { [uint64][BitConverter]::ToUInt32($Buf, $optOff + 28) } `
                 else       { [BitConverter]::ToUInt64($Buf, $optOff + 24) }

    # PE32+ carries both x64 (machine 0x8664) and Windows-on-ARM arm64 (0xAA64);
    # the machine field splits them so an arm64 dll matches only pe-arm64
    # milestones (the arm64 'bcond' flip) and never the x64 'pe' jg tables.
    $machine = [BitConverter]::ToUInt16($Buf, $eLfanew + 4)
    $format  = if ($is32) { 'pe32' } elseif ($machine -eq 0xAA64) { 'pe-arm64' } else { 'pe' }

    return [pscustomobject]@{
        Format     = $format                               # matches a milestone's "container"
        TextRVA    = $textRVA
        TextRaw    = $textRaw
        TextSize   = $textSize
        RdataRVA   = $rdataRVA                              # featurebyte (.rdata) locator inputs
        RdataRaw   = $rdataRaw
        RdataSize  = $rdataSize
        ImageBase  = $imageBase
        ChecksumAt = $optOff + 64                          # same offset in PE32 and PE32+
        SecDirAt   = $optOff + $fixedLen + 4 * 8           # data directory [4] = Security
        NtHeaderAt = [int64]$eLfanew
        Machine    = $machine
        TimeStamp  = [BitConverter]::ToUInt32($Buf, $eLfanew + 8)
        Is32       = $is32
    }
}

# A non-zero Security Directory means an untouched, signed stock chrome.dll
# (this tool zeroes it when patching).
function Test-LikelyStock {
    param($Img, [byte[]]$Buf)
    $va = [BitConverter]::ToUInt32($Buf, $Img.SecDirAt)
    $sz = [BitConverter]::ToUInt32($Buf, $Img.SecDirAt + 4)
    return ($va -ne 0 -and $sz -ne 0)
}

# Clears the Authenticode Security Directory and writes the recomputed checksum
# (the finalize step).
function Complete-Image {
    param($Img, [byte[]]$Buf)

    $va = [BitConverter]::ToUInt32($Buf, $Img.SecDirAt)
    $sz = [BitConverter]::ToUInt32($Buf, $Img.SecDirAt + 4)
    if ($va -ne 0 -or $sz -ne 0) {
        [Array]::Clear($Buf, $Img.SecDirAt, 8)
    }

    Initialize-NativeHelpers
    $sum = [Mv2Native]::PeChecksum($Buf, $Img.ChecksumAt)
    [Array]::Copy([BitConverter]::GetBytes([uint32]$sum), 0, $Buf, $Img.ChecksumAt, 4)
}

function Get-ByteHash {
    param([byte[]]$Buf)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Buf))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-PeIdentity {
    param([byte[]]$Buf, $Img)
    return [pscustomobject]@{
        Format    = [string]$Img.Format
        Machine   = [uint16]$Img.Machine
        TimeStamp = [uint32]$Img.TimeStamp
        Length    = [int64]$Buf.LongLength
        SHA256    = Get-ByteHash $Buf
    }
}

function Test-SameBuildIdentity {
    param($A, $B)
    return ($A.Format -eq $B.Format -and [uint16]$A.Machine -eq [uint16]$B.Machine -and
        [uint32]$A.TimeStamp -eq [uint32]$B.TimeStamp -and [int64]$A.Length -eq [int64]$B.Length)
}

function Write-AtomicFile {
    param(
        [string]$TargetPath,
        [byte[]]$Buf,
        [string]$ExpectedCurrentHash = '',
        [string]$PreserveMetadataFrom = '',
        # Caller-supplied SHA-256 of $Buf. When set, the read-back verification
        # compares against it instead of re-hashing the 285 MB $Buf a second time
        # (the caller has usually just computed this hash).
        [string]$KnownBufHash = ''
    )

    $full = [IO.Path]::GetFullPath($TargetPath)
    $dir = [IO.Path]::GetDirectoryName($full)
    if (-not $dir) { $dir = (Get-Location).Path }
    $tmp = Join-Path $dir ('.chrome-mv2-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $old = Join-Path $dir ('.chrome-mv2-' + [Guid]::NewGuid().ToString('N') + '.old')

    try {
        $fs = New-Object IO.FileStream($tmp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
            [IO.FileShare]::None, 1048576, [IO.FileOptions]::WriteThrough)
        try {
            $fs.Write($Buf, 0, $Buf.Length)
            $fs.Flush($true)
        } finally { $fs.Dispose() }

        $written = [IO.File]::ReadAllBytes($tmp)
        $bufHash = if ($KnownBufHash) { $KnownBufHash } else { Get-ByteHash $Buf }
        if ($written.LongLength -ne $Buf.LongLength -or (Get-ByteHash $written) -ne $bufHash) {
            throw "Couldn't write to $TargetPath safely - nothing was changed."
        }

        if ($PreserveMetadataFrom -and (Test-Path -LiteralPath $PreserveMetadataFrom -PathType Leaf)) {
            try { [IO.File]::SetAttributes($tmp, [IO.File]::GetAttributes($PreserveMetadataFrom)) } catch { }
            try { Set-Acl -LiteralPath $tmp -AclObject (Get-Acl -LiteralPath $PreserveMetadataFrom) } catch { }
        }

        if ($ExpectedCurrentHash) {
            if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw 'The file went missing before we could update it.' }
            $now = Get-ByteHash ([IO.File]::ReadAllBytes($full))
            if ($now -ne $ExpectedCurrentHash.ToLowerInvariant()) {
                throw 'Chrome changed while we were working - nothing was changed. Try again.'
            }
        }

        if (Test-Path -LiteralPath $full -PathType Leaf) {
            [IO.File]::Replace($tmp, $full, $old, $true)
            Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue
        } else {
            [IO.File]::Move($tmp, $full)
        }
    } finally {
        if (Test-Path -LiteralPath $tmp -PathType Leaf) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        # If replacement succeeded but cleanup was interrupted, the .old file is
        # a recoverable copy of the previous target; remove it on normal unwind.
        if (Test-Path -LiteralPath $old -PathType Leaf) { Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue }
    }
}

function Get-BackupMetadataPath { param([string]$BackupPath) return "$BackupPath.json" }

# Delete a backup and its metadata sidecar. Called after a successful restore:
# the installed DLL is now the verified original, so the backup has served its
# purpose. A later 'patch' recreates it from the restored stock DLL.
function Remove-BackupFiles {
    param([string]$BackupPath)
    foreach ($p in @($BackupPath, (Get-BackupMetadataPath $BackupPath))) {
        if (Test-Path -LiteralPath $p -PathType Leaf) {
            try { Remove-Item -LiteralPath $p -Force -ErrorAction Stop }
            catch { Write-Warn "Couldn't delete a backup file: ${p}" }
        }
    }
}

function Save-BackupSnapshot {
    param([string]$TargetPath, [string]$BackupPath, [byte[]]$Buf, $Identity)

    Write-AtomicFile -TargetPath $BackupPath -Buf $Buf -PreserveMetadataFrom $TargetPath
    $meta = [ordered]@{
        Schema = 1; Format = $Identity.Format; Machine = $Identity.Machine
        TimeStamp = $Identity.TimeStamp; Length = $Identity.Length; SHA256 = $Identity.SHA256
    }
    $json = ($meta | ConvertTo-Json -Compress) + "`n"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    Write-AtomicFile -TargetPath (Get-BackupMetadataPath $BackupPath) -Buf $bytes
}

function Read-ValidatedBackup {
    param([string]$BackupPath)

    if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) { throw "No backup found at: $BackupPath" }
    $buf = [IO.File]::ReadAllBytes($BackupPath)
    if ($buf.Length -eq 0) { throw 'The backup file is empty.' }
    $img = Open-Image $buf
    $identity = Get-PeIdentity -Buf $buf -Img $img
    $metaPath = Get-BackupMetadataPath $BackupPath
    $legacy = -not (Test-Path -LiteralPath $metaPath -PathType Leaf)
    if (-not $legacy) {
        try { $meta = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json }
        catch { throw "The backup's info file looks wrong: ${metaPath}" }
        if ([int]$meta.Schema -ne 1 -or $meta.Format -ne $identity.Format -or
            [uint16]$meta.Machine -ne $identity.Machine -or [uint32]$meta.TimeStamp -ne $identity.TimeStamp -or
            [int64]$meta.Length -ne $identity.Length -or ([string]$meta.SHA256).ToLowerInvariant() -ne $identity.SHA256) {
            throw "The backup doesn't match its saved info - it may be damaged."
        }
    }
    return [pscustomobject]@{ Buf = $buf; Img = $img; Identity = $identity; Legacy = $legacy }
}

# ============================================================================
# Patching engine
# ============================================================================

# Pure-PowerShell signature match at ONE known offset - the recorded-RVA check in
# Find-AffectedJgSites, so the per-byte cost is irrelevant. It is what keeps an
# unmoved build off the compiled full-section scan.
#
# Mirrors Mv2Native.SigMatchesAt exactly (keep the two in sync): the opcode byte
# matches the stock jg OR the already-flipped form, and the displacement is
# wildcarded. Accepting the flipped form is what makes a re-run idempotent
# instead of "no known layout matched".
function Test-SigAt {
    param([byte[]]$Buf, [int64]$Start, [byte[]]$Sig, [int]$JgOff, [int]$Kind)

    if ($Start -lt 0 -or ($Start + $Sig.Length) -gt $Buf.LongLength) { return $false }
    if ($Kind -eq 2) {
        # arm64 B.cond word (little-endian) at JgOff: 0x54 opcode + bit4=0 fixed,
        # cond nibble in {0xC stock GT, 0xE patched AL}, imm19 wild.
        $w = [uint32]$Buf[$Start + $JgOff] -bor ([uint32]$Buf[$Start + $JgOff + 1] -shl 8) -bor `
             ([uint32]$Buf[$Start + $JgOff + 2] -shl 16) -bor ([uint32]$Buf[$Start + $JgOff + 3] -shl 24)
        if (($w -band 0xFF000010) -ne 0x54000000) { return $false }
        $cond = $w -band 0xF
        if ($cond -ne 0x0C -and $cond -ne 0x0E) { return $false }
    }
    if ($Kind -eq 4) {
        # arm64 CBZ word (little-endian) at JgOff: stock 32-bit CBZ (0x34, Rt =
        # the sig's, imm19 wild) or patched unconditional B (0x14) with the same
        # resolved target as the sig CBZ's.
        $w = [uint32]$Buf[$Start + $JgOff] -bor ([uint32]$Buf[$Start + $JgOff + 1] -shl 8) -bor `
             ([uint32]$Buf[$Start + $JgOff + 2] -shl 16) -bor ([uint32]$Buf[$Start + $JgOff + 3] -shl 24)
        $sw = [uint32]$Sig[$JgOff] -bor ([uint32]$Sig[$JgOff + 1] -shl 8) -bor `
              ([uint32]$Sig[$JgOff + 2] -shl 16) -bor ([uint32]$Sig[$JgOff + 3] -shl 24)
        $ok = $false
        if (($w -band 0xFF000000) -eq 0x34000000 -and (($w -band 0x1F) -eq ($sw -band 0x1F))) {
            $ok = $true
        } elseif (($w -band 0xFC000000) -eq 0x14000000) {
            $dc = [int]($w -band 0x03FFFFFF)
            if (($dc -band 0x2000000) -ne 0) { $dc -= 0x4000000 }
            $dr = [int](($sw -shr 5) -band 0x7FFFF)
            if (($dr -band 0x40000) -ne 0) { $dr -= 0x80000 }
            if ($dc -eq $dr) { $ok = $true }
        }
        if (-not $ok) { return $false }
    }
    for ($k = 0; $k -lt $Sig.Length; $k++) {
        $p = $Buf[$Start + $k]
        if ($Kind -eq 0) {
            if     ($k -eq $JgOff)     { if ($p -ne $Sig[$k] -and $p -ne 0xEB) { return $false } }
            elseif ($k -eq $JgOff + 1) { }                       # disp8 wildcard
            elseif ($p -ne $Sig[$k])   { return $false }
        } elseif ($Kind -eq 1) {
            if ($k -eq $JgOff) {
                $p1 = $Buf[$Start + $JgOff + 1]
                if (-not (($p -eq $Sig[$k] -and $p1 -eq $Sig[$k + 1]) -or ($p -eq 0x90 -and $p1 -eq 0xE9))) { return $false }
            }
            elseif ($k -eq $JgOff + 1) { }                         # pair checked above
            elseif ($k -ge $JgOff + 2 -and $k -le $JgOff + 5) { } # disp32 wildcard
            elseif ($p -ne $Sig[$k])   { return $false }
        } else {                                                   # bcond / cbz
            if ($k -ge $JgOff -and $k -le $JgOff + 3) { }         # branch word validated above
            elseif ($p -ne $Sig[$k])   { return $false }
        }
    }
    return $true
}

# Returns the patch-byte file offset if the SimpleFeatureData at $Base satisfies
# the featurebyte site's verify criteria and its patch byte is stock or patched;
# else -1. $Base is the struct's .name field (i.e. the struct start).
function Test-FeatureStruct {
    param([byte[]]$Buf, [int64]$Base, $Site, [int64]$Lo, [int64]$Hi)
    $poff = $Base + $Site.PatchOff
    if ($poff -lt $Lo -or $poff -ge $Hi) { return [int64](-1) }
    $b = $Buf[$poff]
    if ($b -ne $Site.Stock -and $b -ne $Site.Patched) { return [int64](-1) }
    foreach ($k in $Site.Verify.Keys) {
        $vo = $Base + [int]$k
        if ($vo -lt $Lo -or $vo -ge $Hi -or $Buf[$vo] -ne $Site.Verify[$k]) { return [int64](-1) }
    }
    return [int64]$poff
}

# featurebyte (.rdata data-byte) locator. Fast path: the recorded StructRVA. Else
# name-anchored: find the feature name literal, find 8-byte pointers to it (a
# struct's .name field), decode + verify each struct. Returns Found (patch-byte
# file offsets) and Relocated. The .rdata scan is a handful of compiled IndexOf
# calls, so it is cheap enough to run on every pass.
function Find-FeatureByteSite {
    param([byte[]]$Buf, $Img, $Site)
    $lo = [int64]$Img.RdataRaw; $hi = $lo + [int64]$Img.RdataSize
    if ([int64]$Img.RdataSize -le 0 -or [uint64]$Img.ImageBase -eq 0) {
        return [pscustomobject]@{ Found = @(); Relocated = $false }
    }
    if ($Site.StructRVA -ne 0 -and $Site.StructRVA -ge $Img.RdataRVA -and
        $Site.StructRVA -lt ($Img.RdataRVA + $Img.RdataSize)) {
        $base = $lo + ([int64]$Site.StructRVA - [int64]$Img.RdataRVA)
        $poff = Test-FeatureStruct -Buf $Buf -Base $base -Site $Site -Lo $lo -Hi $hi
        if ($poff -ge 0) { return [pscustomobject]@{ Found = @([int64]$poff); Relocated = $false } }
    }
    Initialize-NativeHelpers
    $needle = [byte[]](@([Text.Encoding]::ASCII.GetBytes($Site.Feature)) + [byte]0)
    $found = New-Object System.Collections.Generic.List[int64]
    $litPos = $lo
    while ($true) {
        $i = [Mv2Native]::IndexOf($Buf, $needle, $litPos, $hi)
        if ($i -lt 0) { break }
        $litPos = $i + 1
        $litRva = [uint64]$Img.RdataRVA + [uint64]($i - $lo)
        $va = [uint64]$Img.ImageBase + $litRva
        $ptr = [BitConverter]::GetBytes([uint64]$va)
        $p = $lo
        while ($true) {
            $j = [Mv2Native]::IndexOf($Buf, $ptr, $p, $hi)
            if ($j -lt 0) { break }
            $p = $j + 1
            $poff = Test-FeatureStruct -Buf $Buf -Base $j -Site $Site -Lo $lo -Hi $hi
            if ($poff -ge 0 -and -not $found.Contains([int64]$poff)) {
                $found.Add([int64]$poff)
                if ($found.Count -gt $Site.ExpectedMatches) {
                    return [pscustomobject]@{ Found = $found.ToArray(); Relocated = $true }
                }
            }
        }
    }
    return [pscustomobject]@{ Found = $found.ToArray(); Relocated = $true }
}

# Locates the jg gate for one site. First it checks the recorded RVA in pure
# PowerShell; only a miss falls through to the compiled full-section scan.
# Returns Found (file offsets of each jg opcode byte) and Relocated ($true when
# the hit came from the scan, i.e. this build moved the gate - reported to the
# user and a hint that the table's jgRVA is worth refreshing).
function Find-AffectedJgSites {
    param([byte[]]$Buf, $Img, $Site)

    if ($Site.Kind -eq 3) { return Find-FeatureByteSite -Buf $Buf -Img $Img -Site $Site }

    $textRVA = [int64]$Img.TextRVA; $textRaw = [int64]$Img.TextRaw; $textSize = [int64]$Img.TextSize

    # Shortcut only when the site is expected to be unique - a shared-body site
    # (expectedMatches > 1) must always scan so it finds every copy.
    if ($Site.ExpectedMatches -eq 1 -and
        $Site.JgRVA -ge $textRVA -and ($Site.JgRVA - $textRVA) -lt $textSize) {
        $jgRaw = $textRaw + ($Site.JgRVA - $textRVA)
        $sigStart = $jgRaw - $Site.JgOff
        if ($sigStart -ge 0 -and (Test-SigAt -Buf $Buf -Start $sigStart -Sig $Site.Sig -JgOff $Site.JgOff -Kind $Site.Kind)) {
            return [pscustomobject]@{ Found = @([int64]$jgRaw); Relocated = $false }
        }
    }

    if ($textSize -lt $Site.Sig.Length) {
        return [pscustomobject]@{ Found = @(); Relocated = $false }
    }

    Initialize-NativeHelpers
    $hits = [Mv2Native]::Scan($Buf, $textRaw, $textSize, $Site.Sig, $Site.JgOff, $Site.Kind, $Site.ExpectedMatches)
    return [pscustomobject]@{
        Found     = @($hits)
        Relocated = ($hits.Count -gt 0)
    }
}

# Picks the winning milestone and applies its flips to $Buf in place. A site is
# "satisfied" only when its signature matches EXACTLY expectedMatches times; a
# wrong count means the layout changed and the site is declined, never guessed.
# The milestone with the most satisfied sites wins.
#
# Returns:
#   Status     0 = nothing matched, caller declines; 1 = bytes were flipped;
#              2 = every located site was already patched (buffer unchanged)
#   Milestone  winning table's name, for output
#   Located    satisfied sites, out of Total sites in that milestone
#   Full       Located -eq Total; a partial patch may still leave MV2 blocked
#   Flips      sites now in the patched state, already-applied ones included
#   Written    @{ RVA; Bytes } per patched site for record-keeping
#   Relocated  at least one gate was found by scan, not at its recorded RVA
function Invoke-PatchMilestones {
    param(
        [byte[]]$Buf,
        $Img,
        [array]$Milestones,
        [bool]$AllowPartial = $false,
        [bool]$Apply = $true,
        [string]$Version = ''    # display-only: the target's detected version
    )

    # Ranking: a milestone whose EVERY site matched (full) always beats a partial
    # one, regardless of raw satisfied count; among full matches the one with MORE
    # sites wins (most specific), so a Chrome build's multi-site table is chosen
    # over a coexisting single-site Chromium table (same container tag) and vice-
    # versa. Among partials the most-satisfied wins. A genuine equal-rank collision
    # (two fulls of the same size, or two equal partials) bumps $bestCount and the
    # caller declines when $bestCount > 1.
    $best = $null
    $bestCount = 0
    foreach ($ms in $Milestones) {
        $flips = @(); $satisfied = 0; $required = 0
        foreach ($s in $ms.Sites) {
            $r = Find-AffectedJgSites -Buf $Buf -Img $Img -Site $s
            $isOptional = ($s.PSObject.Properties['Optional'] -and $s.Optional)
            if ($isOptional) {
                # Best-effort: apply if located, but never count toward ranking, so
                # a miss can't drop the milestone to partial or block the MV2 gates.
                if ($r.Found.Count -eq $s.ExpectedMatches) {
                    foreach ($off in $r.Found) {
                        $flips += [pscustomobject]@{ Site = $s; JgRaw = $off; Relocated = $r.Relocated }
                    }
                }
                continue
            }
            $required++
            if ($r.Found.Count -eq $s.ExpectedMatches) {
                $satisfied++
                foreach ($jgRaw in $r.Found) {
                    $flips += [pscustomobject]@{ Site = $s; JgRaw = $jgRaw; Relocated = $r.Relocated }
                }
            }
        }
        if ($satisfied -eq 0) { continue }
        $total    = $required
        $candFull = ($satisfied -eq $total)
        $bestFull = ($null -ne $best -and $best.Satisfied -eq $best.Required)

        $take = $false; $tie = $false
        if ($null -eq $best) {
            $take = $true                                  # first candidate
        } elseif ($candFull -and -not $bestFull) {
            $take = $true                                  # full beats partial
        } elseif ($candFull -and $bestFull -and $total -gt $best.Required) {
            $take = $true                                  # more specific full
        } elseif (-not $candFull -and -not $bestFull -and $satisfied -gt $best.Satisfied) {
            $take = $true                                  # more of a partial matched
        } elseif (($candFull -and $bestFull -and $total -eq $best.Required) -or
                  (-not $candFull -and -not $bestFull -and $satisfied -eq $best.Satisfied)) {
            $tie = $true                                   # genuine equal-rank collision
        }

        if ($take) {
            $best = [pscustomobject]@{ Ms = $ms; Flips = $flips; Satisfied = $satisfied; Required = $required }
            $bestCount = 1
        } elseif ($tie) {
            $bestCount++
        }
    }

    $res = [pscustomobject]@{
        Status = 0; Milestone = ''; Located = 0; Total = 0; Flips = 0
        Full = $false; Written = @(); Relocated = $false; Reason = ''
        Stock = 0; Already = 0
    }
    if ($null -eq $best -or $best.Satisfied -eq 0) { return $res }

    $res.Milestone = $best.Ms.Name
    $res.Located   = $best.Satisfied
    $res.Total     = $best.Required
    $res.Full      = ($best.Satisfied -eq $best.Required)

    if ($bestCount -gt 1) {
        $res.Reason = "$bestCount possible Chrome versions tied - can't tell which one this is"
        Write-Warn $res.Reason
        return $res
    }
    if (-not $res.Full -and -not $AllowPartial) {
        $res.Reason = "only $($res.Located) of $($res.Total) changes matched; a partial patch needs -AllowPartial"
        Write-Warn $res.Reason
        return $res
    }

    $label = Get-ChromeLabel -Version $Version -Milestone $best.Ms.Name
    Write-Info "Applying $($best.Flips.Count) change(s)..."

    # Three cases per site: already flipped (counted, nothing written), stock jg
    # (flip it), anything else (left alone with a warning - never guess).
    $applied = 0; $already = 0
    foreach ($f in $best.Flips) {
        if ($f.Site.Kind -eq 3) {
            $jgRVA = [uint32]($Img.RdataRVA + ($f.JgRaw - $Img.RdataRaw))
        } else {
            $jgRVA = [uint32]($Img.TextRVA + ($f.JgRaw - $Img.TextRaw))
        }
        $ms    = $best.Ms.Name
        if ($f.Relocated) { $res.Relocated = $true }

        if ($f.Site.Kind -eq 0) {
            $cur = $Buf[$f.JgRaw]
            if ($cur -eq 0xEB) {
                $already++; $res.Already++
                $res.Written += [pscustomobject]@{ RVA = $jgRVA; Off = [int64]$f.JgRaw; Bytes = [byte[]]@(0xEB) }
                continue
            }
            if ($cur -ne $f.Site.Sig[$f.Site.JgOff]) {
                Write-Host ("    {0} Skipped one change - it didn't look the way we expected." -f $script:TagWarn)
                continue
            }
            $res.Stock++
            if ($Apply) { $Buf[$f.JgRaw] = 0xEB }          # jg -> jmp short
            $applied++; $res.Flips++
            $res.Written += [pscustomobject]@{ RVA = $jgRVA; Off = [int64]$f.JgRaw; Bytes = [byte[]]@(0xEB) }
        } elseif ($f.Site.Kind -eq 1) {
            $o0 = $Buf[$f.JgRaw]; $o1 = $Buf[$f.JgRaw + 1]
            if ($o0 -eq 0x90 -and $o1 -eq 0xE9) {
                $already++; $res.Already++
                $res.Written += [pscustomobject]@{ RVA = $jgRVA; Off = [int64]$f.JgRaw; Bytes = [byte[]]@(0x90, 0xE9) }
                continue
            }
            if (-not ($o0 -eq $f.Site.Sig[$f.Site.JgOff] -and $o1 -eq $f.Site.Sig[$f.Site.JgOff + 1])) {
                Write-Host ("    {0} Skipped one change - it didn't look the way we expected." -f $script:TagWarn)
                continue
            }
            $res.Stock++
            if ($Apply) {
                $Buf[$f.JgRaw]     = 0x90      # nop
                $Buf[$f.JgRaw + 1] = 0xE9      # jmp near (keeps the disp32)
            }
            $applied++; $res.Flips++
            $res.Written += [pscustomobject]@{ RVA = $jgRVA; Off = [int64]$f.JgRaw; Bytes = [byte[]]@(0x90, 0xE9) }
        } elseif ($f.Site.Kind -eq 3) {
            # featurebyte: overwrite one .rdata data byte (stock -> patched). Same
            # three cases: already patched, stock (write it), anything else (skip).
            $cur = $Buf[$f.JgRaw]
            if ($cur -eq $f.Site.Patched) {
                $already++; $res.Already++
                $res.Written += [pscustomobject]@{ RVA = $jgRVA; Off = [int64]$f.JgRaw; Bytes = [byte[]]@($f.Site.Patched) }
                continue
            }
            if ($cur -ne $f.Site.Stock) {
                Write-Host ("    {0} Skipped one change - it didn't look the way we expected." -f $script:TagWarn)
                continue
            }
            $res.Stock++
            if ($Apply) { $Buf[$f.JgRaw] = $f.Site.Patched }
            $applied++; $res.Flips++
            $res.Written += [pscustomobject]@{ RVA = $jgRVA; Off = [int64]$f.JgRaw; Bytes = [byte[]]@($f.Site.Patched) }
        } elseif ($f.Site.Kind -eq 4) {
            # cbz (arm64): rewrite the 32-bit CBZ word to the unconditional B with
            # the SAME resolved target - imm26 is recomputed from the sign-extended
            # imm19 (the field layouts differ, so the raw bits never carry over).
            $w = [uint32]$Buf[$f.JgRaw] -bor ([uint32]$Buf[$f.JgRaw + 1] -shl 8) -bor `
                 ([uint32]$Buf[$f.JgRaw + 2] -shl 16) -bor ([uint32]$Buf[$f.JgRaw + 3] -shl 24)
            $sw = [uint32]$f.Site.Sig[$f.Site.JgOff] -bor ([uint32]$f.Site.Sig[$f.Site.JgOff + 1] -shl 8) -bor `
                  ([uint32]$f.Site.Sig[$f.Site.JgOff + 2] -shl 16) -bor ([uint32]$f.Site.Sig[$f.Site.JgOff + 3] -shl 24)
            if (($w -band 0xFC000000) -eq 0x14000000) {
                # patched form? only ours if the target matches the sig CBZ's
                $dc = [int]($w -band 0x03FFFFFF)
                if (($dc -band 0x2000000) -ne 0) { $dc -= 0x4000000 }
                $dr = [int](($sw -shr 5) -band 0x7FFFF)
                if (($dr -band 0x40000) -ne 0) { $dr -= 0x80000 }
                if ($dc -eq $dr) {
                    $already++; $res.Already++
                    $res.Written += [pscustomobject]@{ RVA = $jgRVA; Off = [int64]$f.JgRaw; Bytes = [byte[]]@($Buf[$f.JgRaw], $Buf[$f.JgRaw + 1], $Buf[$f.JgRaw + 2], $Buf[$f.JgRaw + 3]) }
                    continue
                }
                Write-Host ("    {0} Skipped one change - it didn't look the way we expected." -f $script:TagWarn)
                continue
            }
            if (-not ((($w -band 0xFF000000) -eq 0x34000000) -and (($w -band 0x1F) -eq ($sw -band 0x1F)))) {
                Write-Host ("    {0} Skipped one change - it didn't look the way we expected." -f $script:TagWarn)
                continue
            }
            $imm19 = [int](($w -shr 5) -band 0x7FFFF)
            if (($imm19 -band 0x40000) -ne 0) { $imm19 -= 0x80000 }
            $newW = [uint32](0x14000000 -bor ($imm19 -band 0x3FFFFFF))
            $newBytes = [byte[]]@([byte]($newW -band 0xFF), [byte](($newW -shr 8) -band 0xFF), [byte](($newW -shr 16) -band 0xFF), [byte](($newW -shr 24) -band 0xFF))
            $res.Stock++
            if ($Apply) {
                for ($bi = 0; $bi -lt 4; $bi++) { $Buf[$f.JgRaw + $bi] = $newBytes[$bi] }
            }
            $applied++; $res.Flips++
            $res.Written += [pscustomobject]@{ RVA = $jgRVA; Off = [int64]$f.JgRaw; Bytes = $newBytes }
        } else {
            # bcond (arm64): the branch's cond nibble is the low nibble of byte0.
            # Flip GT (0xC) -> AL (0xE); imm19 and everything else are preserved,
            # so a valid branch to its existing target simply becomes unconditional.
            $cur     = $Buf[$f.JgRaw]
            $cond    = $cur -band 0x0F
            $patched = [byte](($cur -band 0xF0) -bor 0x0E)
            if ($cond -eq 0x0E) {
                $already++; $res.Already++
                $res.Written += [pscustomobject]@{ RVA = $jgRVA; Off = [int64]$f.JgRaw; Bytes = [byte[]]@($patched) }
                continue
            }
            if ($cond -ne 0x0C) {
                Write-Host ("    {0} Skipped one change - it didn't look the way we expected." -f $script:TagWarn)
                continue
            }
            $res.Stock++
            if ($Apply) { $Buf[$f.JgRaw] = $patched }      # b.gt -> b.al (cond GT->AL)
            $applied++; $res.Flips++
            $res.Written += [pscustomobject]@{ RVA = $jgRVA; Off = [int64]$f.JgRaw; Bytes = [byte[]]@($patched) }
        }
    }
    $res.Flips += $already   # count already-applied sites toward the flip total

    if (-not $res.Full) {
        Write-Host ("    {0} {1} of {2} change(s) couldn't be found for Chrome {3}, so this may not fully work. Please report this Chrome version." -f `
            $script:TagWarn, ($res.Total - $res.Located), $res.Total, $label)
    }

    $res.Status = if ($applied -gt 0) { 1 } else { 2 }
    return $res
}

function Test-PatchOutput {
    param([byte[]]$Buf, $Img, $Patch)
    foreach ($w in $Patch.Written) {
        $off = [int64]$w.Off      # absolute file offset (correct for .text and .rdata)
        if ($off -lt 0 -or $off + $w.Bytes.Length -gt $Buf.LongLength) { return $false }
        for ($i = 0; $i -lt $w.Bytes.Length; $i++) {
            if ($Buf[$off + $i] -ne $w.Bytes[$i]) { return $false }
        }
    }
    return ($Patch.Written.Count -gt 0)
}

function Get-CleanStockLayout {
    param([byte[]]$Buf, $Img, [array]$Milestones, [bool]$AllowPartialLayout = $false)
    # A read-only validation probe: Invoke-PatchMilestones with -Apply $false
    # never writes to $Buf, so it is passed through directly (no defensive clone
    # of the 285 MB buffer). Suppress the per-site "stock jg at RVA ..." host
    # output (stream 6) - callers print their own one-line summary.
    $probe = Invoke-PatchMilestones -Buf $Buf -Img $Img -Milestones $Milestones `
        -AllowPartial $AllowPartialLayout -Apply $false 6>$null
    $clean = ($probe.Status -ne 0 -and $probe.Stock -gt 0 -and $probe.Already -eq 0 -and
        ($probe.Full -or $AllowPartialLayout) -and -not $probe.Reason)
    return [pscustomobject]@{ Clean = $clean; Probe = $probe }
}

# Report-only structural scan for the decline path. Never writes anything: it
# prints up to 20 cmp/jg skeletons that LOOK like a gate, as a starting point for
# deriving a new milestone by hand. Heuristic, so expect false positives.
function Show-LayoutCandidates {
    param([byte[]]$Buf, $Img)

    if ($Img.TextSize -lt 8) { return }
    Write-Info "This Chrome version isn't recognized yet. Looking for clues to help add support..."
    Initialize-NativeHelpers

    $hits = [Mv2Native]::SkeletonScan($Buf, [int64]$Img.TextRaw, [int64]$Img.TextSize)
    $maxDisplay = 20
    $shown = 0
    foreach ($cmpStart in $hits) {
        if ($shown -ge $maxDisplay) { break }
        $rva = [uint32]($Img.TextRVA + $cmpStart)
        $len = [Math]::Min(24, $Img.TextSize - $cmpStart)
        $slice = [byte[]]::new($len)
        [Array]::Copy($Buf, $Img.TextRaw + $cmpStart, $slice, 0, $len)
        Write-Host ("    [candidate] RVA 0x{0:X}: {1}" -f $rva, (Format-HexUpper $slice))
        $shown++
    }
    $extra = if ($hits.Count -gt $shown) { " ($($hits.Count - $shown) not shown)" } else { '' }
    Write-Info ("Found {0} possible spot(s){1}. Nothing was changed - please share this and your Chrome version with the developer." -f $hits.Count, $extra)
}

# ============================================================================
# Windows host glue: who has chrome.dll open, and are we admin.
# ============================================================================

# Restart Manager (rstrtmgr) + CreateFileW P/Invoke. Loaded on demand, and only
# once - the ('Mv2Win32' -as [type]) probe is the guard, since Add-Type cannot
# redefine a type in the same session.
function Initialize-Win32 {
    if ('Mv2Win32' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class Mv2Win32
{
    [StructLayout(LayoutKind.Sequential)]
    public struct RM_UNIQUE_PROCESS { public int dwProcessId; public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime; }

    const int CCH_RM_MAX_APP_NAME = 255;
    const int CCH_RM_MAX_SVC_NAME = 63;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)] public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)] public string strServiceShortName;
        public int ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmRegisterResources(uint pSessionHandle, uint nFiles, string[] rgsFilenames,
        uint nApplications, IntPtr rgApplications, uint nServices, string[] rgsServiceNames);
    [DllImport("rstrtmgr.dll")]
    static extern int RmGetList(uint dwSessionHandle, out uint pnProcInfoNeeded, ref uint pnProcInfo,
        [In, Out] RM_PROCESS_INFO[] rgAffectedApps, ref uint lpdwRebootReasons);
    [DllImport("rstrtmgr.dll")]
    static extern int RmEndSession(uint pSessionHandle);

    // Returns "pid|starttime|appname" for each process holding the file, so the
    // caller can validate the PID has not been recycled before terminating it.
    public static string[] GetFileHolders(string path)
    {
        uint session; var key = Guid.NewGuid().ToString();
        var results = new List<string>();
        if (RmStartSession(out session, 0, key) != 0) return results.ToArray();
        try
        {
            if (RmRegisterResources(session, 1, new[] { path }, 0, IntPtr.Zero, 0, null) != 0)
                return results.ToArray();

            uint needed = 0, got = 0, reason = 0;
            RmGetList(session, out needed, ref got, null, ref reason);
            if (needed == 0) return results.ToArray();

            var info = new RM_PROCESS_INFO[needed];
            got = needed;
            if (RmGetList(session, out needed, ref got, info, ref reason) != 0)
                return results.ToArray();

            for (int i = 0; i < got; i++)
            {
                ulong ft = ((ulong)(uint)info[i].Process.ProcessStartTime.dwHighDateTime << 32)
                         | (uint)info[i].Process.ProcessStartTime.dwLowDateTime;
                results.Add(info[i].Process.dwProcessId + "|" + ft + "|" + info[i].strAppName);
            }
        }
        finally { RmEndSession(session); }
        return results.ToArray();
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
    const uint OPEN_EXISTING = 3, FILE_ATTRIBUTE_NORMAL = 0x80;
    const int ERROR_SHARING_VIOLATION = 32, ERROR_LOCK_VIOLATION = 33;

    // Open for write with no sharing; a sharing/lock violation means a running
    // process has it mapped. Any other failure is a permissions problem.
    public static bool IsFileLocked(string path)
    {
        IntPtr h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (h != new IntPtr(-1)) { CloseHandle(h); return false; }
        int err = Marshal.GetLastWin32Error();
        return err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION;
    }

    delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")]
    static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll")]
    static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("user32.dll")]
    static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern bool PostMessageW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    const uint WM_CLOSE = 0x0010;

    // Asks every visible top-level window these processes own to close - the
    // same request the window's X button sends, which is what makes Chrome shut
    // down cleanly and write its session out, so the tabs can come back.
    // Returns how many windows were asked. Process.CloseMainWindow is NOT
    // equivalent: it reaches one window per process, and a Chrome session
    // normally has several.
    public static int CloseWindows(int[] pids)
    {
        var want = new List<uint>();
        foreach (int p in pids) want.Add((uint)p);
        int asked = 0;
        EnumWindows(delegate(IntPtr hWnd, IntPtr lParam) {
            uint owner; GetWindowThreadProcessId(hWnd, out owner);
            if (want.Contains(owner) && IsWindowVisible(hWnd)
                && PostMessageW(hWnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero)) asked++;
            return true;
        }, IntPtr.Zero);
        return asked;
    }

    // How many visible top-level windows these processes still have. Chrome with
    // "keep running in the background" on answers WM_CLOSE by closing its windows
    // and staying alive, so a caller waiting for the file to be released needs to
    // know the difference between "still shutting down" and "not going to exit".
    public static int CountWindows(int[] pids)
    {
        var want = new List<uint>();
        foreach (int p in pids) want.Add((uint)p);
        int n = 0;
        EnumWindows(delegate(IntPtr hWnd, IntPtr lParam) {
            uint owner; GetWindowThreadProcessId(hWnd, out owner);
            if (want.Contains(owner) && IsWindowVisible(hWnd)) n++;
            return true;
        }, IntPtr.Zero);
        return n;
    }
}
'@
}

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ElevationHint {
    return "This needs administrator access to change Chrome.`n    Right-click PowerShell and choose 'Run as administrator', then try again."
}

function Get-QuotedArg {
    param([string]$s)
    # CommandLineToArgvW rules: wrap in quotes if empty or containing whitespace
    # or a quote, escaping embedded quotes as \". Adequate for switches and
    # Windows file paths (no trailing-backslash / embedded-quote cases here).
    if ($s -eq '' -or $s -match '[\s"]') { return '"' + ($s -replace '"', '\"') + '"' }
    return $s
}

<#
Recovers this file's own source text, needed when there is no script file to
point -File at (`irm ... | iex`). $PSCommandPath is empty there, but every
function in the file was compiled from ONE scriptblock spanning the whole file,
so that scriptblock's AST hands the text back verbatim.

Returns $null when the text cannot be trusted - notably when the body arrived in
fragments (pasted into a console chunk by chunk), where the AST covers only the
fragment that happened to define the function. Both ends of the file must be
present for the copy to count as whole.
#>
function Get-SelfSourceText {
    $src = $null
    try { $src = ${function:Invoke-SelfElevate}.Ast.Extent.StartScriptPosition.GetFullScript() }
    catch { return $null }
    if (-not $src) { return $null }
    # A fragment can still parse, and a whole file can still be broken, so check
    # both: the two ends of the file must be there AND the text must parse. If
    # either anchor below is ever edited away, the elevation test in
    # scripts/test_windows.py fails rather than this silently refusing.
    if ($src -notmatch '(?m)^function Invoke-Main\b') { return $null }
    if ($src -notmatch '(?m)^exit \$exitCode\s*$') { return $null }
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$parseErrors)
    if ($parseErrors -and $parseErrors.Count) { return $null }
    return $src
}

<#
Stages the recovered source in a private temp directory so the elevated child has
a real file to run. Returns $null when the source could not be recovered.

The staged copy is then held open on a READ handle (FileAccess Read, FileShare
Read) for as long as the child runs. That combination lets the child open it for
reading while denying write and delete to everything else, so the file cannot be
swapped in the window between UAC consent and the elevated child loading it.
Holding a WRITE handle instead would break the child: its own read open asks for
a share mode that excludes writers, which our write access would violate.
#>
function New-SelfStage {
    $src = Get-SelfSourceText
    if (-not $src) { return $null }

    $dir  = Join-Path ([IO.Path]::GetTempPath()) ('chrome-mv2-' + [Guid]::NewGuid().ToString('N'))
    $path = Join-Path $dir 'chrome-mv2.ps1'
    try {
        [void][IO.Directory]::CreateDirectory($dir)
        # BOM so the child reads it as UTF-8 whatever the host's default is.
        [IO.File]::WriteAllText($path, $src, (New-Object Text.UTF8Encoding($true)))
        $handle = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        return @{ Path = $path; Dir = $dir; Handle = $handle }
    } catch {
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        return $null
    }
}

function Remove-SelfStage {
    param($Stage)
    if (-not $Stage) { return }
    try { $Stage.Handle.Dispose() } catch { }
    Remove-Item -LiteralPath $Stage.Dir -Recurse -Force -ErrorAction SilentlyContinue
}

<#
Re-launches this script elevated via Start-Process -Verb RunAs, which raises the
UAC consent dialog (a compiled exe would get the same effect from a
requireAdministrator manifest). Returns the elevated child's
exit code, or $null when elevation was declined/impossible so the caller can
fall back to the plain "you need admin" message.

The child is ALWAYS started as -File <script>, so there is one relaunch shape to
reason about. Normally the script already is a file on disk ($PSCommandPath is
set) and is used as-is; under `irm https://.../chrome-mv2.ps1 | iex` there is no
file, so the source is staged to a temp one first (see New-SelfStage).

Earlier versions instead replayed the process's own command line under RunAs,
which meant parsing powershell.exe's argv to find the -Command payload and
prefixing an `$env:MV2_RELAUNCHED='1';` guard into it. That only ever worked for
a literal `-Command`/`-EncodedCommand` token: the documented one-liner
`powershell "irm ...|iex"` puts the command in the implicit positional slot with
no switch to find, and an abbreviation the host does accept (-Com, -Comm) missed
too. Both failed with "cannot ask for administrator access this way".

Staging removes that whole class of bug: the loop guard and the target are
ordinary parameters (-Relaunched, positional path), so nothing has to survive the
UAC boundary in-band - and env vars would NOT survive it. It also means the
elevated run is the very code that just ran, instead of a second download.

Details:
  * Arguments are quoted so a path with spaces ("C:\Program Files\...") stays one
    argument instead of splitting.
  * -WorkingDirectory is pinned to the current directory (an elevated process
    otherwise starts in system32), so a relative target path still resolves.
  * -Wait -PassThru is required for $p.ExitCode to be populated.

NOTE: parameters are forwarded explicitly - a new user-facing switch has to be
added to the $argv list below or it is silently dropped on the elevated run.
#>
function Invoke-SelfElevate {
    param([string]$ResolvedTargetPath)
    # Prefer the current host (pwsh vs powershell.exe) so PS7 stays on PS7.
    $exe = (Get-Process -Id $PID).Path
    if (-not $exe) { $exe = if ($PSVersionTable.PSVersion.Major -ge 6) { 'pwsh.exe' } else { 'powershell.exe' } }

    $scriptPath = $PSCommandPath
    $stage = $null
    if (-not ($scriptPath -and (Test-Path -LiteralPath $scriptPath -PathType Leaf))) {
        $stage = New-SelfStage
        if (-not $stage) {
            # Nothing runnable to hand the elevated child - refuse rather than
            # risk a UAC loop.
            Write-Warn 'Cannot ask for administrator access this way; re-run from an admin terminal.'
            return $null
        }
        $scriptPath = $stage.Path
    }

    try {
        $argv = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Get-QuotedArg $scriptPath), $Command)
        if ($ResolvedTargetPath)  { $argv += (Get-QuotedArg $ResolvedTargetPath) }
        if ($Yes)   { $argv += '-Yes' }
        if ($Quiet) { $argv += '-Quiet' }
        if ($AllowPartial) { $argv += '-AllowPartial' }
        if ($ForceRestore) { $argv += '-ForceRestore' }
        if ($NoReopen) { $argv += '-NoReopen' }
        if ($Signatures) { $argv += '-Signatures'; $argv += (Get-QuotedArg ([IO.Path]::GetFullPath($Signatures))) }
        $argv += '-Relaunched'

        Write-Info 'Asking for admin access...'
        try {
            $p = Start-Process -FilePath $exe -ArgumentList ($argv -join ' ') -Verb RunAs `
                               -WorkingDirectory (Get-Location).Path -Wait -PassThru -ErrorAction Stop
            return $p.ExitCode
        } catch {
            # 1223 = ERROR_CANCELLED: the user dismissed the UAC dialog.
            Write-Warn 'Admin access was declined - nothing was changed.'
            return $null
        }
    } finally {
        Remove-SelfStage $stage
    }
}

function Test-TargetLocked {
    param([string]$TargetPath)
    Initialize-Win32
    return [Mv2Win32]::IsFileLocked($TargetPath)
}

# True while the selected browser is running. Identified by process, not by the
# holder list: Restart Manager also reports whatever else happens to have the
# file open (an antivirus scanning it, the shell, a backup agent), and treating
# those as "the browser is running" is what makes a close look like it never
# worked.
function Test-BrowserRunning {
    param($Target)
    return ((@(Get-BrowserProcesses -TargetPath $Target.Path)).Count -gt 0)
}

# Polls until the file can be replaced: nothing holds it against a write, and no
# browser process of this install is left. TimeoutMs 0 = check once.
#
# The lock probe is the gate that matters, because it asks the one question the
# write needs answered. It is NOT a holder-list check: a process can have
# chrome.dll open for reading (every scanner does) without stopping the replace.
function Wait-TargetUnlocked {
    param([string]$TargetPath, [int]$TimeoutMs)
    $deadline = [Environment]::TickCount + $TimeoutMs
    while ($true) {
        if (-not (Test-TargetLocked -TargetPath $TargetPath) -and
            (@(Get-BrowserProcesses -TargetPath $TargetPath)).Count -eq 0) { return $true }
        if ([Environment]::TickCount -ge $deadline) { return $false }
        Start-Sleep -Milliseconds 250
    }
}

# Polls until the browser has the file mapped again - how a reopen is confirmed
# rather than assumed (the shell hand-off in Start-AsDesktopUser is fire and
# forget, so the launch itself reports nothing).
function Wait-BrowserRunning {
    param($Target, [int]$TimeoutMs)
    $deadline = [Environment]::TickCount + $TimeoutMs
    while ($true) {
        if (Test-BrowserRunning -Target $Target) { return $true }
        if ([Environment]::TickCount -ge $deadline) { return $false }
        Start-Sleep -Milliseconds 250
    }
}

# Unpacks the "pid|starttime|appname" rows from Mv2Win32.GetFileHolders. Empty
# when nothing holds the file (or Restart Manager refused the query).
function Get-FileHolders {
    param([string]$TargetPath)
    Initialize-Win32
    $out = @()
    foreach ($row in [Mv2Win32]::GetFileHolders($TargetPath)) {
        $parts = $row -split '\|', 3
        $out += [pscustomobject]@{
            Pid = [int]$parts[0]; StartTime = [uint64]$parts[1]; AppName = $parts[2]
        }
    }
    return $out
}

# The processes to close: the browser and its children. Identified by image path
# when there is a chrome.exe next to the target, and otherwise by Restart Manager,
# whose PIDs are validated against the process start time it saw (PIDs recycle).
#
# Anything else RM reports is NEVER returned, so it is never terminated. An
# antivirus scanning chrome.dll, the shell, a backup agent - killing a stranger's
# process to patch a browser is not a trade this tool makes, and the write does
# not need it: those hold the file for reading, which does not block the replace.
function Get-BrowserProcesses {
    param([string]$TargetPath)

    $exe = Get-BrowserExePath -TargetPath $TargetPath
    $found = @{}
    if ($exe) {
        foreach ($p in @(Get-Process -Name 'chrome', 'chromium' -ErrorAction SilentlyContinue)) {
            try { if ($p.Path -and $p.Path -eq $exe) { $found[$p.Id] = $p } } catch { }
        }
    }
    foreach ($h in @(Get-FileHolders -TargetPath $TargetPath)) {
        if ($found.ContainsKey($h.Pid)) { continue }
        try {
            $p = Get-Process -Id $h.Pid -ErrorAction Stop
            if ($h.StartTime -ne 0 -and [uint64]$p.StartTime.ToFileTime() -ne $h.StartTime) { continue }
            if ($p.ProcessName -notin 'chrome', 'chromium') { continue }
            if ($exe -and $p.Path -and $p.Path -ne $exe) { continue }   # a different install
            $found[$p.Id] = $p
        } catch { }
    }
    return @($found.Values)
}

# Force-closes only the browser processes tied to this file.
#
# Graceful first: WM_CLOSE to their windows, which Chrome answers by shutting
# down normally and saving its session - that saved session is what
# --restore-last-session brings back afterwards (see Start-BrowserSession).
# Only what is still there after that is terminated, which costs the last
# unflushed history/cookie writes but not the tabs, since the session is written
# when the windows close.
#
# Two things stop the graceful route from finishing on its own, and both end in
# the same place - waiting longer will not help:
#   * "Keep Chrome running in the background" (or a background app): the windows
#     go, the browser process stays, and the file stays mapped forever.
#   * A page answering "leave site?": the window never closes at all.
# The first is detected by the windows being gone while the file is still held,
# and gets a short grace period for a normal exit before the hard close. The
# second just runs out the clock.
function Close-FileHolders {
    param([string]$TargetPath)

    $live = @(Get-BrowserProcesses -TargetPath $TargetPath)
    if ($live.Count -eq 0) { return (Wait-TargetUnlocked -TargetPath $TargetPath -TimeoutMs 0) }

    Initialize-Win32
    $ids = @($live | ForEach-Object { $_.Id })
    [void][Mv2Win32]::CloseWindows($ids)

    $deadline = [Environment]::TickCount + 15000
    $windowsGoneAt = 0
    while ($true) {
        if (Wait-TargetUnlocked -TargetPath $TargetPath -TimeoutMs 0) { return $true }
        if ([Environment]::TickCount -ge $deadline) { break }
        if ([Mv2Win32]::CountWindows($ids) -eq 0) {
            if ($windowsGoneAt -eq 0) { $windowsGoneAt = [Environment]::TickCount }
            elseif ([Environment]::TickCount - $windowsGoneAt -ge 3000) { break }
        } else {
            $windowsGoneAt = 0
        }
        Start-Sleep -Milliseconds 250
    }

    # Re-query rather than reuse the list from before the wait: Chrome retires and
    # spawns processes as it shuts down, and a browser that relaunched itself in
    # the meantime (a staged update does that) is not in the old snapshot at all.
    Write-Warn 'Chrome is not closing on its own - closing it the hard way.'
    foreach ($p in @(Get-BrowserProcesses -TargetPath $TargetPath)) {
        try {
            if ($p.HasExited) { continue }
            $p.Kill()
            $p.WaitForExit(5000) | Out-Null
        } catch { }
    }
    return (Wait-TargetUnlocked -TargetPath $TargetPath -TimeoutMs 5000)
}

# Closes the selected browser so its file can be replaced. No question asked:
# the browser is put back with the same tabs when the work is done, so this is a
# restart rather than a loss (Start-BrowserSession, called from Invoke-Main).
# -Quiet still refuses without -Yes - an unattended run must not close a browser
# nobody agreed to close.
#
# A process which starts after this returns is handled by the atomic replace
# failing; it is never closed without going through the gate below.
function Request-TargetUnlock {
    param($Target, [bool]$AssumeYes)

    if (Wait-TargetUnlocked -TargetPath $Target.Path -TimeoutMs 0) { return $true }

    $label = Get-TargetLabel -Target $Target
    if ($Quiet -and -not $AssumeYes) {
        Write-Err "Can't make the change while $label is open."
        Write-Host '    Close it, or add -Yes to close it automatically.'
        return $false
    }

    if ($NoReopen) { Write-Info "Closing $label to make the change..." }
    else { Write-Info "Closing $label - it reopens with the same tabs when this is done..." }

    if (Close-FileHolders -TargetPath $Target.Path) {
        Write-Ok "Closed $label. Your other browsers are still running."
        return $true
    }
    # Name what is in the way. It is not always the browser: a scanner or backup
    # agent with the file open for write shows up here too, and the answer to
    # that one is to wait a moment and run this again.
    $stuck = @(Get-FileHolders -TargetPath $Target.Path |
               ForEach-Object { if ($_.AppName) { $_.AppName } else { "pid $($_.Pid)" } } |
               Select-Object -Unique)
    if ($stuck.Count -gt 0) { Write-Host ("    Still holding the file: " + ($stuck -join ', ')) }
    return $false
}

function Test-TargetDirectoryWritable {
    param([string]$TargetPath)
    $dir = Split-Path -Parent ([IO.Path]::GetFullPath($TargetPath))
    $probe = Join-Path $dir ('.chrome-mv2-write-probe-' + [Guid]::NewGuid().ToString('N'))
    try {
        $fs = [IO.File]::Open($probe, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $fs.Dispose()
        return $true
    } catch {
        return $false
    } finally {
        if (Test-Path -LiteralPath $probe -PathType Leaf) { Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue }
    }
}

# Writes the patched image in place. The file was unlocked first, so a straight
# overwrite is safe (Chrome reopens chrome.dll on next launch).
function Write-Target {
    param([string]$TargetPath, [byte[]]$Buf, [string]$ExpectedCurrentHash = '', [string]$KnownBufHash = '')
    Write-AtomicFile -TargetPath $TargetPath -Buf $Buf -ExpectedCurrentHash $ExpectedCurrentHash -PreserveMetadataFrom $TargetPath -KnownBufHash $KnownBufHash
}

# ============================================================================
# Putting the browser back. The write needs chrome.dll unmapped, so the browser
# has to go down for it; everything here is about making that a restart the user
# does not have to think about, instead of a browser that vanished.
# ============================================================================

# The launcher for a chrome.dll target. Chrome's layout is
# <Application>\<version>\chrome.dll with chrome.exe one level up in
# <Application>; some Chromium packages keep both in the same directory. Empty
# when there is no chrome.exe in either place (a bare/offline copy of the dll),
# which is also the signal that there is nothing to reopen.
function Get-BrowserExePath {
    param([string]$TargetPath)
    try {
        $verDir = Split-Path -Parent ([IO.Path]::GetFullPath($TargetPath))
        foreach ($dir in @($verDir, (Split-Path -Parent $verDir))) {
            if (-not $dir) { continue }
            $exe = Join-Path $dir 'chrome.exe'
            if (Test-Path -LiteralPath $exe -PathType Leaf) { return $exe }
        }
    } catch { }
    return ''
}

# The flags the running browser was started with, so the restart keeps them - a
# --profile-directory or --user-data-dir especially, without which the reopened
# browser would come up on the wrong profile and restore nothing.
#
# Read from the browser process only: every other chrome.exe of an install is a
# child process carrying --type=..., and none of those command lines describe how
# the user starts Chrome. Empty when nothing could be read, and the restart then
# passes --restore-last-session alone.
function Get-BrowserRelaunchArgs {
    param([string]$ExePath)
    if (-not $ExePath) { return '' }
    $want = ''
    try { $want = ([IO.Path]::GetFullPath($ExePath)).ToLower() } catch { return '' }
    try {
        foreach ($proc in @(Get-CimInstance -ClassName Win32_Process -Filter "Name='chrome.exe'" -ErrorAction Stop)) {
            $img = [string]$proc.ExecutablePath
            if (-not $img -or $img.ToLower() -ne $want) { continue }
            $cl = [string]$proc.CommandLine
            if (-not $cl -or $cl -match '--type=') { continue }
            # Drop the leading image path (quoted or bare); keep the flags verbatim.
            if ($cl -match '^\s*"[^"]*"\s*(.*)$') { return (Select-BrowserUserArgs $Matches[1]) }
            if ($cl -match '^\s*\S+\s*(.*)$')     { return (Select-BrowserUserArgs $Matches[1]) }
        }
    } catch { }
    return ''
}

<#
Keeps the switches that say how the user starts this browser, and drops the ones
that only describe the launch being replaced:

  --restart, --original-process-start-time=...  Chrome relaunching itself (after
      an update, or the Relaunch button). Carried forward they describe a process
      that no longer exists.
  --flag-switches-begin ... --flag-switches-end  Chrome echoing back the
      chrome://flags choices it re-applies from Local State on every start, so
      replaying them adds nothing.
  --no-startup-window  would bring the browser back with no window at all.
  --restore-last-session  the caller adds it; never twice.
  positional arguments  a URL or file opened once, not part of how Chrome starts.

Tokenized so a quoted value keeps its spaces: --user-data-dir="C:\Some Dir" is
one argument, not two.
#>
function Select-BrowserUserArgs {
    param([string]$Arguments)
    if (-not $Arguments) { return '' }

    $keep = @()
    $inFlagBlock = $false
    foreach ($m in [regex]::Matches($Arguments, '(?:[^\s"]|"[^"]*")+')) {
        $tok = $m.Value
        if ($tok -eq '--flag-switches-begin') { $inFlagBlock = $true; continue }
        if ($tok -eq '--flag-switches-end')   { $inFlagBlock = $false; continue }
        if ($inFlagBlock) { continue }
        if (-not $tok.StartsWith('-')) { continue }
        if ($tok -in '--restart', '--no-startup-window', '--restore-last-session') { continue }
        if ($tok -like '--original-process-start-time=*') { continue }
        $keep += $tok
    }
    return ($keep -join ' ')
}

<#
Starts a program as the logged-on user from an elevated process, by asking the
desktop shell to open a shortcut that carries the arguments: explorer.exe hands
the request to the already-running shell, which creates the process with ITS
token, so the child runs at the normal integrity level. Returns $false when the
shortcut or the hand-off could not be made.

Chrome must NOT inherit our admin token. A browser holding the profile's
singleton at high integrity cannot be reached by the user's next ordinary Chrome
launch - UIPI blocks the rendezvous with its message window - and that surfaces
as "profile in use" on a browser they can see running. So there is no
"launch it elevated anyway" fallback here; the caller says so instead.
#>
function Start-AsDesktopUser {
    param([string]$FilePath, [string]$Arguments)

    $lnk = Join-Path ([IO.Path]::GetTempPath()) ('chrome-mv2-reopen-' + [Guid]::NewGuid().ToString('N') + '.lnk')
    try {
        $shell = New-Object -ComObject WScript.Shell
        $sc = $shell.CreateShortcut($lnk)
        $sc.TargetPath = $FilePath
        $sc.Arguments = $Arguments
        $sc.WorkingDirectory = Split-Path -Parent $FilePath
        $sc.Save()
    } catch { return $false }

    $ok = $true
    try { Start-Process -FilePath 'explorer.exe' -ArgumentList (Get-QuotedArg $lnk) -ErrorAction Stop }
    catch { $ok = $false }
    # The shell opens the shortcut on its own schedule, so the file has to outlive
    # this call by a moment. Cleanup is best effort - it lives in TEMP.
    if ($ok) { Start-Sleep -Seconds 2 }
    Remove-Item -LiteralPath $lnk -Force -ErrorAction SilentlyContinue
    return $ok
}

# Reopens the browser that was closed for the write, with the session it had.
# --restore-last-session is what brings the tabs back after the clean shutdown
# Close-FileHolders asks for; the captured flags go with it so the profile and
# any user flags survive the restart.
function Start-BrowserSession {
    param($Target, [string]$ExePath, [string]$Arguments)

    $label = Get-TargetLabel -Target $Target
    if (-not $ExePath) {
        Write-Warn "Left $label closed - start it again when you want it."
        return
    }

    $argLine = $Arguments
    if ($argLine -notmatch '(?i)(^|\s)--restore-last-session(\s|$)') {
        $argLine = if ($argLine) { "$argLine --restore-last-session" } else { '--restore-last-session' }
    }

    Write-Info "Reopening $label with your tabs..."
    $started = $false
    if (Test-Elevated) {
        $started = Start-AsDesktopUser -FilePath $ExePath -Arguments $argLine
    } else {
        try { Start-Process -FilePath $ExePath -ArgumentList $argLine -ErrorAction Stop; $started = $true } catch { }
    }

    if ($started -and (Wait-BrowserRunning -Target $Target -TimeoutMs 15000)) {
        Write-Ok "Reopened $label with your tabs."
        return
    }
    Write-Warn "Couldn't reopen $label - start it yourself."
    Write-Host '    Your tabs are under History > Recently closed.'
}

# ============================================================================
# Install discovery: find each channel's chrome.dll without touching the registry
# (the install roots and per-channel subdirectory names are fixed).
# ============================================================================

$WinChannels = @(
    @{ Name = 'Stable'; Subdir = 'Google\Chrome' }
    @{ Name = 'Beta';   Subdir = 'Google\Chrome Beta' }
    @{ Name = 'Dev';    Subdir = 'Google\Chrome Dev' }
    @{ Name = 'Canary'; Subdir = 'Google\Chrome SxS' }   # SxS = Canary's side-by-side dir
    @{ Name = 'Chromium'; Subdir = 'Chromium' }          # open-source Chromium keeps the chrome.dll name
)

# The channel label for a target we were handed as a bare path: an explicit
# -Path, a typed custom path, or the elevated relaunch, which forwards only the
# resolved path. Matched on whole path segments, because a plain substring test
# reads "Google\Chrome Beta" as Stable - "Google\Chrome" is a prefix of it - and
# so mislabels every non-Stable channel once elevation re-derives the label.
function Get-ChannelFromPath {
    param([string]$TargetPath)
    $hay = '\' + ($TargetPath -replace '/', '\').Trim('\').ToLower() + '\'
    foreach ($ch in $WinChannels) {
        if ($hay.Contains('\' + $ch.Subdir.ToLower() + '\')) { return $ch.Name }
    }
    return 'Unknown'
}

# True for a Chrome version directory name like "151.0.7922.109" (>= 3 numeric
# parts). Used to label the target and to skip non-version subdirectories.
function Test-LooksLikeVersion {
    param([string]$Name)
    $parts = $Name -split '\.'
    if ($parts.Count -lt 3) { return $false }
    foreach ($p in $parts) { if ($p -eq '' -or $p -notmatch '^\d+$') { return $false } }
    return $true
}

# Numeric version compare over up to 4 parts, so "151.0.7922.99" sorts below
# "151.0.7922.109" (a plain string compare would not).
function Compare-Version {
    param([string]$A, [string]$B)   # returns $true if A < B
    $pa = @($A -split '\.' | ForEach-Object { [int]($_ -replace '\D', '0') })
    $pb = @($B -split '\.' | ForEach-Object { [int]($_ -replace '\D', '0') })
    for ($i = 0; $i -lt 4; $i++) {
        $x = if ($i -lt $pa.Count) { $pa[$i] } else { 0 }
        $y = if ($i -lt $pb.Count) { $pb[$i] } else { 0 }
        if ($x -ne $y) { return ($x -lt $y) }
    }
    return $false
}

function Get-BackupPath { param([string]$Target) return "$Target.bak" }

# Best-effort display version of the target: the PE version resource first
# (present in every chrome.dll, works for a loose copy in any folder), then the
# install's version-looking parent directory name. Display-only - '' means
# unknown, and output then falls back to the matched milestone table's name.
function Get-ChromeVersion {
    param($Target)

    $ver = ''
    try   { $ver = ([Diagnostics.FileVersionInfo]::GetVersionInfo($Target.Path)).FileVersion.Trim() }
    catch { }
    if ($ver) { return $ver }
    if ($Target.PSObject.Properties['Version']) { return [string]$Target.Version }
    return ''
}

# The "Chrome X" string for output. A milestone table's name says which gate
# set matched, NOT which browser this is - a 153/154 build whose gates are
# unchanged legitimately matches the 152 table - so show the detected version
# when we have one, noting the matched table when its milestone differs; the
# table name alone otherwise.
function Get-ChromeLabel {
    param([string]$Version, [string]$Milestone)

    if (-not $Version) { return $Milestone }
    $major = ($Version -split '\.')[0]
    if ($Milestone -match "^$major(\D|$)") { return $Version }
    return "$Version (using the Chrome $Milestone changes)"
}

# Returns the chrome.dll under the highest-numbered version subdirectory, or one
# sitting directly in the Application dir.
function Find-DllUnderApplication {
    param([string]$AppDir)
    if (Test-Path -LiteralPath $AppDir -PathType Container) {
        $best = ''
        foreach ($d in Get-ChildItem -LiteralPath $AppDir -Directory -ErrorAction SilentlyContinue) {
            if ($best -eq '' -or (Compare-Version $best $d.Name)) {
                if (Test-Path -LiteralPath (Join-Path $d.FullName 'chrome.dll') -PathType Leaf) { $best = $d.Name }
            }
        }
        if ($best -ne '') { return (Join-Path (Join-Path $AppDir $best) 'chrome.dll') }
    }
    $direct = Join-Path $AppDir 'chrome.dll'
    if (Test-Path -LiteralPath $direct -PathType Leaf) { return $direct }
    return ''
}

# One target's display/decision facts: channel, version, whether it is running,
# and whether a .bak already exists.
# Cheap patched/stock probe for the install list. Reads ONLY the PE header (not
# the ~285 MB body) and inspects the Authenticode Security Directory: a stock,
# signed chrome.dll has one; patching zeroes it (see Complete-Image). Returns
# 'patched', 'not patched', or '' (unknown / not a PE). This is a fast list hint,
# not the authoritative gate probe that 'check'/'patch' run.
function Get-PatchStateQuick {
    param([string]$Path)
    try {
        $hdr = [byte[]]::new(8192)
        $fs = [IO.File]::OpenRead($Path)
        try { $n = $fs.Read($hdr, 0, $hdr.Length) } finally { $fs.Dispose() }
        if ($n -lt 64 -or $hdr[0] -ne 0x4D -or $hdr[1] -ne 0x5A) { return '' }
        $eLfanew = [BitConverter]::ToUInt32($hdr, 0x3C)
        if ($eLfanew + 24 -gt $n) { return '' }
        if ($hdr[$eLfanew] -ne 0x50 -or $hdr[$eLfanew + 1] -ne 0x45) { return '' }
        $optOff = [int]$eLfanew + 24
        $magic = [BitConverter]::ToUInt16($hdr, $optOff)
        $fixedLen = if ($magic -eq 0x20B) { 112 } elseif ($magic -eq 0x10B) { 96 } else { return '' }
        $secDirAt = $optOff + $fixedLen + 4 * 8      # data directory [4] = Security
        if ($secDirAt + 8 -gt $n) { return '' }
        $va = [BitConverter]::ToUInt32($hdr, $secDirAt)
        $sz = [BitConverter]::ToUInt32($hdr, $secDirAt + 4)
        if ($va -ne 0 -and $sz -ne 0) { return 'not patched' } else { return 'patched' }
    } catch { return '' }
}

function Get-InstallDetails {
    param([string]$TargetPath, [string]$Channel)

    $parent = Split-Path -Leaf (Split-Path -Parent $TargetPath)
    $version = if (Test-LooksLikeVersion $parent) { $parent } else { '' }

    $holders = @()
    try { $holders = @(Get-FileHolders -TargetPath $TargetPath) } catch { }
    $running = ($holders.Count -gt 0)
    if (-not $running) { try { $running = Test-TargetLocked -TargetPath $TargetPath } catch { } }

    if (-not $Channel) { $Channel = Get-ChannelFromPath $TargetPath }

    return [pscustomobject]@{
        Channel   = $Channel
        Path      = $TargetPath
        Version   = $version
        Running   = $running
        Holders   = $holders.Count
        HasBackup = (Test-Path -LiteralPath (Get-BackupPath $TargetPath) -PathType Leaf)
        State     = (Get-PatchStateQuick $TargetPath)
    }
}

# Every installed channel across the machine-wide and per-user install roots,
# deduplicated by path (a channel can appear under more than one root).
function Get-ChromeInstalls {
    $found = @(); $seen = @{}

    $roots = @()
    foreach ($v in 'ProgramFiles', 'ProgramFiles(x86)', 'LOCALAPPDATA') {
        $val = [Environment]::GetEnvironmentVariable($v)
        if ($val) { $roots += $val }
    }
    foreach ($ch in $WinChannels) {
        foreach ($root in $roots) {
            $dll = Find-DllUnderApplication (Join-Path (Join-Path $root $ch.Subdir) 'Application')
            if ($dll -eq '') { continue }
            $key = $dll.ToLower()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $found += Get-InstallDetails -TargetPath $dll -Channel $ch.Name
        }
    }
    # A chrome.dll dropped next to the script stays supported for offline use.
    if ($found.Count -eq 0 -and (Test-Path './chrome.dll' -PathType Leaf)) {
        $found += Get-InstallDetails -TargetPath './chrome.dll' -Channel 'Local file'
    }
    return $found
}

# ============================================================================
# Interactive prompts. All of these are skipped under -Quiet, which never reads
# from stdin - see Resolve-Target. Closing the browser asks nothing: it is
# reopened with the same tabs when the work is done (Request-TargetUnlock).
# ============================================================================

# Menu display name: the Google channels get the "Chrome " prefix; Chromium and
# anything else (custom path, local file) is shown as-is.
function Get-BrowserDisplayName {
    param([string]$Channel)
    if ($Channel -in 'Stable', 'Beta', 'Dev', 'Canary') { return "Chrome $Channel" }
    return $Channel
}

# The same name in a sentence ("Closing Chrome Beta..."). A target handed over as
# a bare path has no channel to name, and "Unknown is closed" reads like a fault,
# so those get the generic wording instead.
function Get-TargetLabel {
    param($Target)
    $name = Get-BrowserDisplayName $Target.Channel
    if (-not $name -or $name -eq 'Unknown') { return 'the browser' }
    return $name
}

# One numbered row of the browser table:
#   "  1  Chrome Stable    152.0.7977.65       Patched".
function Show-InstallRow {
    param([int]$Index, $Inst)
    $status = if ($Inst.State -eq 'patched') { "$($C.Grn)Patched$($C.Reset)" }
              elseif ($Inst.State -eq 'not patched') { "$($C.Dim)Not patched$($C.Reset)" }
              else { '' }
    Write-Host ("  {0,-2} {1,-17}{2,-20}{3}" -f $Index, (Get-BrowserDisplayName $Inst.Channel), [string]$Inst.Version, $status)
}

function Show-InstallTable {
    param([array]$Installs)
    Write-Host ''
    Write-Host "$($C.Bold)  #  Browser          Version             Status$($C.Reset)"
    for ($i = 0; $i -lt $Installs.Count; $i++) { Show-InstallRow ($i + 1) $Installs[$i] }
}

# Prompts for a chrome.dll path until one exists, or $null if the user gives up.
# The Trim chain strips the quotes that copying a path from Explorer adds.
function Read-CustomPath {
    while ($true) {
        Write-Host "$($C.Bold)"
        $line = Read-Host 'Enter the full path to chrome.dll, blank to cancel'
        Write-Host "$($C.Reset)" -NoNewline
        $p = $line.Trim().Trim('"').Trim("'").Trim()
        if ($p -eq '') { return $null }
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
            Write-Err 'No file at that path. Try again, or leave blank to cancel.'
            continue
        }
        return (Get-InstallDetails -TargetPath $p -Channel '')
    }
}

# Lists the browsers as a table and returns the chosen one, or $null on quit.
# With exactly one install, Enter accepts it; otherwise a number is required.
function Select-Install {
    param([array]$Installs)

    $count = $Installs.Count
    Write-Info ("Found {0} browser{1}." -f $count, $(if ($count -ne 1) { 's' }))
    Show-InstallTable $Installs

    # 'check' is read-only and must never turn into a write, so it neither offers
    # nor honors the restore switch; only 'patch' may divert to restore. The verb
    # keeps the menu honest for whichever command is actually running.
    $verb = switch ($script:Command) { 'check' { 'Check' } 'restore' { 'Restore' } default { 'Patch' } }
    $allowRestore = ($script:Command -eq 'patch')
    $range = if ($count -eq 1) { '1' } else { "1-$count" }

    Write-Host ''
    Write-Host "$($C.Bold)Select command:$($C.Reset)"
    Write-Host ''
    Write-Host "  [$range]  $verb browser"
    if ($allowRestore) { Write-Host '  [r]    Restore patched' }
    Write-Host '  [c]    Use custom path'
    Write-Host '  [q]    Quit'

    while ($true) {
        $line = (Read-Host "`nChoice").Trim()

        if ($line -in 'q', 'Q') { return $null }
        if ($allowRestore -and $line -in 'r', 'R') {
            $script:Command = 'restore'
            if ($count -eq 1) { return $Installs[0] }
            # Restore targets a specific browser, so ask which one.
            while ($true) {
                $restoreLine = (Read-Host "`nRestore which browser? [1-$count, q=cancel]").Trim()
                if ($restoreLine -in 'q', 'Q') {
                    Write-Info 'Restore cancelled.'
                    return $null
                }
                $rn = 0
                if ([int]::TryParse($restoreLine, [ref]$rn) -and $rn -ge 1 -and $rn -le $count) {
                    return $Installs[$rn - 1]
                }
                Write-Err "Enter a number between 1 and $count, or q to cancel."
            }
        }
        if ($line -in 'c', 'C') {
            $pick = Read-CustomPath
            if ($pick) { return $pick }
            continue
        }
        if ($count -eq 1 -and $line -eq '') { return $Installs[0] }
        $n = 0
        if ([int]::TryParse($line, [ref]$n) -and $n -ge 1 -and $n -le $count) {
            return $Installs[$n - 1]
        }
        $restoreHint = if ($allowRestore) { 'r to restore, ' } else { '' }
        if ($count -eq 1) {
            Write-Err "Press Enter to accept, ${restoreHint}c for a custom path, or q to quit."
        } else {
            Write-Err "Enter a number between 1 and $count, ${restoreHint}c for a custom path, or q to quit."
        }
    }
}

# ============================================================================
# Orchestration
# ============================================================================

# Decides which file to work on: an explicit path wins; otherwise discovery, then
# a prompt. Non-interactive (-Quiet) auto-picks only when exactly one channel is
# installed, so an unattended run can never patch a channel nobody chose.
function Resolve-Target {
    param([string]$TargetPath, [bool]$Interactive)

    if ($TargetPath) {
        if (-not (Test-Path -LiteralPath $TargetPath -PathType Leaf)) {
            Write-Err "That path doesn't exist."
            return $null
        }
        return (Get-InstallDetails -TargetPath $TargetPath -Channel '')
    }

    Write-Info 'Searching for supported browsers...'
    $installs = @(Get-ChromeInstalls)

    if ($installs.Count -eq 0) {
        if (-not $Interactive) {
            Write-Err "Couldn't find Chrome on this computer."
            Write-Host '    Give the path to chrome.dll, e.g. .\chrome-mv2.ps1 patch C:\path\to\chrome.dll'
            return $null
        }
        Write-Warn "Couldn't find Chrome on this computer."
        $pick = Read-CustomPath
        if ($pick) { return $pick }
        Write-Info 'No path entered - nothing was changed.'
        return $null
    }
    if (-not $Interactive -and $installs.Count -gt 1) {
        Write-Err "Found $($installs.Count) browsers, and -Quiet can't ask which one."
        Show-InstallTable $installs
        for ($i = 0; $i -lt $installs.Count; $i++) {
            Write-Host "      $($C.Dim)$($installs[$i].Path)$($C.Reset)"
        }
        Write-Host '    Re-run with the path of the one you want.'
        return $null
    }
    if (-not $Interactive) { return $installs[0] }

    $picked = Select-Install $installs
    if (-not $picked) { Write-Info 'Nothing selected - nothing was changed.'; return $null }
    return $picked
}

# patch: consent -> unlock -> read -> backup policy -> flip gates -> finalize ->
# write. Returns a process exit code (0 = patched, 1 = nothing written).
function Invoke-Patch {
    param($Target, [bool]$AssumeYes)

    Write-Info 'Checking chrome.dll...'
    $buf = [IO.File]::ReadAllBytes($Target.Path)
    if ($buf.Length -eq 0) { Write-Err 'That file is empty.'; return 1 }

    $img = Open-Image $buf
    $chromeVer = Get-ChromeVersion -Target $Target
    $targetIdentity = Get-PeIdentity -Buf $buf -Img $img
    $targetHash = $targetIdentity.SHA256

    $milestones = @(Import-Milestones | Where-Object { $_.Container -eq $img.Format })
    if ($milestones.Count -eq 0) {
        Write-Warn "This kind of Chrome isn't supported yet - nothing was changed."
        Show-LayoutCandidates -Buf $buf -Img $img
        return 1
    }

    # Recognize the build up front so the signature table it uses is reported
    # before the backup policy runs. The matcher accepts stock and already-
    # patched bytes alike, so this works whether or not the target is patched.
    # Declines (unrecognized / tied / partial without -AllowPartial) stay silent
    # here - the backup policy and the apply pass below print their own reasons.
    Write-Info 'Searching for MV2 signatures...'
    $recognized = Invoke-PatchMilestones -Buf $buf -Img $img -Milestones $milestones `
        -AllowPartial $AllowPartial.IsPresent -Apply $false 6>$null
    if ($recognized.Status -ne 0 -and -not $recognized.Reason) {
        Write-Ok ("Found matching signatures ({0}, {1} gates)." -f $recognized.Milestone, $recognized.Located)
    }

    # Backups are accepted only when they parse as clean stock and describe the
    # same PE build. A patched/unsigned target can never become a new baseline.
    $backupPath = Get-BackupPath $Target.Path
    if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
        if (-not (Test-LikelyStock -Img $img -Buf $buf)) {
            Write-Err "There's no backup yet, and this Chrome has already been changed."
            Write-Host '    Reinstall Chrome first so we can save a clean backup.'
            return 1
        }
        $stockLayout = Get-CleanStockLayout -Buf $buf -Img $img -Milestones $milestones `
            -AllowPartialLayout $AllowPartial.IsPresent
        if (-not $stockLayout.Clean) {
            Write-Err "There's no backup yet, and this doesn't look like an untouched Chrome."
            return 1
        }
        Write-Info 'Creating backup...'
        Save-BackupSnapshot -TargetPath $Target.Path -BackupPath $backupPath -Buf $buf -Identity $targetIdentity
        $backup = Read-ValidatedBackup $backupPath
    } else {
        try {
            $backup = Read-ValidatedBackup $backupPath
        } catch {
            Write-Err "The backup couldn't be verified: $_"
            return 1
        }
        if (-not (Test-LikelyStock -Img $backup.Img -Buf $backup.Buf)) {
            Write-Err "The backup doesn't look like an original Chrome, so I won't use it."
            return 1
        }
        $backupLayout = Get-CleanStockLayout -Buf $backup.Buf -Img $backup.Img -Milestones $milestones `
            -AllowPartialLayout $AllowPartial.IsPresent
        if (-not $backupLayout.Clean) {
            Write-Err "The backup doesn't look like an untouched Chrome."
            return 1
        }

        if (-not (Test-SameBuildIdentity -A $targetIdentity -B $backup.Identity)) {
            if (-not (Test-LikelyStock -Img $img -Buf $buf)) {
                Write-Err "Chrome was updated, but this copy has already been changed."
                Write-Host '    Reinstall or update Chrome so we can start from a clean copy.'
                return 1
            }
            $newStockLayout = Get-CleanStockLayout -Buf $buf -Img $img -Milestones $milestones `
                -AllowPartialLayout $AllowPartial.IsPresent
            if (-not $newStockLayout.Clean) {
                Write-Err "This updated Chrome isn't fully supported yet."
                return 1
            }
            Write-Info 'Chrome was updated - saving a fresh backup...'
            Save-BackupSnapshot -TargetPath $Target.Path -BackupPath $backupPath -Buf $buf -Identity $targetIdentity
            $backup = Read-ValidatedBackup $backupPath
        } elseif ($backup.Legacy) {
            Save-BackupSnapshot -TargetPath $Target.Path -BackupPath $backupPath -Buf $backup.Buf -Identity $backup.Identity
        }
    }

    $buf = [byte[]]$backup.Buf.Clone()
    $img = Open-Image $buf

    Write-Info 'Applying patch...'
    $patch = Invoke-PatchMilestones -Buf $buf -Img $img -Milestones $milestones `
        -AllowPartial $AllowPartial.IsPresent -Apply $true -Version $chromeVer 6>$null
    if ($patch.Status -eq 0) {
        Write-Err 'Something went wrong while preparing the change - nothing was changed.'
        return 1
    }

    $msg = if ($patch.Status -eq 1) { 'Patch applied successfully.' } else { 'Chrome was already patched (no change needed).' }
    Write-Ok $msg

    Complete-Image -Img $img -Buf $buf
    if (-not (Test-PatchOutput -Buf $buf -Img $img -Patch $patch)) {
        Write-Err 'Something went wrong while preparing the change - nothing was changed.'
        return 1
    }

    $preparedHash = Get-ByteHash $buf
    if ($preparedHash -eq $targetHash) {
        Write-Success 'Already done - no change was needed.'
        return 0
    }
    if ($targetHash -ne $backup.Identity.SHA256) {
        Write-Err "This Chrome has other changes we didn't make, so we won't overwrite it."
        Write-Host '    Reinstall Chrome, or check the file yourself, then try again.'
        return 1
    }

    if (-not (Request-TargetUnlock -Target $Target -AssumeYes $AssumeYes)) {
        Write-Err 'Chrome is still open - close it and try again.'
        return 1
    }
    # Write-AtomicFile reads the written bytes back and verifies them against
    # $preparedHash before the atomic Replace, so the target already equals the
    # prepared image on success - no post-write re-read/re-hash is needed.
    Write-Target -TargetPath $Target.Path -Buf $buf -ExpectedCurrentHash $targetHash -KnownBufHash $preparedHash

    if ($patch.Full) {
        Write-Ok 'Manifest V2 is enabled.'
    } else {
        Write-Host "$script:TagWarning Only part of the change was applied ($($patch.Located)/$($patch.Total))."
        Write-Host "          $($patch.Total - $patch.Located) part(s) couldn't be found, so this may not fully work."
        Write-Host '          Please report your Chrome version. To undo: .\chrome-mv2.ps1 restore'
    }
    return 0
}

# restore: validates backup metadata, stock layout, and build identity before an
# atomic replacement. A cross-build restore requires the explicit force switch.
function Invoke-Restore {
    param($Target, [bool]$AssumeYes)

    Write-Info 'Checking backup...'
    $backupPath = Get-BackupPath $Target.Path
    if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
        Write-Err "No backup found, so there's nothing to restore."
        return 1
    }
    try { $backup = Read-ValidatedBackup $backupPath }
    catch { Write-Err "The backup couldn't be verified: $_"; return 1 }
    if (-not (Test-LikelyStock -Img $backup.Img -Buf $backup.Buf)) {
        Write-Err "The backup doesn't look like an original Chrome, so I won't use it."
        return 1
    }
    $milestones = @(Import-Milestones | Where-Object { $_.Container -eq $backup.Img.Format })
    $backupLayout = Get-CleanStockLayout -Buf $backup.Buf -Img $backup.Img -Milestones $milestones -AllowPartialLayout $true
    if (-not $backupLayout.Clean) {
        Write-Err "The backup doesn't look like an untouched Chrome."
        return 1
    }
    Write-Ok 'Backup found.'

    $current = [IO.File]::ReadAllBytes($Target.Path)
    $currentImg = Open-Image $current
    $currentIdentity = Get-PeIdentity -Buf $current -Img $currentImg
    if (-not (Test-SameBuildIdentity -A $currentIdentity -B $backup.Identity) -and -not $ForceRestore) {
        Write-Err "This backup is from a different Chrome version, so I won't use it."
        Write-Host '    Add -ForceRestore only if you really mean to go back to that version.'
        return 1
    }
    if (-not (Test-SameBuildIdentity -A $currentIdentity -B $backup.Identity)) {
        Write-Warn 'Restoring a different Chrome version (-ForceRestore).'
    }
    if ($currentIdentity.SHA256 -eq $backup.Identity.SHA256) {
        Write-Success 'Chrome is already the original - nothing to undo.'
        Remove-BackupFiles $backupPath
        Write-Info 'Backup removed - Chrome is back to normal.'
        return 0
    }
    if (-not (Request-TargetUnlock -Target $Target -AssumeYes $AssumeYes)) {
        Write-Err 'Chrome is still open - close it and try again.'
        return 1
    }
    # As in Invoke-Patch: Write-AtomicFile verifies the read-back against the
    # backup's known hash before the atomic Replace, so no post-write re-read.
    Write-Info 'Restoring chrome.dll...'
    Write-Target -TargetPath $Target.Path -Buf $backup.Buf -ExpectedCurrentHash $currentIdentity.SHA256 -KnownBufHash $backup.Identity.SHA256
    Write-Ok 'Restore complete.'
    Remove-BackupFiles $backupPath

    Write-Host ''
    Write-Ok 'Original file restored.'
    Write-Ok 'Manifest V2 patch removed.'
    return 0
}

function Invoke-Check {
    param($Target)
    $buf = [IO.File]::ReadAllBytes($Target.Path)
    if ($buf.Length -eq 0) { Write-Err 'That file is empty.'; return 1 }
    $img = Open-Image $buf
    $chromeVer = Get-ChromeVersion -Target $Target
    $identity = Get-PeIdentity -Buf $buf -Img $img

    $milestones = @(Import-Milestones | Where-Object { $_.Container -eq $img.Format })
    $probe = Invoke-PatchMilestones -Buf $buf -Img $img -Milestones $milestones -AllowPartial $true -Apply $false -Version $chromeVer 6>$null
    if ($probe.Status -eq 0) {
        if ($probe.Reason -match 'tied') { Write-Warn "Couldn't tell which Chrome version this is." }
        else { Write-Warn "This Chrome version isn't recognized yet." }
    } else {
        $state = if ($probe.Stock -gt 0 -and $probe.Already -gt 0) { 'partly patched' } elseif ($probe.Stock -gt 0) { 'not patched yet' } else { 'already patched' }
        Write-Ok ("This is Chrome {0} - {1}." -f (Get-ChromeLabel -Version $chromeVer -Milestone $probe.Milestone), $state)
    }

    $backupPath = Get-BackupPath $Target.Path
    if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
        try {
            $backup = Read-ValidatedBackup $backupPath
            Write-Ok 'A backup is saved.'
        } catch { Write-Warn 'A backup exists but looks damaged.' }
    } else { Write-Info 'No backup saved yet.' }

    # Exit-code contract (kept in step with chrome-mv2.sh): 0 = a complete,
    # internally consistent layout was recognized, whether stock or patched;
    # non-zero = no complete layout matched, or it was mixed/partial. This is
    # deliberately NOT a patched-vs-stock detector - read the printed
    # state=stock|patched|mixed line for that distinction.
    return $(if ($probe.Full) { 0 } else { 1 })
}

# ============================================================================
# Entry point
# ============================================================================

# Version/banner -> elevation -> target selection -> command dispatch. Returns
# the process exit code; MV2_TEST_NO_ELEVATION=1 bypasses the admin gate so an
# unelevated run can be tested against a scratch copy of a chrome.dll.
function Invoke-Main {
    # Must run BEFORE Initialize-Colors: the flag is read while the ANSI color
    # table is built, so setting it any later has no effect on this run.
    if ($Relaunched) { $script:ForceBlackBg = $true }
    Initialize-Colors

    if ($Version) { Write-Host "chrome-mv2-patch (PowerShell) $AppVersion"; return 0 }

    # The elevated child opens its own console window - give that window a black
    # background for the run. Windows PowerShell consoles start blue, and BOTH
    # color stores must be set: $Host.UI.RawUI is what Write-Host paints with,
    # while [Console] covers .NET writes and the Clear-Host repaint. Skipped for
    # non-console hosts, where Clear-Host is not meaningful.
    if ($Relaunched) {
        try {
            $Host.UI.RawUI.BackgroundColor = 'Black'
            $Host.UI.RawUI.ForegroundColor = 'Gray'
            [Console]::BackgroundColor = [ConsoleColor]::Black
            [Console]::ForegroundColor = [ConsoleColor]::Gray
            Clear-Host
        } catch { }
    }

    Write-Banner

    # Resolve before elevation. Read-only checks never need admin, and an
    # offline/user-owned copy should not cause a UAC prompt merely because the
    # normal Program Files installation does.
    $target = Resolve-Target -TargetPath $Path -Interactive (-not $Quiet)
    if (-not $target) { return 1 }

    $selName = Get-BrowserDisplayName $target.Channel
    $selVer = Get-ChromeVersion -Target $target
    if ($selVer) { Write-Ok "Selected browser: $selName $selVer" }
    else         { Write-Ok "Selected browser: $selName" }

    if ($Command -eq 'check') { return (Invoke-Check -Target $target) }

    $needsElevation = -not (Test-TargetDirectoryWritable -TargetPath $target.Path)
    if ($needsElevation -and -not (Test-Elevated) -and -not $env:MV2_TEST_NO_ELEVATION) {
        # Loop guard: -Relaunched means we ALREADY tried to elevate. If we are
        # still not admin, report and stop instead of spawning again.
        if (-not $Relaunched) {
            $childCode = Invoke-SelfElevate -ResolvedTargetPath ([IO.Path]::GetFullPath($target.Path))
            if ($null -ne $childCode) {
                # The child did the work in its own window and held it open until
                # the user dismissed it, so don't pause again here - but do say how
                # it went, or this window's last line is still "asking for
                # administrator access" as if nothing had happened.
                $script:SuppressPause = $true
                if ($childCode -eq 0) { Write-Ok 'Finished with administrator access.' }
                else { Write-Err 'The run with administrator access did not succeed.' }
                return $childCode
            }
            return 1
        }
        Write-Host "$script:TagWarn $(Get-ElevationHint)"
        return 1
    }

    # Patch and restore close the browser themselves, right before the write.
    # What it takes to put it back has to be read BEFORE that: the launcher next
    # to the target, and the flags the running browser was started with. Done
    # here rather than in the parent of an elevated run, so the reopen happens in
    # the process that did the closing - the parent is still waiting on this one.
    $wasRunning = $false
    $reopenExe = ''
    $reopenArgs = ''
    if (-not $NoReopen) {
        $wasRunning = Test-BrowserRunning -Target $target
        if ($wasRunning) {
            $reopenExe = Get-BrowserExePath -TargetPath $target.Path
            $reopenArgs = Get-BrowserRelaunchArgs -ExePath $reopenExe
        }
    }

    $code = if ($Command -eq 'restore') { Invoke-Restore -Target $target -AssumeYes $Yes.IsPresent }
            else { Invoke-Patch -Target $target -AssumeYes $Yes.IsPresent }

    # Reopen only what this run actually closed. A browser still holding the file
    # was never closed (nothing needed writing, or the close was refused), and a
    # run that never saw it running has nothing to put back.
    if ($wasRunning -and -not (Test-BrowserRunning -Target $target)) {
        Start-BrowserSession -Target $target -ExePath $reopenExe -Arguments $reopenArgs
    }
    return $code
}
<#
Whether to hold the window open before exiting.

An interactive run always pauses - the window is often opened by a double-click,
so both failures and successes need a "Press Enter to exit." hold. Skipped when
the caller asked for silence (-Quiet, scripting), when an elevated child has
already done the pausing, or when input is redirected (piped/automation) - an
unattended run must not hang waiting for a key.
#>
function Test-ShouldPause {
    param(
        [int]$ExitCode,
        [bool]$IsElevatedChild,
        [bool]$QuietMode,
        [bool]$ChildAlreadyPaused,
        [bool]$InputRedirected
    )
    if ($QuietMode -or $ChildAlreadyPaused -or $InputRedirected) { return $false }
    return $true
}

# Set true when an elevated child ran: it owns its window and its own pause.
$script:SuppressPause = $false

if ($env:MV2_TEST_LIBRARY_ONLY) { return }

# Wraps everything that talks to the user, including the pause: a click in the
# window must not be able to suspend the run at any point, and the console's
# own setting is put back before this process exits either way.
Disable-ConsoleQuickEdit
try {
    $exitCode = Invoke-Main

    if (Test-ShouldPause -ExitCode $exitCode -IsElevatedChild $Relaunched.IsPresent `
                         -QuietMode $Quiet.IsPresent -ChildAlreadyPaused $script:SuppressPause `
                         -InputRedirected ([Console]::IsInputRedirected)) {
        Write-Host ''
        Write-Host 'Press Enter to exit.' -NoNewline
        try { [void](Read-Host) } catch { }
        Write-Host ''
    }
} finally {
    Restore-ConsoleQuickEdit
}
exit $exitCode
