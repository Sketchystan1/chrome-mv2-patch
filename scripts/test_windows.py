"""Windows PE regression tests for chrome-mv2.ps1.

The PowerShell patcher is tested white-box (dot-sourced internals: the matcher,
patch/restore, atomic writer, image parser, milestone selection), so this Python
file launches that assertion script via `pwsh`. It is skipped cleanly where
PowerShell is unavailable (e.g. a Linux runner without pwsh); CI runs it on the
Windows runner. Kept as .py so the whole suite lives flat in scripts/.
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# White-box PowerShell assertions. $repo comes from the environment so the body
# does not depend on its own location.
PS_TEST = r'''
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = $env:MV2_REPO
$env:MV2_TEST_LIBRARY_ONLY = '1'
. (Join-Path $repo 'chrome-mv2.ps1')
Remove-Item Env:MV2_TEST_LIBRARY_ONLY -ErrorAction SilentlyContinue
Initialize-Colors
$script:Quiet = $true

$passed = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
    $script:passed++
}
function Assert-Throws {
    param([scriptblock]$Action, [string]$Message)
    $threw = $false
    try { & $Action } catch { $threw = $true }
    Assert-True $threw $Message
}
function New-TestPe {
    param([string]$Path, [byte[]]$Signature, [int]$SignatureOffset = 0x40,
          [uint32]$TimeStamp = 0x12345678, [bool]$Signed = $true, [uint16]$Machine = 0x8664)
    $buf = [byte[]]::new(0x800)
    $buf[0] = 0x4D; $buf[1] = 0x5A
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x80), 0, $buf, 0x3C, 4)
    $nt = 0x80
    $buf[$nt] = 0x50; $buf[$nt + 1] = 0x45
    [Array]::Copy([BitConverter]::GetBytes([uint16]$Machine), 0, $buf, $nt + 4, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]1), 0, $buf, $nt + 6, 2)
    [Array]::Copy([BitConverter]::GetBytes($TimeStamp), 0, $buf, $nt + 8, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint16]0xF0), 0, $buf, $nt + 20, 2)
    $opt = $nt + 24
    [Array]::Copy([BitConverter]::GetBytes([uint16]0x20B), 0, $buf, $opt, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint32]16), 0, $buf, $opt + 108, 4)
    if ($Signed) {
        [Array]::Copy([BitConverter]::GetBytes([uint32]0x700), 0, $buf, $opt + 144, 4)
        [Array]::Copy([BitConverter]::GetBytes([uint32]0x20), 0, $buf, $opt + 148, 4)
    }
    $section = $opt + 0xF0
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes('.text'), 0, $buf, $section, 5)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x200), 0, $buf, $section + 8, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x1000), 0, $buf, $section + 12, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x200), 0, $buf, $section + 16, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x400), 0, $buf, $section + 20, 4)
    [Array]::Copy($Signature, 0, $buf, 0x400 + $SignatureOffset, $Signature.Length)
    [IO.File]::WriteAllBytes($Path, $buf)
}
function Write-Signatures {
    param([string]$Path, [array]$Milestones)
    @{ milestones = $Milestones } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding utf8
}
$temp = Join-Path ([IO.Path]::GetTempPath()) ('chrome mv2 ps tests ' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $near = [byte[]]@(0x83,0x7F,0x50,0x02,0x0F,0x8F,0x8B,0,0,0,0x48,0x8B)
    $pePath = Join-Path $temp 'near fixture.dll'
    New-TestPe -Path $pePath -Signature $near
    $buf = [IO.File]::ReadAllBytes($pePath)
    $start = 0x440
    Assert-True (Test-SigAt -Buf $buf -Start $start -Sig $near -JgOff 4 -Kind 1) 'stock near pair should match'
    $buf[$start + 4] = 0x90; $buf[$start + 5] = 0xE9
    Assert-True (Test-SigAt -Buf $buf -Start $start -Sig $near -JgOff 4 -Kind 1) 'patched near pair should match'
    $buf[$start + 4] = 0x0F; $buf[$start + 5] = 0xE9
    Assert-True (-not (Test-SigAt -Buf $buf -Start $start -Sig $near -JgOff 4 -Kind 1)) 'mixed 0F E9 pair must not match'
    $buf[$start + 4] = 0x90; $buf[$start + 5] = 0x8F
    Assert-True (-not (Test-SigAt -Buf $buf -Start $start -Sig $near -JgOff 4 -Kind 1)) 'mixed 90 8F pair must not match'
    Initialize-NativeHelpers
    Assert-True (-not [Mv2Native]::SigMatchesAt($buf, $start, $near, 4, 1)) 'compiled matcher must reject mixed near pairs'

    $sig = [byte[]]@(0x83,0x7E,0x50,0x02,0x7F,0x2F,0x55,0x48,0x89,0xE5)
    $target = Join-Path $temp 'full fixture.dll'
    $sigPath = Join-Path $temp 'full signatures.json'
    New-TestPe -Path $target -Signature $sig
    Write-Signatures -Path $sigPath -Milestones @(
        @{ name='test-pe'; container='pe'; sites=@(
            @{ name='gate'; kind='short'; jgRVA='0x00001044'; jgOff=4; expectedMatches=1; sig='837E50027F2F554889E5' }
        ) }
    )
    $script:Signatures = $sigPath
    $script:AllowPartial = [switch]$false
    $script:ForceRestore = [switch]$false
    $targetObj = [pscustomobject]@{ Path=$target; Channel='Test'; Running=$false; Holders=0 }

    Assert-True ((Invoke-Patch -Target $targetObj -AssumeYes $true) -eq 0) 'full synthetic PE patch should succeed'
    Assert-True (([IO.File]::ReadAllBytes($target))[0x444] -eq 0xEB) 'patch should flip the short jump'
    Assert-True (Test-Path -LiteralPath "$target.bak") 'patch should create a backup'
    Assert-True (Test-Path -LiteralPath "$target.bak.json") 'patch should create backup metadata'
    $patchedHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    Assert-True ((Invoke-Patch -Target $targetObj -AssumeYes $true) -eq 0) 'idempotent re-patch should succeed'
    Assert-True ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -eq $patchedHash) 'idempotent re-patch should not rewrite different bytes'
    Assert-True ((Invoke-Restore -Target $targetObj -AssumeYes $true) -eq 0) 'verified restore should succeed'
    Assert-True (([IO.File]::ReadAllBytes($target))[0x444] -eq 0x7F) 'restore should recover stock byte'
    Assert-True (-not (Test-Path -LiteralPath "$target.bak")) 'restore should remove the backup'
    Assert-True (-not (Test-Path -LiteralPath "$target.bak.json")) 'restore should remove the backup metadata'
    # target is stock again; re-patch to recreate a backup for the remaining sub-tests
    Assert-True ((Invoke-Patch -Target $targetObj -AssumeYes $true) -eq 0) 're-patch after restore should recreate the backup'
    Assert-True (Test-Path -LiteralPath "$target.bak") 're-patch should recreate the backup'
    $unrelated = [IO.File]::ReadAllBytes($target)
    $unrelated[0x620] = 0xA5
    [IO.File]::WriteAllBytes($target, $unrelated)
    Assert-True ((Invoke-Patch -Target $targetObj -AssumeYes $true) -eq 1) 'patch should refuse unrelated target modifications'
    Assert-True (([IO.File]::ReadAllBytes($target))[0x620] -eq 0xA5) 'refused patch must preserve unrelated modifications'
    Copy-Item -LiteralPath "$target.bak" -Destination $target -Force

    $other = Join-Path $temp 'different build.dll'
    New-TestPe -Path $other -Signature $sig -TimeStamp 0x22345678
    Copy-Item -LiteralPath $other -Destination $target -Force
    Assert-True ((Invoke-Restore -Target $targetObj -AssumeYes $true) -eq 1) 'stale restore should fail closed'
    Assert-True (([BitConverter]::ToUInt32([IO.File]::ReadAllBytes($target), 0x88)) -eq 0x22345678) 'failed stale restore must leave target untouched'

    $raceTarget = Join-Path $temp 'race target.bin'
    $raceSource = Join-Path $temp 'race source.bin'
    [IO.File]::WriteAllBytes($raceTarget, [byte[]]@(1,2,3))
    [IO.File]::WriteAllBytes($raceSource, [byte[]]@(9,8,7))
    Assert-Throws { Write-AtomicFile -TargetPath $raceTarget -Buf ([IO.File]::ReadAllBytes($raceSource)) -ExpectedCurrentHash ('0' * 64) } 'atomic writer should reject a changed target'
    Assert-True ((Get-ByteHash ([IO.File]::ReadAllBytes($raceTarget))) -eq (Get-ByteHash ([byte[]]@(1,2,3)))) 'race rejection must preserve target bytes'

    $truncated = [IO.File]::ReadAllBytes($pePath)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x1000), 0, $truncated, 0x80 + 24 + 0xF0 + 16, 4)
    Assert-Throws { Open-Image $truncated | Out-Null } 'out-of-bounds .text must be rejected'

    $partialBuf = [IO.File]::ReadAllBytes($pePath)
    $partialImg = Open-Image $partialBuf
    $partialMilestones = @(
        [pscustomobject]@{ Name='partial'; Container='pe'; Sites=@(
            [pscustomobject]@{ Name='present'; Kind=1; JgRVA=[uint32]0x1044; Sig=$near; JgOff=4; ExpectedMatches=1 },
            [pscustomobject]@{ Name='missing'; Kind=0; JgRVA=[uint32]0x1084; Sig=$sig; JgOff=4; ExpectedMatches=1 }
        ) }
    )
    $declined = Invoke-PatchMilestones -Buf $partialBuf -Img $partialImg -Milestones $partialMilestones -Apply $true
    Assert-True ($declined.Status -eq 0 -and $declined.Reason -match 'partial') 'partial layout should be declined by default'

    $ambiguous = @(
        [pscustomobject]@{ Name='a'; Container='pe'; Sites=$partialMilestones[0].Sites },
        [pscustomobject]@{ Name='b'; Container='pe'; Sites=$partialMilestones[0].Sites }
    )
    $ambiguousResult = Invoke-PatchMilestones -Buf ([IO.File]::ReadAllBytes($pePath)) -Img $partialImg -Milestones $ambiguous -AllowPartial $true -Apply $true
    Assert-True ($ambiguousResult.Status -eq 0 -and $ambiguousResult.Reason -match 'tied') 'ambiguous partial layouts should be declined'

    # --- Windows on ARM (pe-arm64 / bcond) -----------------------------------
    # arm64 gate: cmp w,#2 ; b.gt ; nop ; cmp w,#1. The flip rewrites ONLY the
    # B.cond condition GT(0xC)->AL(0xE) - one byte, imm19 preserved - the same
    # code path as the macOS arm64 slice. Little-endian words:
    #   7100091F cmp w,#2 | 5400008C b.gt | D503201F nop | 7100051F cmp w,#1
    $armSig = [byte[]]@(0x1F,0x09,0x00,0x71, 0x8C,0x00,0x00,0x54, 0x1F,0x20,0x03,0xD5, 0x1F,0x05,0x00,0x71)
    $armTarget = Join-Path $temp 'arm64 fixture.dll'
    $armSigPath = Join-Path $temp 'arm64 signatures.json'
    New-TestPe -Path $armTarget -Signature $armSig -Machine 0xAA64
    $armImg = Open-Image ([IO.File]::ReadAllBytes($armTarget))
    Assert-True ($armImg.Format -eq 'pe-arm64') 'arm64 PE (machine 0xAA64) must be tagged pe-arm64, not pe'

    $armBuf = [IO.File]::ReadAllBytes($armTarget)
    $astart = 0x440
    Assert-True (Test-SigAt -Buf $armBuf -Start $astart -Sig $armSig -JgOff 4 -Kind 2) 'stock b.gt should match (bcond)'
    $armBuf[$astart + 4] = 0x8E   # cond AL = already patched
    Assert-True (Test-SigAt -Buf $armBuf -Start $astart -Sig $armSig -JgOff 4 -Kind 2) 'patched b.al should match (idempotent)'
    Initialize-NativeHelpers
    Assert-True ([Mv2Native]::SigMatchesAt($armBuf, $astart, $armSig, 4, 2)) 'compiled matcher accepts b.al'
    $armBuf[$astart + 4] = 0x8D   # cond LE = inverted sense, must not match
    Assert-True (-not (Test-SigAt -Buf $armBuf -Start $astart -Sig $armSig -JgOff 4 -Kind 2)) 'b.le condition must not match'
    Assert-True (-not [Mv2Native]::SigMatchesAt($armBuf, $astart, $armSig, 4, 2)) 'compiled matcher rejects b.le'
    $armBuf[$astart + 4] = 0x8C; $armBuf[$astart + 7] = 0x14   # opcode 0x14 = unconditional B, not B.cond
    Assert-True (-not (Test-SigAt -Buf $armBuf -Start $astart -Sig $armSig -JgOff 4 -Kind 2)) 'non-B.cond opcode must not match'

    Write-Signatures -Path $armSigPath -Milestones @(
        @{ name='test-pe-arm64'; container='pe-arm64'; sites=@(
            @{ name='gate'; kind='bcond'; jgRVA='0x00001044'; jgOff=4; expectedMatches=1; sig='1F0900718C0000541F2003D51F050071' }
        ) }
    )
    $script:Signatures = $armSigPath
    $armObj = [pscustomobject]@{ Path=$armTarget; Channel='Test'; Running=$false; Holders=0 }
    Assert-True ((Invoke-Patch -Target $armObj -AssumeYes $true) -eq 0) 'arm64 synthetic PE patch should succeed'
    Assert-True (([IO.File]::ReadAllBytes($armTarget))[0x444] -eq 0x8E) 'patch should flip b.gt (0x8C) -> b.al (0x8E)'
    Assert-True (Test-Path -LiteralPath "$armTarget.bak") 'arm64 patch should create a backup'
    $armHash = (Get-FileHash -LiteralPath $armTarget -Algorithm SHA256).Hash
    Assert-True ((Invoke-Patch -Target $armObj -AssumeYes $true) -eq 0) 'idempotent arm64 re-patch should succeed'
    Assert-True ((Get-FileHash -LiteralPath $armTarget -Algorithm SHA256).Hash -eq $armHash) 'idempotent arm64 re-patch should not rewrite different bytes'
    Assert-True ((Invoke-Restore -Target $armObj -AssumeYes $true) -eq 0) 'arm64 restore should succeed'
    Assert-True (([IO.File]::ReadAllBytes($armTarget))[0x444] -eq 0x8C) 'restore should recover the stock b.gt byte'
    Assert-True (-not (Test-Path -LiteralPath "$armTarget.bak")) 'arm64 restore should remove the backup'
    $script:Signatures = $sigPath

    # --- Windows on ARM (pe-arm64 / cbz) --------------------------------------
    # Gate B mac-arm64 shape: mov x0,x20 ; bl SFSP ; cbz w0,<skip> ; b +0x2c.
    # The flip rewrites the CBZ word 0x34FFDF60 to the unconditional B 0x17FFFEFB
    # with the SAME resolved target (imm26 recomputed from the sign-extended imm19).
    $cbzSigHex = 'E00314AA642EEA9460DFFF340B000014'
    $cbzSig = [byte[]]@(0xE0,0x03,0x14,0xAA, 0x64,0x2E,0xEA,0x94, 0x60,0xDF,0xFF,0x34, 0x0B,0x00,0x00,0x14)
    $cbzTarget = Join-Path $temp 'cbz fixture.dll'
    $cbzSigPath = Join-Path $temp 'cbz signatures.json'
    New-TestPe -Path $cbzTarget -Signature $cbzSig -Machine 0xAA64
    $cbzBuf = [IO.File]::ReadAllBytes($cbzTarget)
    $cstart = 0x440
    Assert-True (Test-SigAt -Buf $cbzBuf -Start $cstart -Sig $cbzSig -JgOff 8 -Kind 4) 'stock CBZ should match (cbz)'
    # patched form: B 0x17FFFEFB - same target as the sig CBZ
    $cbzBuf[$cstart + 8]  = 0xFB; $cbzBuf[$cstart + 9]  = 0xFE; $cbzBuf[$cstart + 10] = 0xFF; $cbzBuf[$cstart + 11] = 0x17
    Assert-True (Test-SigAt -Buf $cbzBuf -Start $cstart -Sig $cbzSig -JgOff 8 -Kind 4) 'patched B (same target) should match (idempotent)'
    Assert-True ([Mv2Native]::SigMatchesAt($cbzBuf, $cstart, $cbzSig, 8, 4)) 'compiled matcher accepts the patched B'
    # a foreign B (different target) must NOT read as ours
    $cbzBuf[$cstart + 8] = 0x01; $cbzBuf[$cstart + 9] = 0x00; $cbzBuf[$cstart + 10] = 0x00; $cbzBuf[$cstart + 11] = 0x14
    Assert-True (-not (Test-SigAt -Buf $cbzBuf -Start $cstart -Sig $cbzSig -JgOff 8 -Kind 4)) 'foreign B target must not match'
    Assert-True (-not [Mv2Native]::SigMatchesAt($cbzBuf, $cstart, $cbzSig, 8, 4)) 'compiled matcher rejects a foreign B'

    Write-Signatures -Path $cbzSigPath -Milestones @(
        @{ name='t-cbz'; container='pe-arm64'; sites=@(
            @{ name='gate'; kind='cbz'; jgRVA='0x00001048'; jgOff=8; expectedMatches=1; sig=$cbzSigHex }
        ) }
    )
    $script:Signatures = $cbzSigPath
    $cbzObj = [pscustomobject]@{ Path=$cbzTarget; Channel='Test'; Running=$false; Holders=0 }
    Assert-True ((Invoke-Patch -Target $cbzObj -AssumeYes $true) -eq 0) 'cbz synthetic PE patch should succeed'
    $cbzPatched = [IO.File]::ReadAllBytes($cbzTarget)
    $patchedWord = [BitConverter]::ToUInt32($cbzPatched, 0x448)
    Assert-True ($patchedWord -eq 0x17FFFEFB) 'cbz patch should rewrite 34FFDF60 -> 17FFFEFB (B, same target)'
    $cbzHash = (Get-FileHash -LiteralPath $cbzTarget -Algorithm SHA256).Hash
    Assert-True ((Invoke-Patch -Target $cbzObj -AssumeYes $true) -eq 0) 'idempotent cbz re-patch should succeed'
    Assert-True ((Get-FileHash -LiteralPath $cbzTarget -Algorithm SHA256).Hash -eq $cbzHash) 'idempotent cbz re-patch should not rewrite different bytes'
    Assert-True ((Invoke-Restore -Target $cbzObj -AssumeYes $true) -eq 0) 'cbz restore should succeed'
    $cbzRestored = [IO.File]::ReadAllBytes($cbzTarget)
    $stockWord = [BitConverter]::ToUInt32($cbzRestored, 0x448)
    Assert-True ($stockWord -eq 0x34FFDF60) 'cbz restore should recover the stock CBZ word'
    $script:Signatures = $sigPath

    # --- near stockOpcode (near-JE shape, pe container) -----------------
    # cmp ...,2 ; je near (0F 84 disp32) ; mov. Stock pair 0F 84 (not 0F 8F):
    # the flip writes 90 E9 keeping the disp32 bit-identical.
    $jeSigHex = '837F50020F84FCFCFFFF488B8C24200100'
    $jeSig = [byte[]]@(0x83,0x7F,0x50,0x02, 0x0F,0x84,0xFC,0xFC,0xFF,0xFF, 0x48,0x8B,0x8C,0x24,0x20,0x01,0x00)
    $jeTarget = Join-Path $temp 'je fixture.dll'
    $jeSigPath = Join-Path $temp 'je signatures.json'
    New-TestPe -Path $jeTarget -Signature $jeSig
    $jeBuf = [IO.File]::ReadAllBytes($jeTarget)
    Assert-True (Test-SigAt -Buf $jeBuf -Start 0x440 -Sig $jeSig -JgOff 4 -Kind 1) 'stock near je (0F 84) should match'
    $jeBuf[0x444] = 0x90; $jeBuf[0x445] = 0xE9
    Assert-True (Test-SigAt -Buf $jeBuf -Start 0x440 -Sig $jeSig -JgOff 4 -Kind 1) 'patched 90 E9 should match (idempotent)'
    Assert-True ([Mv2Native]::SigMatchesAt($jeBuf, 0x440, $jeSig, 4, 1)) 'compiled matcher accepts 90 E9 over a 0F 84 stock'
    $jeBuf[0x444] = 0x0F; $jeBuf[0x445] = 0x85
    Assert-True (-not (Test-SigAt -Buf $jeBuf -Start 0x440 -Sig $jeSig -JgOff 4 -Kind 1)) 'a jne pair (0F 85) must not match the 0F 84 stock sig'

    Write-Signatures -Path $jeSigPath -Milestones @(
        @{ name='t-je'; container='pe'; sites=@(
            @{ name='gate'; kind='near'; stockOpcode='0x0F84'; jgRVA='0x00001044'; jgOff=4; expectedMatches=1; sig=$jeSigHex }
        ) }
    )
    $script:Signatures = $jeSigPath
    $jeObj = [pscustomobject]@{ Path=$jeTarget; Channel='Test'; Running=$false; Holders=0 }
    Assert-True ((Invoke-Patch -Target $jeObj -AssumeYes $true) -eq 0) 'near-je stockOpcode patch should succeed'
    $patched = [IO.File]::ReadAllBytes($jeTarget)
    Assert-True ($patched[0x444] -eq 0x90 -and $patched[0x445] -eq 0xE9) 'near-je patch should write 90 E9 at jgOff'
    Assert-True ($patched[0x446] -eq 0xFC -and $patched[0x447] -eq 0xFC -and $patched[0x448] -eq 0xFF -and $patched[0x449] -eq 0xFF) 'near-je patch must preserve disp32 bit-identically'
    $jeHash = (Get-FileHash -LiteralPath $jeTarget -Algorithm SHA256).Hash
    Assert-True ((Invoke-Patch -Target $jeObj -AssumeYes $true) -eq 0) 'idempotent near-je re-patch should succeed'
    Assert-True ((Get-FileHash -LiteralPath $jeTarget -Algorithm SHA256).Hash -eq $jeHash) 'idempotent near-je re-patch should not rewrite different bytes'
    Assert-True ((Invoke-Restore -Target $jeObj -AssumeYes $true) -eq 0) 'near-je restore should succeed'
    $restored = [IO.File]::ReadAllBytes($jeTarget)
    Assert-True ($restored[0x444] -eq 0x0F -and $restored[0x445] -eq 0x84) 'near-je restore should recover the stock 0F 84'
    $script:Signatures = $sigPath

    # --- window pause decision -----------------------------------------------
    # An interactive run always holds the window open ("Press Enter to exit."),
    # success included - the window is often opened by a double-click, so a
    # successful patch must not flash past. Silence/automation switches still win
    # over both.
    Assert-True (Test-ShouldPause -ExitCode 0 -IsElevatedChild $false -QuietMode $false -ChildAlreadyPaused $false -InputRedirected $false) 'ordinary success should pause'
    Assert-True (Test-ShouldPause -ExitCode 1 -IsElevatedChild $false -QuietMode $false -ChildAlreadyPaused $false -InputRedirected $false) 'failure should pause so the error stays visible'
    Assert-True (Test-ShouldPause -ExitCode 0 -IsElevatedChild $true -QuietMode $false -ChildAlreadyPaused $false -InputRedirected $false) 'elevated child should pause even on success'
    Assert-True (Test-ShouldPause -ExitCode 1 -IsElevatedChild $true -QuietMode $false -ChildAlreadyPaused $false -InputRedirected $false) 'elevated child should pause on failure'
    Assert-True (-not (Test-ShouldPause -ExitCode 0 -IsElevatedChild $true -QuietMode $true -ChildAlreadyPaused $false -InputRedirected $false)) '-Quiet should suppress the elevated child pause'
    Assert-True (-not (Test-ShouldPause -ExitCode 1 -IsElevatedChild $false -QuietMode $true -ChildAlreadyPaused $false -InputRedirected $false)) '-Quiet should suppress the failure pause'
    Assert-True (-not (Test-ShouldPause -ExitCode 1 -IsElevatedChild $false -QuietMode $false -ChildAlreadyPaused $true -InputRedirected $false)) 'parent should not pause again after the child paused'
    Assert-True (-not (Test-ShouldPause -ExitCode 0 -IsElevatedChild $true -QuietMode $false -ChildAlreadyPaused $false -InputRedirected $true)) 'redirected input must never hang an unattended run'

    Write-Host "PowerShell tests passed: $passed assertions"
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
'''

# Elevation regression test for the `irm ... | iex` launch shape.
#
# There is no script file there, so Invoke-SelfElevate has to recover its own
# source, stage it, and relaunch with -File. It used to instead replay
# powershell.exe's own argv and inject the loop guard into the -Command payload,
# which refused outright ("Cannot ask for administrator access this way") for any
# launch shape whose payload is not a literal -Command/-EncodedCommand token.
#
# The shape below matters: the driver is reached through an IMPLICIT positional
# command (`powershell "iex ..."`, the documented one-liner), so there is no
# -Command token in argv. A test that passed -Command explicitly would pass
# against the old code too and catch nothing. Everything reaches the patcher
# through iex, so $PSCommandPath stays empty all the way down and the staging
# branch is the one under test.
PS_ELEVATION_DRIVER = r'''
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$src = [IO.File]::ReadAllText((Join-Path $env:MV2_REPO 'chrome-mv2.ps1'))
$anchor = 'if ($env:MV2_TEST_LIBRARY_ONLY) { return }'
if (-not $src.Contains($anchor)) { throw 'library-only anchor not found in chrome-mv2.ps1' }

# Spliced in at the anchor so it runs in the patcher's own scope, where the
# param() defaults ($Command, $Yes, ...) that Invoke-SelfElevate forwards live.
$probe = @'
Initialize-Colors
$script:RelaunchArgs = ''
$script:StagedPath = $null
$script:StagedText = $null
$script:SwapBlocked = $false
$script:DeleteBlocked = $false
$script:ChildExit = 7

# A function shadows the cmdlet, so no elevated process is ever spawned.
function Start-Process {
    param(
        [string]$FilePath, [string]$ArgumentList, [string]$Verb,
        [string]$WorkingDirectory, [switch]$Wait, [switch]$PassThru,
        [string]$ErrorAction
    )
    $script:RelaunchArgs = $ArgumentList
    if ($ArgumentList -match '-File\s+"?([^"]+chrome-mv2\.ps1)"?') {
        $script:StagedPath = $Matches[1]
        # What the elevated child does: open the staged script for reading.
        $fs = [IO.File]::Open($script:StagedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $sr = New-Object IO.StreamReader($fs, $true)
        $script:StagedText = $sr.ReadToEnd()
        $sr.Dispose(); $fs.Dispose()
        # What a same-user attacker does after UAC consent: swap the file.
        try { [IO.File]::WriteAllText($script:StagedPath, 'swapped') } catch { $script:SwapBlocked = $true }
        try { [IO.File]::Delete($script:StagedPath) } catch { $script:DeleteBlocked = $true }
    }
    return [pscustomobject]@{ ExitCode = $script:ChildExit }
}

$dll = 'C:\Program Files\Google\Chrome\Application\1.2.3.4\chrome.dll'
$code = Invoke-SelfElevate -ResolvedTargetPath $dll

$fail = @()
if ($code -ne 7) { $fail += "did not elevate (returned '$code')" }
if (-not $script:StagedPath) { $fail += 'relaunch args carried no -File staged copy' }
elseif (-not $script:StagedPath.StartsWith([IO.Path]::GetTempPath(), 'OrdinalIgnoreCase')) {
    $fail += "staged copy is not under TEMP: $($script:StagedPath)"
}
if ($script:RelaunchArgs -notmatch '(^|\s)-Relaunched(\s|$)') { $fail += 'loop guard -Relaunched not forwarded' }
if ($script:RelaunchArgs -notmatch [regex]::Escape('"' + $dll + '"')) { $fail += 'target not forwarded as one quoted argument' }
if ($script:StagedText -cne $global:MV2SplicedSource) { $fail += 'staged copy is not the source that actually ran' }
if (-not $script:SwapBlocked) { $fail += 'staged copy could be overwritten while the child held it' }
if (-not $script:DeleteBlocked) { $fail += 'staged copy could be deleted while the child held it' }
if ($script:StagedPath -and (Test-Path -LiteralPath (Split-Path -Parent $script:StagedPath))) {
    $fail += 'temp stage was not cleaned up'
}

# The parent window must not end on "asking for administrator access" as if
# nothing had happened, so it reports the child's outcome. Target resolution and
# the writability probe are stubbed out so this needs no installed Chrome and
# touches no real file.
function Resolve-Target {
    param($TargetPath, $Interactive)
    return [pscustomobject]@{ Path = 'C:\nonexistent\chrome.dll'; Channel = 'Test'; Version = '1.2.3.4'; Running = $false; Holders = 0 }
}
function Test-TargetDirectoryWritable { param($TargetPath) return $false }
function Test-Elevated { return $false }
$script:Reported = @()
function Write-Ok  { param([string]$m) $script:Reported += "OK:$m" }
function Write-Err { param([string]$m) $script:Reported += "ERR:$m" }

$script:ChildExit = 0
$rc = Invoke-Main
if ($rc -ne 0) { $fail += "parent should hand back the child's exit code 0 (got '$rc')" }
if (-not ($script:Reported -match '^OK:')) { $fail += 'parent stayed silent after a successful elevated run' }

$script:Reported = @()
$script:ChildExit = 1
$rc = Invoke-Main
if ($rc -ne 1) { $fail += "parent should hand back the child's exit code 1 (got '$rc')" }
if (-not ($script:Reported -match '^ERR:')) { $fail += 'parent stayed silent after a failed elevated run' }

$global:MV2ElevationFailures = $fail
return
'@

$global:MV2SplicedSource = $src.Replace($anchor, $probe)
$global:MV2ElevationFailures = $null
Invoke-Expression $global:MV2SplicedSource

if ($null -eq $global:MV2ElevationFailures) {
    Write-Host 'ELEVATION TEST FAILED: probe never ran'
    exit 1
}
if ($global:MV2ElevationFailures.Count) {
    Write-Host ('ELEVATION TEST FAILED: ' + ($global:MV2ElevationFailures -join '; '))
    exit 1
}
Write-Host 'PowerShell elevation staging tests passed: 12 assertions'
exit 0
'''


def _run_ps(host, body, env, positional=False):
    """Run a PowerShell body from a temp .ps1. With positional=True the file is
    reached through an implicit positional command and iex, so the code under test
    sees no script file at all (the `irm ... | iex` shape)."""
    with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8") as f:
        f.write(body)
        ps_path = f.name
    try:
        if positional:
            argv = [host, "-NoProfile", "iex (gc -Raw '%s')" % ps_path]
        else:
            argv = [host, "-NoProfile", "-File", ps_path]
        return subprocess.run(argv, env=env, capture_output=True, text=True)
    finally:
        os.unlink(ps_path)


def main():
    if not sys.platform.startswith("win"):
        # The PowerShell patcher targets Windows; its white-box test dot-sources
        # Windows-oriented internals (Add-Type helper, PE parsing). Skip off-Windows
        # even where pwsh (Core) exists, to avoid cross-platform false failures.
        print("PowerShell tests skipped: not on Windows")
        return 0
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh:
        print("PowerShell tests skipped: no pwsh/powershell on PATH")
        return 0
    env = dict(os.environ, MV2_REPO=str(REPO))

    r = _run_ps(pwsh, PS_TEST, env)
    sys.stdout.write(r.stdout)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        sys.exit(r.returncode)

    # Windows PowerShell specifically: only powershell.exe accepts a command in
    # the implicit positional slot (pwsh treats a bare argument as -File), and
    # that slot is what the documented one-liner and the old bug both used.
    ps51 = shutil.which("powershell")
    if not ps51:
        print("PowerShell elevation staging tests skipped: no powershell.exe on PATH")
        return 0
    r = _run_ps(ps51, PS_ELEVATION_DRIVER, env, positional=True)
    sys.stdout.write(r.stdout)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        sys.exit(r.returncode)
    return 0


if __name__ == "__main__":
    main()


