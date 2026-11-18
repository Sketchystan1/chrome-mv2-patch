$ErrorActionPreference = 'Stop'

$workflow = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../workflows/win-build.yml') -Raw
$match = [regex]::Match($workflow, '(?ms)^      - name: Read release notes from CHANGELOG\.md\r?\n.*?^        run: \|\r?\n(?<script>(?:^          [^\r\n]*\r?\n)+)')
if (-not $match.Success) { throw 'release notes workflow step not found' }
$step = [scriptblock]::Create(($match.Groups['script'].Value -replace '(?m)^ {10}', ''))

$v200 = "## [2.0.0] - 2026-11-17`n`n- Windows Patcher v2."
$v201 = "## [2.0.1] - 2026-11-18`n`n- Bug fix."
$v211 = "## [2.1.1] - 2026-11-18`n`n- Latest changes."
$v116 = "## [1.16.0] - 2026-11-07`n`n- Legacy changes."
$changelog = @('# Changelog', "## [Unreleased]`n`n- Future changes.",
               "## [3.0.0]`n`n- Next major.", '## [2.2.0]', $v211, $v201, $v200, $v116) -join "`n`n"
$cases = @(
    @('v2.1.1', "$v211`n`n$v201`n`n$v200"),
    @('v2.0.1', "$v201`n`n$v200"),
    @('v2.0.0', $v200),
    @('v1.16.0', $v116)
)

$testDir = Join-Path ([IO.Path]::GetTempPath()) ('mv2-release-notes-' + [guid]::NewGuid())
$originalTag = $env:RELEASE_TAG
New-Item -ItemType Directory -Path $testDir | Out-Null
Push-Location -LiteralPath $testDir
try {
    $checks = 0
    foreach ($newline in "`n", "`r`n") {
        Set-Content -LiteralPath 'CHANGELOG.md' -Value ($changelog -replace "`n", $newline) -Encoding utf8
        foreach ($case in $cases) {
            $env:RELEASE_TAG = $case[0]
            & $step
            $actual = (Get-Content -LiteralPath 'release-notes.md' -Raw).Trim()
            $expected = $case[1] -replace "`n", $newline
            if ($actual -cne $expected) { throw "incorrect release notes for $env:RELEASE_TAG" }
            $checks++
        }
        foreach ($case in @(@('v2.1.2', 'no changelog entry for 2.1.2'),
                           @('v2.2.0', 'empty changelog entry for 2.2.0'))) {
            $env:RELEASE_TAG = $case[0]
            $errorMessage = $null
            try { & $step } catch { $errorMessage = $_.Exception.Message }
            if ($errorMessage -ne $case[1]) { throw "expected '$($case[1])', got '$errorMessage'" }
            $checks++
        }
    }
    Write-Host "$checks release notes checks passed."
} finally {
    Pop-Location
    $env:RELEASE_TAG = $originalTag
    [IO.File]::Delete((Join-Path $testDir 'CHANGELOG.md'))
    [IO.File]::Delete((Join-Path $testDir 'release-notes.md'))
    [IO.Directory]::Delete($testDir)
}
