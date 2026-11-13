# SPDX-License-Identifier: MIT
# Verify one dedicated per-rule xUnit file at a time; stop at the first failure.
# This focused gate does not replace verify-local.ps1.
[CmdletBinding()]
param(
    [ValidateRange(1, 2147483647)][int]$First = 1,
    [ValidateRange(1, 2147483647)][int]$Last = 5
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Last -lt $First) { throw 'Last must be >= First.' }
if ($Last - $First -gt 4) { throw 'Verify no more than five rules per batch.' }

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$project = 'Carthago.Tests/Carthago.Tests.csproj'
$logDir = Join-Path $root 'build-verify/rule-batches'
Push-Location $root
try {
    $ruleIds = @($First..$Last | ForEach-Object {
        'R' + $_.ToString('D3', [Globalization.CultureInfo]::InvariantCulture)
    })
    # Exact canonical numeric prefix followed by a supported dedicated class
    # suffix; R1000 cannot match R100 or R10000.
    $testFiles = @(Get-ChildItem -LiteralPath (Join-Path $root 'Carthago.Tests') -File -Filter '*.cs')
    $labels = @{}
    foreach ($id in $ruleIds) {
        $pattern = '^' + [regex]::Escape($id) + '(?:Tests|[A-Za-z][A-Za-z0-9]*QualityTests)\.cs$'
        $matchesForRule = @($testFiles | Where-Object { $_.Name -cmatch $pattern })
        if ($matchesForRule.Count -ne 1) {
            throw "Expected exactly one dedicated test file for $id; found $($matchesForRule.Count). Do not skip or guess."
        }
        $labels[$id] = $matchesForRule[0].BaseName
    }

    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    Write-Host ("Compiling rule batch: " + ($ruleIds -join ', '))
    & dotnet build $project -c Release --verbosity quiet --nologo
    if ($LASTEXITCODE -ne 0) { throw 'The rule batch failed to compile.' }

    foreach ($id in $ruleIds) {
        $label = $labels[$id]
        $log = Join-Path $logDir "$label.log"
        $trxPath = Join-Path $logDir "$label.trx"
        Write-Host "START: $id — dedicated $label.cs"
        $testArgs = @('test', $project, '-c', 'Release', '--no-build',
            '--no-restore', '--filter', "FullyQualifiedName~Carthago.Tests.$label.",
            '--logger', "trx;LogFileName=$label.trx",
            '--results-directory', $logDir, '--verbosity', 'normal')
        if (Test-Path -LiteralPath $trxPath) { Remove-Item -LiteralPath $trxPath -Force }
        & dotnet @testArgs 2>&1 | Tee-Object -FilePath $log | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "$id failed. Inspect $log and $trxPath before moving on."
        }
        if (-not (Test-Path -LiteralPath $trxPath -PathType Leaf)) { throw "$id produced no TRX." }
        [xml]$trx = Get-Content -LiteralPath $trxPath -Raw
        $results = @($trx.SelectNodes("//*[local-name()='UnitTestResult']"))
        if ($results.Count -eq 0 -or @($results | Where-Object { $_.outcome -ne 'Passed' }).Count -gt 0) {
            throw "$id did not produce nonempty passing test results."
        }
        # Verify every result actually belongs to the requested class, including
        # parameterized tests. This catches accidental broad filters.
        foreach ($result in $results) {
            $testName = $result.GetAttribute('testName')
            if ($testName -notmatch ('^Carthago\.Tests\.' + [regex]::Escape($label) + '\.')) {
                throw "$id returned an unrelated test: $testName"
            }
        }
        Write-Host "PASS: $id ($($results.Count) cases)"
    }

    Write-Host ("PASS: all per-rule test files verified: " + ($ruleIds -join ', '))
    Write-Host 'Next: run .\verify-local.ps1 -Details -LiveOutput for the full registered suite and replay regression checks.'
}
finally {
    Pop-Location
}
