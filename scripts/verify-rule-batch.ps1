# SPDX-License-Identifier: MIT
# Verify one per-rule xUnit file at a time; stop after the first failure.
# This focused gate does not replace verify-local.ps1.
[CmdletBinding()]
param(
    [ValidateRange(1, 544)][int]$First = 1,
    [ValidateRange(1, 544)][int]$Last = 5
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
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    $ruleIds = @($First..$Last | ForEach-Object { 'R{0:000}' -f $_ })
    foreach ($id in $ruleIds) {
        $testFile = "Carthago.Tests/$($id)Tests.cs"
        if (-not (Test-Path -LiteralPath $testFile -PathType Leaf)) {
            throw "Missing dedicated test file: $testFile. Do not skip a rule."
        }
    }

    Write-Host ("Compiling rule batch: " + ($ruleIds -join ', '))
    & dotnet build $project -c Release --verbosity quiet --nologo
    if ($LASTEXITCODE -ne 0) { throw 'The rule batch failed to compile.' }

    foreach ($id in $ruleIds) {
        $label = "$($id)Tests"
        $log = Join-Path $logDir "$label.log"
        Write-Host "START: $id — dedicated $label.cs"
        $testArgs = @('test', $project, '-c', 'Release', '--no-build',
            '--no-restore', '--filter', "FullyQualifiedName~Carthago.Tests.$label",
            '--logger', "trx;LogFileName=$label.trx",
            '--results-directory', $logDir, '--verbosity', 'normal')
        & dotnet @testArgs 2>&1 | Tee-Object -FilePath $log | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "$id failed. Inspect $log and the $label.trx file before moving on."
        }
        Write-Host "PASS: $id"
    }

    Write-Host ("PASS: all per-rule test files verified: " + ($ruleIds -join ', '))
    Write-Host 'Next: run .\verify-local.ps1 -Details -LiveOutput for all 544 rules and replay regression checks.'
}
finally {
    Pop-Location
}
