# SPDX-License-Identifier: MIT
# Gate R001-R005, then the complete catalog and separate synthetic holdout.
[CmdletBinding()]
param([switch]$SkipFullRegression)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $root
try {
    $classNames = @(
        'R001Tests','R002Tests','R003Tests','R004Tests','R005Tests',
        'R001AdvancedAccuracyBatchTests','R002AdvancedAccuracyBatchTests',
        'R003AdvancedAccuracyBatchTests','R004AdvancedAccuracyBatchTests',
        'R005AdvancedAccuracyBatchTests'
    )
    $filter = ($classNames | ForEach-Object {
        'FullyQualifiedName~Carthago.Tests.' + $_
    }) -join '|'
    $resultsDir = 'build-verify/rule-batches'
    New-Item -ItemType Directory -Force -Path $resultsDir | Out-Null
    Write-Host '=== Batch 01 R001-R005: legacy suites + 25 new cases ==='
    $argsForTests = @(
        'test','Carthago.Tests/Carthago.Tests.csproj','--configuration','Release',
        '--verbosity','normal','--filter',$filter,
        '--logger','trx;LogFileName=R001-R005.trx','--results-directory',$resultsDir
    )
    & dotnet @argsForTests
    if ($LASTEXITCODE -ne 0) { throw 'R001-R005 targeted xUnit suite failed.' }

    $trxPath = Join-Path $resultsDir 'R001-R005.trx'
    if (-not (Test-Path -LiteralPath $trxPath -PathType Leaf)) {
        throw 'Missing R001-R005 TRX evidence.'
    }
    [xml]$trx = Get-Content -LiteralPath $trxPath -Raw
    $results = @($trx.SelectNodes("//*[local-name()='UnitTestResult']"))
    $bad = @($results | Where-Object { $_.outcome -ne 'Passed' })
    $advanced = @($results | Where-Object {
        $_.testName -like '*AdvancedAccuracyBatchTests*'
    })
    Write-Host ("Batch results: total={0}; advanced={1}; not passed={2}" -f
        $results.Count, $advanced.Count, $bad.Count)
    if ($bad.Count -gt 0 -or $advanced.Count -ne 25) {
        throw "Batch requires all passing and exactly 25 advanced tests; found $($advanced.Count)."
    }

    if ($SkipFullRegression) {
        Write-Warning 'Full regression skipped: R001-R005 cannot be marked complete.'
    } else {
        $psExe = Join-Path $PSHOME 'powershell.exe'
        if (-not (Test-Path -LiteralPath $psExe)) {
            $psExe = Join-Path $PSHOME 'pwsh.exe'
        }
        if (-not (Test-Path -LiteralPath $psExe)) {
            throw 'Windows PowerShell/Pwsh executable not found.'
        }
        Write-Host '=== Full catalog regression ==='
        & $psExe -NoProfile -File 'verify-local.ps1' -Details -LiveOutput
        if ($LASTEXITCODE -ne 0) { throw 'Full regression failed. Do not advance to R006.' }

        Write-Host '=== Separate synthetic holdout ==='
        & $psExe -NoProfile -File 'scripts/evaluate-holdout.ps1' -NoBuild
        if ($LASTEXITCODE -ne 0) { throw 'Holdout failed. Do not advance to R006.' }

        Write-Host 'PASS: R001-R005 targeted + full regression + separate holdout.'
    }
    Write-Host ("Batch result file: " + (Join-Path $root $trxPath))
}
finally {
    Pop-Location
}
