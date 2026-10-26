# SPDX-License-Identifier: MIT
# Gate R001-R005, then the complete catalog and separate synthetic holdout.
[CmdletBinding()]
param([switch]$SkipFullRegression)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $root
$transcriptStarted = $false
$transcriptFile = Join-Path $root ('build-verify/rule-batches/batch-001-005-' +
    (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss') + '.txt')
$stageLogs = [ordered]@{}
try {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $transcriptFile) | Out-Null
    Start-Transcript -Path $transcriptFile -ErrorAction Stop | Out-Host
    $transcriptStarted = $true
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
    # Start-Transcript in Windows PowerShell 5.1 can miss stdout from nested
    # native processes. Capture every stage independently; after the transcript
    # closes, append those complete outputs to the same timestamped TXT file.
    $runStamp = [IO.Path]::GetFileNameWithoutExtension($transcriptFile)
    $stageLogs['Targeted xUnit tests'] = Join-Path $root (Join-Path $resultsDir ($runStamp + '-targeted.log'))
    $stageLogs['Full regression'] = Join-Path $root (Join-Path $resultsDir ($runStamp + '-regression.log'))
    $stageLogs['Synthetic holdout'] = Join-Path $root (Join-Path $resultsDir ($runStamp + '-holdout.log'))
    Write-Host '=== Batch 01 R001-R005: legacy suites + at least 25 advanced cases ==='
    $argsForTests = @(
        'test','Carthago.Tests/Carthago.Tests.csproj','--configuration','Release',
        '--verbosity','normal','--filter',$filter,
        '--logger','trx;LogFileName=R001-R005.trx','--results-directory',$resultsDir
    )
    $priorPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & dotnet @argsForTests *>&1 | Tee-Object -FilePath ($stageLogs['Targeted xUnit tests']) | Out-Host
        $testExitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $priorPreference }
    if (-not (Test-Path -LiteralPath $stageLogs['Targeted xUnit tests'] -PathType Leaf)) {
        throw 'Missing complete targeted xUnit log.'
    }
    if ($testExitCode -ne 0) { throw 'R001-R005 targeted xUnit suite failed.' }

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
    if ($bad.Count -gt 0 -or $advanced.Count -lt 25) {
        throw "Batch requires all passing and at least 25 advanced tests; found $($advanced.Count)."
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
        $priorPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & $psExe -NoProfile -File 'verify-local.ps1' -Details -LiveOutput *>&1 |
                Tee-Object -FilePath ($stageLogs['Full regression']) | Out-Host
            $regressionExitCode = $LASTEXITCODE
        } finally { $ErrorActionPreference = $priorPreference }
        if (-not (Test-Path -LiteralPath $stageLogs['Full regression'] -PathType Leaf)) {
            throw 'Missing complete full-regression log.'
        }
        if ($regressionExitCode -ne 0) { throw 'Full regression failed. Do not advance to R006.' }

        Write-Host '=== Separate synthetic holdout ==='
        $priorPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & $psExe -NoProfile -File 'scripts/evaluate-holdout.ps1' -NoBuild *>&1 |
                Tee-Object -FilePath ($stageLogs['Synthetic holdout']) | Out-Host
            $holdoutExitCode = $LASTEXITCODE
        } finally { $ErrorActionPreference = $priorPreference }
        if (-not (Test-Path -LiteralPath $stageLogs['Synthetic holdout'] -PathType Leaf)) {
            throw 'Missing complete synthetic-holdout log.'
        }
        if ($holdoutExitCode -ne 0) { throw 'Holdout failed. Do not advance to R006.' }

        Write-Host 'PASS: R001-R005 targeted + full regression + separate holdout.'
    }
    Write-Host ("Batch result file: " + (Join-Path $root $trxPath))
}
finally {
    if ($transcriptStarted) { Stop-Transcript | Out-Host }
    Pop-Location
    if ($transcriptStarted) {
        # Append after Stop-Transcript releases its handle. The child stage
        # logs are authoritative and remain separately available for diagnosis.
        $writer = $null
        try {
            $writer = [IO.StreamWriter]::new($transcriptFile, $true,
                [Text.UTF8Encoding]::new($false))
            foreach ($entry in $stageLogs.GetEnumerator()) {
                if (-not (Test-Path -LiteralPath $entry.Value -PathType Leaf)) { continue }
                $writer.WriteLine('')
                $writer.WriteLine('=== COMPLETE STAGE OUTPUT: ' + $entry.Key + ' ===')
                $reader = [IO.StreamReader]::new($entry.Value)
                try {
                    while ($null -ne ($line = $reader.ReadLine())) { $writer.WriteLine($line) }
                } finally { $reader.Dispose() }
            }
        } finally {
            if ($null -ne $writer) { $writer.Dispose() }
        }
    }
    Write-Host ("Complete batch TXT transcript: " + $transcriptFile)
}
