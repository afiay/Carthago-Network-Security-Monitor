# SPDX-License-Identifier: MIT
[CmdletBinding()]
param([Parameter(Mandatory)][string]$SyntheticReport,
    [Parameter(Mandatory)][string[]]$PhysicalReports,
    [Parameter(Mandatory)][string]$PositiveServiceReport,
    [Parameter(Mandatory)][string[]]$NegativeServiceReports,
    [Parameter(Mandatory)][string[]]$SoakReports,
    [Parameter(Mandatory)][string]$ExpectedExeSha256)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ActiveReleaseSource.psm1') -Force
$root=Split-Path -Parent $PSScriptRoot
$sha=Get-ActiveReleaseSource $root
if ($ExpectedExeSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'Trusted executable hash required.' }
$report=[ordered]@{schemaVersion=1;sourceSha=$sha;exeSha256=$ExpectedExeSha256;g6b='pending';g6c='pending';
    g6d='pending';g6e='pending';g6f='pending';g6g='blocked';soakSeconds=0;
    manualReviewRequired=$true;productionApproved=$false;failure=$null}
$code=3
function Read-Report([string]$Path) {
    $item=Get-Item -LiteralPath $Path
    if ($item.PSIsContainer -or $item.Length -lt 1 -or $item.Length -gt 1048576 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid qualification report file.' }
    $r=Get-Content -LiteralPath $item.FullName -Raw | ConvertFrom-Json
    if ($r.schemaVersion -ne 1 -or $r.sourceSha -cne $sha) { throw 'Report source or schema mismatch.' }
    return $r
}
function Require($condition,[string]$message) { if (-not $condition) { throw $message } }
function Same-Binary($r) { Require ($r.exeSha256 -ieq $ExpectedExeSha256) 'Executable hash mismatch.' }
try {
    $b=Read-Report $SyntheticReport
    Require ($b.status -ceq 'Passed' -and $b.branch -ceq 'feature/carthago-reliability-hardening' -and
        $b.expectedTotal -eq 392 -and $b.total -eq 392 -and $b.passed -eq 392 -and $b.failedOrSkipped -eq 0 -and
        @($b.suites).Count -eq 28 -and $b.testExitCode -eq 0 -and $b.buildExitCode -eq 0 -and
        $b.monitorBuildExitCode -eq 0 -and $b.monitorHelpExitCode -eq 0 -and $b.monitorInvalidCommandExitCode -eq 2 -and
        $b.processQualificationBuildExitCode -eq 0 -and $b.processQualificationExitCode -eq 0 -and $b.liveLabContractExitCode -eq 0 -and
        $b.deploymentContractPassed -eq $true -and $b.serviceLifecycleContractPassed -eq $true -and $b.serviceNegativeContractPassed -eq $true) 'Synthetic gate not passed.'
    $trxPath=Join-Path (Split-Path -Parent (Get-Item -LiteralPath $SyntheticReport).FullName) 'active-sensors.trx'
    Require ((Get-FileHash -LiteralPath $trxPath -Algorithm SHA256).Hash -ceq $b.trxSha256) 'TRX hash mismatch.'
    [xml]$trx=Get-Content -LiteralPath $trxPath -Raw
    $results=@($trx.SelectNodes("//*[local-name()='UnitTestResult']"))
    Require ($results.Count -eq 392 -and @($results | Where-Object {$_.GetAttribute('outcome') -cne 'Passed'}).Count -eq 0) 'TRX outcomes incomplete.'
    $matrix=@($b.suites | Where-Object {$_.name -ceq 'ActiveFindingReleaseMatrixTests'})
    Require ($matrix.Count -eq 1 -and $matrix[0].expected -eq 34 -and $matrix[0].total -eq 34 -and $matrix[0].passed -eq 34) 'Finding matrix not passed.'
    $report.g6b='passed_synthetic';$report.g6f='passed_synthetic_matrix'
    $required=@('GatewayMatch','GatewayMismatch','GatewayNoReply','GatewayContention','SnmpMatch','SnmpMismatch','SnmpTimeout')
    $seen=@{}
    foreach ($file in $PhysicalReports) {
        $r=Read-Report $file
        Require ($r.case -cin $required -and -not $seen.ContainsKey($r.case) -and
            $r.result -ceq 'expected_physical_outcome_confirmed' -and $r.productionEvidenceWritten -is [bool] -and -not $r.productionEvidenceWritten) 'Physical report incomplete or duplicate.'
        $seen[$r.case]=$true
    }
    Require ($seen.Count -eq $required.Count) 'Missing physical cases.'
    $report.g6c='passed_reported_physical_cases'
    $s=Read-Report $PositiveServiceReport;Same-Binary $s
    Require ($s.result -ceq 'qualified_for_observed_operational_scope' -and $s.firstRun -ceq 'start_observe_stop_confirmed' -and
        $s.restart -ceq 'new_session_responsive_scope_observed' -and $s.cleanup -ceq 'stopped_confirmed' -and
        $s.profiles -ge 1 -and $s.profiles -le 16 -and $s.firstResponsiveProfiles -eq $s.profiles -and
        $s.secondResponsiveProfiles -eq $s.profiles -and [Guid]$s.firstSessionId -ne [Guid]$s.secondSessionId) 'Positive SCM gate incomplete.'
    $reasons=@{}
    $attempts=@{}
    $lastNegative=[DateTimeOffset]::MinValue
    foreach ($file in $NegativeServiceReports) {
        $n=Read-Report $file;Same-Binary $n
        Require ($n.expectedReason -cin @('NoValidGrant','PinnedGrantMismatch','SnmpCredentialUnavailable') -and
            $n.result -ceq 'qualified_expected_startup_rejection' -and $n.rejection -ceq 'expected_pre_readiness_rejection_confirmed' -and
            $n.cleanup -ceq 'stopped_confirmed' -and [Guid]$n.attemptId -ne [Guid]::Empty -and -not $attempts.ContainsKey([string]$n.attemptId)) 'Negative SCM gate incomplete or duplicate.'
        $reasons[$n.expectedReason]=$true;$attempts[[string]$n.attemptId]=$true
        if ([DateTimeOffset]$n.finishedUtc -gt $lastNegative) { $lastNegative=[DateTimeOffset]$n.finishedUtc }
    }
    Require ($reasons.Count -eq 3 -and [DateTimeOffset]$s.startedUtc -gt $lastNegative) 'Missing negative categories or subsequent recovery run.'
    $report.g6d='passed_reported_scm_and_recovery'
    $windows=@(foreach ($file in $SoakReports) { $r=Read-Report $file;Same-Binary $r;$r })
    $end=[DateTimeOffset]::MinValue
    foreach ($w in ($windows | Sort-Object {[DateTimeOffset]$_.startedUtc})) {
        $start=[DateTimeOffset]$w.startedUtc;$finish=[DateTimeOffset]$w.finishedUtc
        Require ($w.result -ceq 'observed_coexistence_window_passed' -and $start -ge $end -and $finish -gt $start -and
            $w.requestedHours -ge 1 -and $w.requestedHours -le 23 -and $w.durationSeconds -ge 3600*$w.requestedHours -and
            $w.durationSeconds -le ($finish-$start).TotalSeconds+1 -and $w.sampleCount -ge 2 -and
            $w.activeCompletedDelta -gt 0 -and $w.passiveCapturedDelta -gt 0 -and
            $w.maxActiveWorkingSetMiB -le $w.limits.activeWorkingSetMiB -and $w.maxPassiveWorkingSetMiB -le $w.limits.passiveWorkingSetMiB -and
            $w.maxCombinedCpuPercent -le $w.limits.combinedCpuPercent -and $w.maxEvidenceMiB -le $w.limits.evidenceMiB) 'Soak window incomplete, overlapping or outside budget.'
        $end=$finish;$report.soakSeconds+=$w.durationSeconds
    }
    Require ($report.soakSeconds -ge 86400) 'At least 24 nonoverlapping observed hours required.'
    $report.g6e='passed_segmented_operational_soak'
    Assert-ActiveReleaseSource $root $sha
    # Even complete machine-readable evidence is not approval: deployment
    # provenance, packet overhead/loss, cross-account DPAPI and scope review
    # still need independent operator sign-off.
    $report.g6g='evidence_complete_manual_review_required'
    $code=0
} catch { $report.failure=$_.Exception.Message }
[pscustomobject]$report | ConvertTo-Json -Depth 5
exit $code
