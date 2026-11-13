# SPDX-License-Identifier: MIT
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('GatewayMatch','GatewayMismatch','GatewayNoReply','GatewayContention','SnmpMatch','SnmpMismatch','SnmpTimeout')][string]$Case,
    [Parameter(Mandatory)][string]$Adapter,[Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Target,[Parameter(Mandatory)][string]$Expected,
    [switch]$ConfirmAuthorizedPhysicalLab)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT' -or -not $ConfirmAuthorizedPhysicalLab) { throw 'Explicit Windows physical lab authorization required.' }
Import-Module (Join-Path $PSScriptRoot 'ActiveReleaseSource.psm1') -Force
$root=Split-Path -Parent $PSScriptRoot
$sha=Get-ActiveReleaseSource $root
$project=Join-Path $root 'Carthago.ActiveQualification/Carthago.ActiveQualification.csproj'
$sensor=if($Case.StartsWith('Gateway')){'gateway'}else{'snmp'}
$dir=Join-Path $root ('build-verify/active-physical/'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$report=[ordered]@{schemaVersion=1;sourceSha=$sha;case=$Case;sensor=$sensor;startedUtc=[DateTimeOffset]::UtcNow.ToString('o');
    result='incomplete_or_failed';outcome=$null;expectedMatch=$null;exitCode=$null;productionEvidenceWritten=$null}
$code=3
try {
    & dotnet build $project -c Release --nologo *> (Join-Path $dir 'build.log')
    if ($LASTEXITCODE -ne 0) { throw 'Physical harness build failed.' }
    # The harness itself asks for PROBE and reads credentials from the console.
    # Only its allowlisted JSON stdout is captured; no target or secret is recorded.
    $raw=@(& dotnet run --project $project -c Release --no-build --no-restore -- live $sensor --adapter $Adapter --source $Source --target $Target --expected $Expected)
    $report.exitCode=$LASTEXITCODE
    if ($raw.Count -ne 1) { throw 'Physical harness output not confirmed.' }
    $r=$raw[0] | ConvertFrom-Json
    if ($r.schemaVersion -ne 1 -or $r.mode -cne 'physical-lab' -or $r.sensor -cne $sensor -or
        $r.productionEvidenceWritten -isnot [bool] -or $r.productionEvidenceWritten) { throw 'Unexpected physical report.' }
    $ok=switch ($Case) {
        'GatewayMatch' { $report.exitCode -eq 0 -and $r.result -ceq 'Passed' -and $r.outcome -ceq 'BaselineMatch' -and $r.expectedMatch -eq $true }
        'GatewayMismatch' { $report.exitCode -eq 1 -and $r.result -ceq 'Failed' -and $r.outcome -ceq 'BaselineDifference' -and $r.expectedMatch -eq $false }
        'GatewayNoReply' { $report.exitCode -eq 3 -and $r.result -ceq 'Inconclusive' -and $r.outcome -ceq 'NoReply' }
        'GatewayContention' { $report.exitCode -eq 3 -and $r.result -ceq 'Inconclusive' -and $r.outcome -ceq 'CaptureReservationUnavailable' }
        'SnmpMatch' { $report.exitCode -eq 0 -and $r.result -ceq 'Passed' -and $r.outcome -ceq 'Observed' -and $r.expectedMatch -eq $true }
        'SnmpMismatch' { $report.exitCode -eq 1 -and $r.result -ceq 'Failed' -and $r.outcome -ceq 'Observed' -and $r.expectedMatch -eq $false }
        'SnmpTimeout' { $report.exitCode -eq 3 -and $r.result -ceq 'Inconclusive' -and $r.outcome -ceq 'TimedOut' }
    }
    $report.outcome=$r.outcome;$report.expectedMatch=$r.expectedMatch;$report.productionEvidenceWritten=$r.productionEvidenceWritten
    Assert-ActiveReleaseSource $root $sha
    if (-not $ok) { throw 'Expected physical outcome not established.' }
    $report.result='expected_physical_outcome_confirmed';$code=0
} catch { Write-Warning 'Physical qualification incomplete or failed; inspect local build log and lab conditions.' }
finally {
    $report.finishedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    $json=[pscustomobject]$report | ConvertTo-Json -Depth 4
    $json | Set-Content -LiteralPath (Join-Path $dir 'physical.json') -Encoding UTF8
    $json
}
exit $code
