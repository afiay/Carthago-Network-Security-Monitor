# SPDX-License-Identifier: MIT
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Get-ActiveReleaseSource([string]$Root) {
    $branch=(& git -C $Root branch --show-current).Trim()
    if ($LASTEXITCODE -ne 0 -or $branch -cne 'feature/carthago-reliability-hardening') { throw 'Qualification branch mismatch.' }
    $sha=(& git -C $Root rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $sha -notmatch '^[0-9a-f]{40}$') { throw 'Source SHA unavailable.' }
    $dirty=@(& git -C $Root status --porcelain --untracked-files=all)
    if ($LASTEXITCODE -ne 0 -or $dirty.Count -ne 0) { throw 'Clean qualification worktree required.' }
    return $sha
}
function Assert-ActiveReleaseSource([string]$Root,[string]$Expected) {
    if ((Get-ActiveReleaseSource $Root) -cne $Expected) { throw 'Qualification source changed.' }
}
# Pure report contract shared by physical runner and final evidence gate.
function Test-ActivePhysicalOutcome([string]$Case,$ExitCode,[string]$LabResult,[string]$Outcome,$ExpectedMatch) {
    if ($ExitCode -isnot [int] -and $ExitCode -isnot [long]) { return $false }
    switch -CaseSensitive ($Case) {
        'GatewayMatch' { return ($ExitCode -eq 0 -and $LabResult -ceq 'Passed' -and $Outcome -ceq 'BaselineMatch' -and $ExpectedMatch -is [bool] -and $ExpectedMatch) }
        'GatewayMismatch' { return ($ExitCode -eq 1 -and $LabResult -ceq 'Failed' -and $Outcome -ceq 'BaselineDifference' -and $ExpectedMatch -is [bool] -and -not $ExpectedMatch) }
        'GatewayNoReply' { return ($ExitCode -eq 3 -and $LabResult -ceq 'Inconclusive' -and $Outcome -ceq 'NoReply' -and $null -eq $ExpectedMatch) }
        'GatewayContention' { return ($ExitCode -eq 3 -and $LabResult -ceq 'Inconclusive' -and $Outcome -ceq 'CaptureReservationUnavailable' -and $null -eq $ExpectedMatch) }
        'SnmpMatch' { return ($ExitCode -eq 0 -and $LabResult -ceq 'Passed' -and $Outcome -ceq 'Observed' -and $ExpectedMatch -is [bool] -and $ExpectedMatch) }
        'SnmpMismatch' { return ($ExitCode -eq 1 -and $LabResult -ceq 'Failed' -and $Outcome -ceq 'Observed' -and $ExpectedMatch -is [bool] -and -not $ExpectedMatch) }
        'SnmpTimeout' { return ($ExitCode -eq 3 -and $LabResult -ceq 'Inconclusive' -and $Outcome -ceq 'TimedOut' -and $null -eq $ExpectedMatch) }
        default { return $false }
    }
}
Export-ModuleMember -Function Get-ActiveReleaseSource,Assert-ActiveReleaseSource,Test-ActivePhysicalOutcome
