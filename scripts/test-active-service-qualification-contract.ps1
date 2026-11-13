# SPDX-License-Identifier: MIT
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ActiveServiceQualification.psm1') -Force
function Require($condition) { if (-not $condition) { throw 'Qualification contract failed.' } }
function Reject([scriptblock]$action) { $rejected=$false; try { & $action | Out-Null } catch { $rejected=$true }; Require $rejected }
$now=[DateTimeOffset]::Parse('2026-11-13T12:00:00Z')
$start=$now.AddMinutes(-1)
function Sample {
    [pscustomobject]@{schemaVersion=1;sessionId='02702701-1234-4321-9999-000000000001';processId=123;
        processStartedUtc=$start.ToString('o');sampleUtc=$now.ToString('o');schedulerOwned=$true;
        profiles=2;blockedProfiles=0;pendingProfiles=0;profilesWithFailures=0;completedProbes=2;
        responsiveProbes=2;deferredChecks=0;storageFailures=0;lastResponsiveUtc=$now.ToString('o');
        earliestGrantExpiryUtc=$now.AddHours(1).ToString('o');latestGrantExpiryUtc=$now.AddHours(2).ToString('o');
        assessment='ResponsiveObserved'}
}
$valid=ConvertTo-ActiveHealthSample (Sample) 123 $start $now
Require (Test-ActiveObservedScope $valid 2)
Reject { ConvertTo-ActiveHealthSample (Sample) 124 $start $now }
Reject { ConvertTo-ActiveHealthSample (Sample) 123 $start $now.AddSeconds(31) }
Reject { ConvertTo-ActiveHealthSample (Sample) 123 $start.AddSeconds(-3) $now }
$x=Sample; $x.responsiveProbes=3; Reject { ConvertTo-ActiveHealthSample $x 123 $start $now }
$x=Sample; $x.schedulerOwned='true'; Reject { ConvertTo-ActiveHealthSample $x 123 $start $now }
$x=Sample; $x | Add-Member -NotePropertyName secret -NotePropertyValue 'do-not-relay'; Reject { ConvertTo-ActiveHealthSample $x 123 $start $now }
$x=Sample; $x.storageFailures=1; $x.assessment='Degraded'
Require (-not (Test-ActiveObservedScope (ConvertTo-ActiveHealthSample $x 123 $start $now) 2))
$x=Sample; $x.pendingProfiles=1; Require (-not (Test-ActiveObservedScope $x 2))
$x=Sample; $x.deferredChecks=1; Require (-not (Test-ActiveObservedScope $x 2))
$x=Sample; $x.completedProbes=3; $x.responsiveProbes=3
Assert-ActiveHealthProgress $valid (ConvertTo-ActiveHealthSample $x 123 $start $now) 2
$x=Sample; $x.completedProbes=1; $x.responsiveProbes=1
Reject { Assert-ActiveHealthProgress $valid (ConvertTo-ActiveHealthSample $x 123 $start $now) 2 }
$x=Sample; $x.sessionId=[Guid]::NewGuid().ToString('D')
Reject { Assert-ActiveHealthProgress $valid (ConvertTo-ActiveHealthSample $x 123 $start $now) 2 }
$x=Sample; $x.sampleUtc=$now.UtcDateTime
Require ((ConvertTo-ActiveHealthSample $x 123 $start $now).sampleUtc -ceq $valid.sampleUtc)
$x=Sample; $x.sampleUtc='2026-11-13T12:00:00'; Reject { ConvertTo-ActiveHealthSample $x 123 $start $now }
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('carthago-health-contract-'+[Guid]::NewGuid().ToString('N')+'.json')
try {
    [IO.File]::WriteAllText($fixture,((Sample) | ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    Require (Test-ActiveObservedScope (ConvertTo-ActiveHealthSample (Read-ActiveHealthFile $fixture) 123 $start $now) 2)
    [IO.File]::WriteAllBytes($fixture,(New-Object byte[] 16385))
    Reject { Read-ActiveHealthFile $fixture }
} finally { if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Force } }
Write-Output 'PASS AS-Q07G5E offline lifecycle qualification contract'
