# SPDX-License-Identifier: MIT
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ActiveServiceNegativeQualification.psm1') -Force
function Reject([scriptblock]$a) { $rejected=$false; try { & $a | Out-Null } catch { $rejected=$true }; if (-not $rejected) { throw 'Expected rejection.' } }
$attempt=[DateTimeOffset]::Parse('2026-11-13T12:00:00Z')
$now=$attempt.AddSeconds(3)
$hash='A'*64
function Record { [pscustomobject]@{schemaVersion=1;attemptId=[Guid]::NewGuid().ToString('D');processId=123;
    processStartedUtc=$attempt.AddSeconds(1).ToString('o');rejectedUtc=$attempt.AddSeconds(2).ToString('o');
    configSha256=$hash;reason='PinnedGrantMismatch';readinessPublished=$false} }
Assert-ActiveRejectionRecord (Record) 'PinnedGrantMismatch' $hash $attempt $now
Reject { Assert-ActiveRejectionRecord (Record) 'NoValidGrant' $hash $attempt $now }
Reject { Assert-ActiveRejectionRecord (Record) 'PinnedGrantMismatch' ('B'*64) $attempt $now }
Reject { Assert-ActiveRejectionRecord (Record) 'PinnedGrantMismatch' $hash $attempt.AddSeconds(2) $now }
$x=Record;$x.readinessPublished=$true;Reject { Assert-ActiveRejectionRecord $x 'PinnedGrantMismatch' $hash $attempt $now }
$x=Record;$x | Add-Member -NotePropertyName secret -NotePropertyValue 'not-allowed';Reject { Assert-ActiveRejectionRecord $x 'PinnedGrantMismatch' $hash $attempt $now }
Write-Output 'PASS AS-Q07G5F3 offline negative SCM contract'
