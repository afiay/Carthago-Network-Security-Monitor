# SPDX-License-Identifier: MIT
# Local, no SCM mutations or packet capture. Run on Windows PowerShell/pwsh.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
foreach ($name in @('MonitorServiceQualification.psm1','test-monitor-service-preflight.ps1','verify-monitor-service.ps1')) {
    $tokens=$null; $errors=$null
    $null=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name),[ref]$tokens,[ref]$errors)
    if (@($errors).Count -ne 0) { throw "PowerShell parse errors in $name" }
}
Import-Module (Join-Path $PSScriptRoot 'MonitorServiceQualification.psm1') -Force
$dir=Join-Path ([IO.Path]::GetTempPath()) ('carthago-monitor-contract-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $dir
try {
    $path=Join-Path $dir 'journal.jsonl'
    $now=[DateTimeOffset]::UtcNow.AddSeconds(-2)
    $start=$now.AddSeconds(-2)
    $row=[ordered]@{eventId=[Guid]::NewGuid().ToString('N');timestampUtc=$now.UtcDateTime.ToString('o');deliveryStatus='Persisted'}
    $line=($row | ConvertTo-Json -Compress)+[Environment]::NewLine
    $utf8=New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($path,$line,$utf8)
    if ((Get-JournalEvidence $path 0 $start) -ne 'appended_persisted_records_observed') { throw 'Valid append rejected.' }
    $baseline=(Get-Item -LiteralPath $path).Length
    if ((Get-JournalEvidence $path $baseline $start) -ne 'no_new_records') { throw 'No append misclassified.' }
    if ((Get-JournalEvidence $path ($baseline+1) $start) -ne 'journal_shrank') { throw 'Shrink missed.' }
    if ((Get-JournalEvidence $path 1 $start) -ne 'baseline_not_record_boundary') { throw 'Partial baseline missed.' }
    [IO.File]::AppendAllText($path,$line,$utf8)
    if ((Get-JournalEvidence $path 0 $start) -ne 'invalid_record') { throw 'Duplicate ID missed.' }
    [IO.File]::WriteAllText($path,'{"eventId":"incomplete"}',$utf8)
    if ((Get-JournalEvidence $path 0 $start) -ne 'incomplete_record') { throw 'Partial record missed.' }
    [IO.File]::WriteAllText($path,$line,$utf8)
    if ((Get-JournalEvidence $path 0 $now.AddSeconds(1)) -ne 'invalid_record') { throw 'Out-of-window timestamp missed.' }
    Write-Output 'Monitor qualification script contract PASS (parser + synthetic journal only; SCM not tested).'
} finally { Remove-Item -LiteralPath $dir -Recurse -Force }
