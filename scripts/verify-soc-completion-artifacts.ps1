# SPDX-License-Identifier: MIT
# Read-only check of a saved, successful SOC completion bundle.
# Windows PowerShell 5.1 / PowerShell 7; no git, build, dotnet, capture or writes.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$RunDirectory)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Require([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "SOC completion bundle rejected: $Message" }
}

function Get-SocOriginal([string]$Directory, [string]$Name) {
    $file = Join-Path $Directory $Name
    $item = Get-Item -LiteralPath $file -ErrorAction Stop
    Require (-not $item.PSIsContainer) "missing regular file: $Name"
    Require (-not [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) "reparse point rejected: $Name"
    return $item.FullName
}

$dirItem = Get-Item -LiteralPath $RunDirectory -ErrorAction Stop
Require ($dirItem.PSIsContainer) 'run directory must exist'
Require (-not [bool]($dirItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'run directory reparse point rejected'

$completionPath = Get-SocOriginal $dirItem.FullName 'completion.json'
Require ((Get-Item -LiteralPath $completionPath).Length -le 1048576) 'completion.json larger than 1 MiB'
$record = Get-Content -LiteralPath $completionPath -Raw -Encoding UTF8 | ConvertFrom-Json
Require ($null -ne $record) 'missing completion JSON'
Require ($record.schemaVersion -eq 1 -and
         $record.purpose -ceq 'soc-workspace-final-provenance-v1' -and
         $record.status -ceq 'SyntheticSocPassed') 'completion status or schema mismatch'
Require ($record.branch -ceq 'feature/carthago-reliability-hardening' -and
         $record.postRunBranch -ceq $record.branch) 'branch mismatch'
Require ($record.evidenceAdmitted -ceq $false -and
         $record.fieldAccuracyQualified -ceq $false -and
         $record.manualWpfValidated -ceq $false) 'unearned acceptance claimed'

$ids = @($record.sourceSha,$record.preRunSha,$record.postRunSha,
         $record.preRunOriginSha,$record.postRunOriginSha)
foreach ($id in $ids) {
    Require ($id -is [string] -and $id -cmatch '^[a-f0-9]{40}$') 'invalid source SHA'
    Require ($id -ceq $ids[0]) 'pre-run, post-run or origin SHA mismatch'
}

$sourcePath = Get-SocOriginal $dirItem.FullName 'source-sha.txt'
$sourceFileHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
Require ($sourceFileHash -ceq $record.sourceShaFileSha256) 'source file SHA-256 mismatch'
Require ((Get-Content -LiteralPath $sourcePath -Raw).Trim() -ceq $record.sourceSha) 'original source file content mismatch'

Import-Module (Join-Path $PSScriptRoot 'SocWorkspaceCompletion.psm1') -Force
$trxPath = Get-SocOriginal $dirItem.FullName 'soc-workspace-tests.trx'
$trx = Get-SocWorkspaceTrxEvidence -Path $trxPath
Require ($trx['trxSha256'] -ceq $record.trxSha256) 'TRX original SHA-256 mismatch'
Require ($trx['trxRunId'] -ceq $record.trxRunId) 'TRX run GUID mismatch'
Require (([DateTimeOffset]::Parse($trx['trxStartedUtc'])).ToUniversalTime() -eq
         ([DateTimeOffset]::Parse($record.trxStartedUtc)).ToUniversalTime()) 'TRX start-time mismatch'
Require (([DateTimeOffset]::Parse($trx['trxFinishedUtc'])).ToUniversalTime() -eq
         ([DateTimeOffset]::Parse($record.trxFinishedUtc)).ToUniversalTime()) 'TRX finish-time mismatch'

foreach ($key in @('total','executed','passed','failed')) {
    Require ([int]$trx['testResults'][$key] -eq [int]$record.testResults.$key) "TRX $key counter mismatch"
}
foreach ($key in @('NetworkInvestigation','IncidentTimeline','IncidentDetectionLinkVm')) {
    Require ([int]$trx['requiredGroups'][$key] -eq [int]$record.requiredGroups.$key) "TRX $key group mismatch"
}
Require ([int]$trx['methodScopedCases'] -eq [int]$record.methodScopedCases) 'TRX method-scoped result count mismatch'

$expectedStages = @('sdk-version','restore','build-release','soc-tests')
Require (@($record.stages.PSObject.Properties).Count -eq 4) 'unexpected stage count'
$logResults = [ordered]@{}
foreach ($stage in $expectedStages) {
    $entryProperty = $record.stages.PSObject.Properties[$stage]
    Require ($null -ne $entryProperty) "stage missing: $stage"
    $entry = $entryProperty.Value
    $name = $stage + '.log'
    Require ($entry.exitCode -is [int] -and $entry.exitCode -eq 0) "stage exit not zero: $stage"
    Require ($entry.logFileName -ceq $name) "stage filename mismatch: $stage"
    Require ($entry.logSha256 -is [string] -and $entry.logSha256 -cmatch '^[a-f0-9]{64}$') "invalid log digest: $stage"
    $logPath = Get-SocOriginal $dirItem.FullName $name
    $observed = (Get-FileHash -LiteralPath $logPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Require ($observed -ceq $entry.logSha256) "original log SHA-256 mismatch: $stage"
    $logResults[$stage] = 'sha256-matched'
}
$start = [DateTimeOffset]::Parse([string]$record.startedUtc)
$end = [DateTimeOffset]::Parse([string]$record.finishedUtc)
$trxStart = [DateTimeOffset]::Parse([string]$record.trxStartedUtc)
$trxEnd = [DateTimeOffset]::Parse([string]$record.trxFinishedUtc)
Require ($start -le $trxStart -and $trxStart -le $trxEnd -and $trxEnd -le $end) 'run timeline inconsistent'

[ordered]@{
    scope = 'saved-SOC-provenance-artifact-hash-check'
    status = 'all-original-artifact-hashes-matched'
    sourceSha = $record.sourceSha
    trxRunId = $record.trxRunId
    trxSha256 = $record.trxSha256
    total = $trx['testResults']['total']
    passed = $trx['testResults']['passed']
    methodScopedCases = $trx['methodScopedCases']
    completionSha256 = (Get-FileHash -LiteralPath $completionPath -Algorithm SHA256).Hash.ToLowerInvariant()
    logs = $logResults
    fieldQualified = $false
    evidenceAdmitted = $false
    verifierTestsExecuted = 0
} | ConvertTo-Json -Depth 6
