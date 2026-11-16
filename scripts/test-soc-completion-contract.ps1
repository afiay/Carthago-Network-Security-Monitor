# SPDX-License-Identifier: MIT
# Offline contract tests for the future SOC completion report.
# Pure temporary TRX/JSON fixtures: never runs dotnet, git, capture or the SOC verifier.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SocWorkspaceCompletion.psm1') -Force

# Parse the production verifier without invoking it. This catches syntax
# errors on Windows PowerShell 5.1 and protects final-check-before-publish order.
foreach ($fileName in @('SocWorkspaceCompletion.psm1','verify-soc-workspace.ps1','test-soc-completion-contract.ps1')) {
    $sourceFile = Join-Path $PSScriptRoot $fileName
    $tokens = $null
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $sourceFile, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) { throw "PowerShell source parse failed: $fileName" }
}
$verificationSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'verify-soc-workspace.ps1') -Raw
$preCheckPos = $verificationSource.IndexOf('$preRun = Get-SocCheckout')
$postCheckPos = $verificationSource.IndexOf('$postRun = Get-SocCheckout')
$publishPos = $verificationSource.IndexOf('Publish-SocWorkspaceCompletionRecord -Record')
if ($preCheckPos -lt 0 -or $postCheckPos -le $preCheckPos -or $publishPos -le $postCheckPos) {
    throw 'Verifier must publish completion only after the final source checkout check.'
}

$asserts = 0
function Require([bool]$condition, [string]$message) {
    $script:asserts++
    if (-not $condition) { throw "SOC completion contract assertion failed: $message" }
}
function Reject([scriptblock]$action, [string]$message) {
    $rejected = $false
    try { $null = & $action } catch { $rejected = $true }
    Require $rejected $message
}

$dir = Join-Path ([IO.Path]::GetTempPath()) ('carthago-soc-completion-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $dir -ErrorAction Stop
try {
    $trxPath = Join-Path $dir 'soc-workspace-tests.trx'
    # Use a non-UTC offset to verify authentic Windows TRX time handling.
    $fixture = @'
<TestRun id="d0741122-ea72-4b2d-889a-5a1af63f0001" xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
  <Times start="2026-11-16T13:00:00+01:00" finish="2026-11-16T13:00:03+01:00" />
  <TestDefinitions>
    <UnitTest id="a0000000-0000-4000-8000-000000000001" name="NetworkInvestigationTests.Positive"><TestMethod className="Carthago.Tests.NetworkInvestigationTests" name="Positive"/></UnitTest>
    <UnitTest id="a0000000-0000-4000-8000-000000000002" name="IncidentTimelineTests.Positive"><TestMethod className="Carthago.Tests.IncidentTimelineTests" name="Positive"/></UnitTest>
    <UnitTest id="a0000000-0000-4000-8000-000000000003" name="IncidentDetectionLinkVmTests.Positive"><TestMethod className="Carthago.Tests.IncidentDetectionLinkVmTests" name="Positive"/></UnitTest>
  </TestDefinitions>
  <Results>
    <UnitTestResult testId="a0000000-0000-4000-8000-000000000001" executionId="b0000000-0000-4000-8000-000000000001" testName="NetworkInvestigationTests.Positive" outcome="Passed"/>
    <UnitTestResult testId="a0000000-0000-4000-8000-000000000002" executionId="b0000000-0000-4000-8000-000000000002" testName="IncidentTimelineTests.Positive" outcome="Passed"/>
    <UnitTestResult testId="a0000000-0000-4000-8000-000000000003" executionId="b0000000-0000-4000-8000-000000000003" testName="IncidentDetectionLinkVmTests.Positive" outcome="Passed"/>
  </Results>
  <ResultSummary outcome="Completed"><Counters total="3" executed="3" passed="3" failed="0"/></ResultSummary>
</TestRun>
'@
    [IO.File]::WriteAllText($trxPath, $fixture, [Text.UTF8Encoding]::new($false))
    $e = Get-SocWorkspaceTrxEvidence -Path $trxPath
    Require ($e['testResults']['total'] -eq 3 -and $e['testResults']['passed'] -eq 3) 'positive TRX counters'
    Require ($e['trxStartedUtc'] -like '2026-11-16T12:00:00*') 'offset-aware time normalized UTC'
    Require ($e['trxSha256'] -cmatch '^[a-f0-9]{64}$') 'TRX SHA256'
    Require ($e['requiredGroups']['NetworkInvestigation'] -eq 1 -and
             $e['requiredGroups']['IncidentTimeline'] -eq 1 -and
             $e['requiredGroups']['IncidentDetectionLinkVm'] -eq 1) 'group coverage'

    $stages = [ordered]@{}
    foreach ($name in @('sdk-version','restore','build-release','soc-tests')) {
        $stages[$name] = [ordered]@{
            exitCode = 0
            logFileName = $name + '.log'
            logSha256 = ('b' * 64)
        }
    }
    $sha = 'a' * 40
    $record = [ordered]@{
        schemaVersion = 1
        purpose = 'soc-workspace-final-provenance-v1'
        status = 'SyntheticSocPassed'
        branch = 'feature/carthago-reliability-hardening'
        postRunBranch = 'feature/carthago-reliability-hardening'
        sourceSha = $sha
        preRunSha = $sha
        postRunSha = $sha
        preRunOriginSha = $sha
        postRunOriginSha = $sha
        sourceShaFileSha256 = ('c' * 64)
        startedUtc = '2026-11-16T11:59:59.0000000Z'
        finishedUtc = '2026-11-16T12:00:04.0000000Z'
        trxRunId = $e['trxRunId']
        trxSha256 = $e['trxSha256']
        trxStartedUtc = $e['trxStartedUtc']
        trxFinishedUtc = $e['trxFinishedUtc']
        testResults = $e['testResults']
        requiredGroups = $e['requiredGroups']
        stages = $stages
        evidenceAdmitted = $false
        fieldAccuracyQualified = $false
        manualWpfValidated = $false
    }
    Assert-SocWorkspaceCompletionRecord -Record $record
    Require $true 'valid positive record accepted'

    $output = Join-Path $dir 'completion.json'
    Publish-SocWorkspaceCompletionRecord -Record $record -Path $output
    $written = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
    Require ($written.sourceSha -ceq $sha -and $written.postRunSha -ceq $sha -and
             $written.trxSha256 -ceq $e['trxSha256'] -and $written.status -ceq 'SyntheticSocPassed') 'published JSON roundtrip'
    Reject { Publish-SocWorkspaceCompletionRecord -Record $record -Path $output } 'reject overwrite of completed run'

    $record['postRunSha'] = 'd' * 40
    Reject { Assert-SocWorkspaceCompletionRecord -Record $record } 'reject changing checkout SHA'
    $record['postRunSha'] = $sha

    $record['postRunOriginSha'] = 'e' * 40
    Reject { Assert-SocWorkspaceCompletionRecord -Record $record } 'reject changed origin tracking SHA'
    $record['postRunOriginSha'] = $sha

    $record['postRunBranch'] = 'main'
    Reject { Assert-SocWorkspaceCompletionRecord -Record $record } 'reject unexpected branch'
    $record['postRunBranch'] = $record['branch']

    $stages['soc-tests']['exitCode'] = 1
    Reject { Assert-SocWorkspaceCompletionRecord -Record $record } 'reject failed stage'
    $stages['soc-tests']['exitCode'] = 0

    $stages['soc-tests']['logSha256'] = 'invalid-hash'
    Reject { Assert-SocWorkspaceCompletionRecord -Record $record } 'reject invalid stage hash'
    $stages['soc-tests']['logSha256'] = 'b' * 64

    $stages.Remove('soc-tests')
    Reject { Assert-SocWorkspaceCompletionRecord -Record $record } 'reject missing stage'
    $stages['soc-tests'] = [ordered]@{exitCode=0;logFileName='soc-tests.log';logSha256=('b' * 64)}

    $record['testResults']['failed'] = 1
    Reject { Assert-SocWorkspaceCompletionRecord -Record $record } 'reject failing results'
    $record['testResults']['failed'] = 0

    $record['manualWpfValidated'] = $true
    Reject { Assert-SocWorkspaceCompletionRecord -Record $record } 'reject inferred visual validation'
    $record['manualWpfValidated'] = $false

    $record['status'] = 'Failed'
    Reject { Assert-SocWorkspaceCompletionRecord -Record $record } 'reject incomplete report'
    $record['status'] = 'SyntheticSocPassed'

    $record['trxRunId'] = 'not-a-guid'
    Reject { Assert-SocWorkspaceCompletionRecord -Record $record } 'reject invalid TRX identity'
    $record['trxRunId'] = $e['trxRunId']

    [IO.File]::WriteAllText($trxPath, $fixture.Replace('outcome="Passed"/>', 'outcome="Failed"/>'), [Text.UTF8Encoding]::new($false))
    Reject { Get-SocWorkspaceTrxEvidence -Path $trxPath } 'reject failed TRX case'

    [IO.File]::WriteAllText($trxPath, $fixture.Replace('executed="3"', 'executed="2"'), [Text.UTF8Encoding]::new($false))
    Reject { Get-SocWorkspaceTrxEvidence -Path $trxPath } 'reject skipped/incomplete TRX'

    [IO.File]::WriteAllText($trxPath, $fixture.Replace('Carthago.Tests.NetworkInvestigationTests', 'Carthago.Tests.NetworkInvestigationIncidentTimelineTests'), [Text.UTF8Encoding]::new($false))
    Reject { Get-SocWorkspaceTrxEvidence -Path $trxPath } 'reject overlapping test group ownership'

    [IO.File]::WriteAllText($trxPath, $fixture.Replace('IncidentDetectionLinkVmTests', 'UnrelatedGroupTests'), [Text.UTF8Encoding]::new($false))
    Reject { Get-SocWorkspaceTrxEvidence -Path $trxPath } 'reject missing required test group'

    [IO.File]::WriteAllText($trxPath, '<!DOCTYPE foo [<!ENTITY x "bad">]>' + $fixture, [Text.UTF8Encoding]::new($false))
    Reject { Get-SocWorkspaceTrxEvidence -Path $trxPath } 'reject DTD external entities'

    Write-Output ("PASS SOC offline completion contract ({0} assertions, no detector tests or captures)" -f $asserts)
} finally {
    if (Test-Path -LiteralPath $dir -PathType Container) {
        Remove-Item -LiteralPath $dir -Recurse -Force
    }
}
