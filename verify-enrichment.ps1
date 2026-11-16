# SPDX-License-Identifier: MIT
# Focused Windows enrichment qualification; no capture or GitHub Actions.
[CmdletBinding()]
param([switch]$LiveOutput, [switch]$SelfTest)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
function Assert-ToolSource([string]$Path) {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if (@($errors).Count -gt 0) { throw "PowerShell parser rejected ${Path}: $($errors[0].Message)" }
    $functions = @($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] })
    $duplicates = @($functions | Group-Object Name | Where-Object { $_.Count -gt 1 })
    if ($duplicates.Count -gt 0) { throw "Duplicate top-level function in ${Path}: $($duplicates[0].Name)" }
}
function Assert-QualificationToolSources {
    foreach ($name in @('verify-enrichment.ps1','measure-enrichment-runtime.ps1','analyze-enrichment-runtime.ps1')) {
        Assert-ToolSource (Join-Path $root $name)
    }
}
function Read-QualificationTrx([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'Missing TRX evidence' }
    [xml]$xml = Get-Content -LiteralPath $Path -Raw
    $summary = $xml.SelectSingleNode("/*[local-name()='TestRun']/*[local-name()='ResultSummary']")
    if ($null -eq $summary) { throw 'Missing TRX result summary' }
    $c = $summary.SelectSingleNode("*[local-name()='Counters']")
    if ($null -eq $c) { throw 'Missing TRX counters' }
    $values = [ordered]@{}
    foreach ($name in @('total','executed','passed','failed','notExecuted','error','timeout','aborted')) {
        $n = 0L
        if (-not [long]::TryParse($c.GetAttribute($name), [ref]$n) -or $n -lt 0) {
            throw "Invalid TRX counter: $name"
        }
        $values[$name] = $n
    }
    $values['outcome'] = $summary.GetAttribute('outcome')
    $values['qualified'] = ($values.total -gt 0 -and $values.total -eq $values.executed -and
        $values.executed -eq $values.passed -and $values.failed -eq 0 -and
        $values.notExecuted -eq 0 -and $values.error -eq 0 -and
        $values.timeout -eq 0 -and $values.aborted -eq 0 -and $values.outcome -eq 'Completed')
    return [pscustomobject]$values
}
if ($SelfTest) {
    Assert-QualificationToolSources
    $sourceFixture = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N') + '.ps1')
    try {
        foreach ($case in @(
            @{ source='function Test-One { 1 }'; rejected=$false },
            @{ source='function Test-One {'; rejected=$true },
            @{ source='function Test-One { 1 }; function test-one { 2 }'; rejected=$true }
        )) {
            Set-Content -LiteralPath $sourceFixture -Value $case.source -Encoding UTF8
            $rejected = $false
            try { Assert-ToolSource $sourceFixture } catch { $rejected = $true }
            if ($rejected -ne $case.rejected) { throw 'Tool source integrity fixture failed' }
        }
    } finally { Remove-Item -LiteralPath $sourceFixture -Force -ErrorAction SilentlyContinue }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N') + '.trx')
    try {
        foreach ($case in @(
            @{ total=2; executed=2; passed=2; failed=0; notExecuted=0; expected=$true },
            @{ total=0; executed=0; passed=0; failed=0; notExecuted=0; expected=$false },
            @{ total=2; executed=1; passed=1; failed=0; notExecuted=1; expected=$false },
            @{ total=2; executed=2; passed=1; failed=1; notExecuted=0; expected=$false }
        )) {
            $fixture = '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"><ResultSummary outcome="Completed"><Counters total="{0}" executed="{1}" passed="{2}" failed="{3}" notExecuted="{4}" error="0" timeout="0" aborted="0"/></ResultSummary></TestRun>' -f $case.total,$case.executed,$case.passed,$case.failed,$case.notExecuted
            Set-Content -LiteralPath $tmp -Value $fixture -Encoding UTF8
            if ((Read-QualificationTrx $tmp).qualified -ne $case.expected) { throw 'TRX qualification fixture failed' }
        }
        Remove-Item -LiteralPath $tmp
        $rejected = $false
        try { Read-QualificationTrx $tmp | Out-Null } catch { $rejected = $true }
        if (-not $rejected) { throw 'Missing evidence was accepted' }
        Write-Host 'PASS: five TRX evidence fixtures and three tool source integrity fixtures'
    } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    return
}
Push-Location $root
try {
    $head = (& git rev-parse HEAD)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot identify repository HEAD' }
    $dirty = @(& git status --porcelain --untracked-files=no)
    if ($LASTEXITCODE -ne 0 -or $dirty.Count -ne 0) { throw 'Tracked working tree must be clean' }
    $runId = (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '-' + [Guid]::NewGuid().ToString('N')
    $dir = Join-Path $root ('build-verify/enrichment/' + $runId)
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $report = [ordered]@{ head=$head; startedUtc=[DateTime]::UtcNow.ToString('o'); build='not-run'; toolSourceIntegrity='not-run';
        groups=@(); runtime='not-run'; visual='not-run'; performance='not-run'; qualified=$false }
    function Invoke-LocalDotnet([string]$Name, [string[]]$Arguments) {
        $log = Join-Path $dir ($Name + '.log')
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            if ($LiveOutput) { & dotnet @Arguments *>&1 | Tee-Object -FilePath $log | Out-Host }
            else { & dotnet @Arguments *> $log }
            return $LASTEXITCODE
        } finally { $ErrorActionPreference = $previous }
    }
    try {
        try { Assert-QualificationToolSources; $report.toolSourceIntegrity = 'passed' }
        catch { $report.toolSourceIntegrity = 'failed'; throw }
        $project = 'Carthago.Tests/Carthago.Tests.csproj'
        $buildExit = Invoke-LocalDotnet 'build' @('build',$project,'-c','Release','--nologo')
        $report.build = if ($buildExit -eq 0) { 'passed' } else { 'failed' }
        if ($buildExit -ne 0) { throw "Release build failed: $buildExit" }
        $groups = [ordered]@{
            enrichment = @('EndpointIpEnrichmentTests','RuntimeEnrichmentRegressionTests','EnrichmentEvaluationGuardTests','EnrichmentProviderHealthTests','VpnInferenceEnrichmentTests','ProcessAttributionEnrichmentTests','CaptureInterfaceEnrichmentTests','DnsConnectionEnrichmentTests','DnsAddressEnrichmentTests','TlsIdentityEnrichmentTests','CarthagoEnrichmentExportTests','EnrichmentCoverageHealthTests','EnrichmentHealthPresentationTests','EnrichmentStorageHealthTests','EnrichmentWorkerHealthTests')
            asset = @('ObservedAssetRegistryTests','ApprovedAssetRegistryTests','AssetBehaviorComparisonTests','AssetHistoryCoveragePresentationTests','AssetHistoryStoreTests','AssetInventoryNoiseRegressionTests','ExternalCommunicationTests','NetworkInvestigationDnsQuerySearchTests')
        }
        foreach ($group in $groups.Keys) {
            $filter = ($groups[$group] | ForEach-Object { 'FullyQualifiedName~' + $_ }) -join '|'
            $trx = $group + '.trx'
            $exitCode = Invoke-LocalDotnet $group @('test',$project,'-c','Release','--no-build','--no-restore','--filter',$filter,'--logger',('trx;LogFileName=' + $trx),'--results-directory',$dir)
            $entry = [ordered]@{ name=$group; filter=$filter; exitCode=$exitCode; counters=$null; qualified=$false; diagnostic=$null }
            try {
                $entry.counters = Read-QualificationTrx (Join-Path $dir $trx)
                $entry.qualified = ($exitCode -eq 0 -and $entry.counters.qualified)
            } catch { $entry.diagnostic = $_.Exception.Message }
            $report.groups += [pscustomobject]$entry
        }
        $endHead = (& git rev-parse HEAD)
        $headExit = $LASTEXITCODE
        $endDirty = @(& git status --porcelain --untracked-files=no)
        $report.sourceUnchanged = ($headExit -eq 0 -and $LASTEXITCODE -eq 0 -and $endHead -eq $head -and $endDirty.Count -eq 0)
        $report.qualified = ($report.sourceUnchanged -and $report.groups.Count -eq $groups.Count -and
            @($report.groups | Where-Object { -not $_.qualified }).Count -eq 0)
    } finally {
        $report.finishedUtc = [DateTime]::UtcNow.ToString('o')
        $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $dir 'qualification.json') -Encoding UTF8
        Write-Host "Evidence: $dir"
    }
    if (-not $report.qualified) { exit 1 }
} finally { Pop-Location }
