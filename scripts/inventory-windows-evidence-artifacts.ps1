# SPDX-License-Identifier: MIT
# Read-only inventory of original Windows qualification artifacts.
# This script never executes tests or admits results to the exact-ID manifest.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$EvidenceRoot,
    [ValidateRange(1, 50000)]
    [int]$MaximumFiles = 10000,
    [switch]$IncludeTestNames
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-TrxMetadata([IO.FileInfo]$file, [bool]$includeNames) {
    if ($file.Length -eq 0 -or $file.Length -gt 16777216) {
        return [pscustomobject]@{ status = 'rejected-size'; reason = 'TRX size outside 1..16777216 bytes' }
    }
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 16777216
    $stream = [IO.File]::OpenRead($file.FullName)
    $reader = $null
    try {
        $reader = [Xml.XmlReader]::Create($stream, $settings)
        $xml = New-Object System.Xml.XmlDocument
        $xml.XmlResolver = $null
        $xml.Load($reader)
    }
    catch {
        return [pscustomobject]@{ status = 'rejected-xml'; reason = $_.Exception.GetType().Name }
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        $stream.Dispose()
    }
    $ns = [Xml.XmlNamespaceManager]::new($xml.NameTable)
    $ns.AddNamespace('t', 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010')
    $run = $xml.SelectSingleNode('/t:TestRun', $ns)
    if ($null -eq $run) {
        return [pscustomobject]@{ status = 'rejected-schema'; reason = 'Unsupported TRX root' }
    }
    $summaries = $run.SelectNodes('t:ResultSummary', $ns)
    if ($summaries.Count -ne 1 -or $summaries[0].GetAttribute('outcome') -cnotin @('Completed', 'Passed', 'Failed')) {
        return [pscustomobject]@{ status = 'rejected-incomplete'; reason = 'Missing or incomplete ResultSummary' }
    }
    $results = $run.SelectNodes('t:Results/t:UnitTestResult', $ns)
    $byOutcome = @{}
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $duplicateNames = [Collections.Generic.List[string]]::new()
    $details = [Collections.Generic.List[object]]::new()
    foreach ($r in $results) {
        $outcome = $r.GetAttribute('outcome')
        if ([string]::IsNullOrWhiteSpace($outcome)) { $outcome = '(missing)' }
        if (-not $byOutcome.ContainsKey($outcome)) { $byOutcome[$outcome] = 0 }
        $byOutcome[$outcome]++
        $name = $r.GetAttribute('testName')
        if ([string]::IsNullOrWhiteSpace($name) -or -not $names.Add($name)) {
            $duplicateNames.Add($name)
        }
        if ($includeNames) {
            $details.Add([pscustomobject]@{
                testName = $name
                outcome = $outcome
                testId = $r.GetAttribute('testId')
                executionId = $r.GetAttribute('executionId')
            })
        }
    }
    $times = $run.SelectSingleNode('t:Times', $ns)
    $counters = $run.SelectSingleNode('t:ResultSummary/t:Counters', $ns)
    $counterValues = @{}
    if ($null -ne $counters) {
        foreach ($attribute in $counters.Attributes) {
            $counterValues[$attribute.Name] = $attribute.Value
        }
    }
    return [pscustomobject]@{
        status = if ($duplicateNames.Count -eq 0) { 'metadata-only' } else { 'ambiguous-test-names' }
        runId = $run.GetAttribute('id')
        runName = $run.GetAttribute('name')
        startTime = if ($null -ne $times) { $times.GetAttribute('start') } else { $null }
        finishTime = if ($null -ne $times) { $times.GetAttribute('finish') } else { $null }
        summaryOutcome = $summaries[0].GetAttribute('outcome')
        counters = $counterValues
        parsedResultCount = $results.Count
        resultOutcomes = $byOutcome
        duplicateOrMissingTestNames = @($duplicateNames.ToArray())
        results = if ($includeNames) { @($details.ToArray()) } else { $null }
    }
}

$allowed = @('.trx', '.json', '.log', '.binlog', '.pcap', '.pcapng', '.csv', '.zip')
$files = [Collections.Generic.Dictionary[string, IO.FileInfo]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($root in $EvidenceRoot) {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw "Missing evidence directory: $root"
    }
    foreach ($f in (Get-ChildItem -LiteralPath $root -File -Recurse -Force)) {
        if ($f.Extension.ToLowerInvariant() -notin $allowed) { continue }
        if (-not $files.ContainsKey($f.FullName)) { $files.Add($f.FullName, $f) }
        if ($files.Count -gt $MaximumFiles) { throw 'Evidence inventory exceeded MaximumFiles' }
    }
}
$artifacts = [Collections.Generic.List[object]]::new()
foreach ($f in ($files.Values | Sort-Object -Property FullName)) {
    # SHA-256 is calculated over the original bytes; no files are rewritten.
    $digest = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $trx = $null
    if ($f.Extension -ieq '.trx') {
        $trx = Read-TrxMetadata $f $IncludeTestNames.IsPresent
    }
    $artifacts.Add([pscustomobject]@{
        path = $f.FullName
        fileName = $f.Name
        bytes = $f.Length
        sha256 = $digest
        lastWriteUtc = $f.LastWriteTimeUtc.ToString('o')
        format = $f.Extension.ToLowerInvariant()
        trx = $trx
        # A filename, timestamp or run ID cannot attest an execution SHA.
        executionSha = $null
        checkoutAttested = $false
        evidenceAdmitted = $false
        duplicateContent = $false
        conflictingTrxRunId = $false
    })
}
$byHash = @{}
$byRun = @{}
foreach ($a in $artifacts) {
    if (-not $byHash.ContainsKey($a.sha256)) {
        $byHash[$a.sha256] = [Collections.Generic.List[object]]::new()
    }
    $byHash[$a.sha256].Add($a)
    if ($null -ne $a.trx -and $null -ne $a.trx.PSObject.Properties['runId'] -and -not [string]::IsNullOrWhiteSpace($a.trx.runId)) {
        $runId = [string]$a.trx.runId
        if (-not $byRun.ContainsKey($runId)) {
            $byRun[$runId] = [Collections.Generic.List[object]]::new()
        }
        $byRun[$runId].Add($a)
    }
}
foreach ($a in $artifacts) {
    $a.duplicateContent = ($byHash[$a.sha256].Count -gt 1)
    if ($null -ne $a.trx -and $null -ne $a.trx.PSObject.Properties['runId'] -and -not [string]::IsNullOrWhiteSpace($a.trx.runId)) {
        $sameRun = $byRun[[string]$a.trx.runId]
        $a.conflictingTrxRunId = (@($sameRun | Select-Object -ExpandProperty sha256 -Unique).Count -gt 1)
    }
}
[pscustomobject]@{
    schemaVersion = 1
    purpose = 'read-only-artifact-discovery'
    inspectionTimeUtc = [DateTime]::UtcNow.ToString('o')
    artifactCount = $artifacts.Count
    executionShaVerified = $false
    testsExecutedByInventory = 0
    artifactAdmissionCount = 0
    artifacts = @($artifacts.ToArray())
} | ConvertTo-Json -Depth 12
