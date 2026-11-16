# SPDX-License-Identifier: MIT
# Pure, fail-closed completion contract for owner-run SOC WPF verification.
# No network, git, dotnet, captures or field-admission side effects.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-SocWorkspaceTrxEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -le 0 -or $item.Length -gt 33554432 -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'SOC TRX must be a nonempty regular file of at most 32 MiB.'
    }
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 33554432
    $reader = [Xml.XmlReader]::Create($item.FullName, $settings)
    try {
        $xml = New-Object System.Xml.XmlDocument
        $xml.XmlResolver = $null
        $xml.Load($reader)
    } finally {
        $reader.Dispose()
    }
    $ns = [Xml.XmlNamespaceManager]::new($xml.NameTable)
    $ns.AddNamespace('t', 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010')
    $run = $xml.SelectSingleNode('/t:TestRun', $ns)
    if ($null -eq $run) { throw 'Unsupported SOC TRX root.' }
    $runId = [guid]::Empty
    if (-not [guid]::TryParse($run.GetAttribute('id'), [ref]$runId) -or
        $runId -eq [guid]::Empty) { throw 'Invalid SOC TRX run ID.' }
    $summary = $run.SelectSingleNode('t:ResultSummary', $ns)
    $counters = $run.SelectSingleNode('t:ResultSummary/t:Counters', $ns)
    $times = $run.SelectSingleNode('t:Times', $ns)
    if ($null -eq $summary -or $null -eq $counters -or $null -eq $times -or
        $summary.GetAttribute('outcome') -cnotin @('Completed','Passed')) {
        throw 'SOC TRX has missing or incomplete summary.'
    }
    $number = @{}
    foreach ($name in @('total','passed','executed','failed')) {
        $raw = $counters.GetAttribute($name)
        if ($raw -cnotmatch '^[0-9]+$') { throw "SOC TRX invalid counter $name." }
        $number[$name] = [int]::Parse($raw, [Globalization.CultureInfo]::InvariantCulture)
    }
    $results = @($run.SelectNodes('t:Results/t:UnitTestResult', $ns))
    $definitions = @($run.SelectNodes('t:TestDefinitions/t:UnitTest', $ns))
    if ($number['total'] -le 0 -or $number['failed'] -ne 0 -or
        $number['total'] -ne $number['passed'] -or
        $number['total'] -ne $number['executed'] -or
        $results.Count -ne $number['total'] -or
        $definitions.Count -ne $number['total']) {
        throw 'SOC TRX has skipped, failed, missing or inconsistent results.'
    }

    $owners = @{}
    foreach ($definition in $definitions) {
        $id = $definition.GetAttribute('id')
        $method = $definition.SelectSingleNode('t:TestMethod', $ns)
        if ([string]::IsNullOrWhiteSpace($id) -or $owners.ContainsKey($id) -or $null -eq $method) {
            throw 'SOC TRX test definitions are ambiguous.'
        }
        $owners[$id] = [ordered]@{
            className = ($method.GetAttribute('className').Split(',')[0]).Trim()
            methodName = $method.GetAttribute('name').Trim()
        }
    }
    $required = @('NetworkInvestigation','IncidentTimeline','IncidentDetectionLinkVm')
    $groups = [ordered]@{}
    foreach ($marker in $required) { $groups[$marker] = 0 }
    $seenExecutions = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $seenTests = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $methodScopedCases = 0
    foreach ($result in $results) {
        $id = $result.GetAttribute('testId')
        $executionId = $result.GetAttribute('executionId')
        if (-not $owners.ContainsKey($id) -or -not $seenTests.Add($id) -or
            [string]::IsNullOrWhiteSpace($executionId) -or
            -not $seenExecutions.Add($executionId) -or
            $result.GetAttribute('outcome') -cne 'Passed') {
            throw 'SOC TRX contains duplicate, unknown, failed or unexecuted tests.'
        }
        # VSTest FullyQualifiedName~ selects both class and method matches.
        # Prefer the owning test class; only use method-name matching when the
        # class itself has no SOC marker. Do not count the same test twice.
        $className = [string]$owners[$id]['className']
        $methodName = [string]$owners[$id]['methodName']
        if (-not $className.StartsWith('Carthago.Tests.', [StringComparison]::Ordinal) -or
            [string]::IsNullOrWhiteSpace($methodName)) {
            throw "SOC TRX test lacks a valid owner: $className.$methodName"
        }
        $classGroups = @($required | Where-Object {
            $className.IndexOf($_, [StringComparison]::OrdinalIgnoreCase) -ge 0
        })
        if ($classGroups.Count -eq 1) {
            $group = $classGroups[0]
        } elseif ($classGroups.Count -eq 0) {
            $methodGroups = @($required | Where-Object {
                $methodName.IndexOf($_, [StringComparison]::OrdinalIgnoreCase) -ge 0
            })
            if ($methodGroups.Count -ne 1) {
                throw "SOC TRX method-scoped test has no unique SOC group: $className.$methodName"
            }
            $group = $methodGroups[0]
            $methodScopedCases++
        } else {
            throw "SOC TRX class matches multiple SOC groups: $className.$methodName"
        }
        $groups[$group]++
    }
    foreach ($marker in $required) {
        if ($groups[$marker] -lt 1) { throw "SOC TRX missing required test group $marker." }
    }
    $started = [DateTimeOffset]::MinValue
    $finished = [DateTimeOffset]::MinValue
    $timeStart = $times.GetAttribute('start')
    $timeFinish = $times.GetAttribute('finish')
    if ($timeStart -cnotmatch '(?:Z|[+-][0-9]{2}:[0-9]{2})$' -or
        $timeFinish -cnotmatch '(?:Z|[+-][0-9]{2}:[0-9]{2})$' -or
        -not [DateTimeOffset]::TryParse($timeStart, [ref]$started) -or
        -not [DateTimeOffset]::TryParse($timeFinish, [ref]$finished) -or
        $finished -lt $started) { throw 'SOC TRX start and finish times are invalid.' }

    return [ordered]@{
        trxRunId = $runId.ToString('D')
        trxSha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        trxStartedUtc = $started.ToUniversalTime().ToString('o')
        trxFinishedUtc = $finished.ToUniversalTime().ToString('o')
        testResults = [ordered]@{
            total = $number['total']; executed = $number['executed']
            passed = $number['passed']; failed = $number['failed']
        }
        requiredGroups = $groups
        methodScopedCases = $methodScopedCases
    }
}

function Assert-SocWorkspaceCompletionRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Record)

    if ($Record['schemaVersion'] -ne 1 -or
        $Record['purpose'] -cne 'soc-workspace-final-provenance-v1' -or
        $Record['status'] -cne 'SyntheticSocPassed' -or
        $Record['branch'] -cne 'feature/carthago-reliability-hardening' -or
        $Record['postRunBranch'] -cne $Record['branch']) {
        throw 'SOC completion record status, schema or branch invalid.'
    }
    foreach ($name in @('sourceSha','preRunSha','postRunSha','preRunOriginSha','postRunOriginSha')) {
        if ($Record[$name] -isnot [string] -or $Record[$name] -cnotmatch '^[a-f0-9]{40}$') {
            throw "SOC completion record invalid $name."
        }
    }
    if ($Record['sourceSha'] -cne $Record['preRunSha'] -or
        $Record['sourceSha'] -cne $Record['postRunSha'] -or
        $Record['sourceSha'] -cne $Record['preRunOriginSha'] -or
        $Record['sourceSha'] -cne $Record['postRunOriginSha']) {
        throw 'SOC completion record pre/post source and tracking SHA differ.'
    }
    foreach ($name in @('trxSha256','sourceShaFileSha256')) {
        if ($Record[$name] -isnot [string] -or $Record[$name] -cnotmatch '^[a-f0-9]{64}$') {
            throw "SOC completion record invalid $name."
        }
    }
    $runId = [guid]::Empty
    if ($Record['trxRunId'] -isnot [string] -or
        -not [guid]::TryParse($Record['trxRunId'], [ref]$runId) -or
        $runId -eq [guid]::Empty) { throw 'SOC completion record invalid TRX run ID.' }
    $start = [DateTimeOffset]::MinValue
    $finish = [DateTimeOffset]::MinValue
    $trxStart = [DateTimeOffset]::MinValue
    $trxFinish = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse([string]$Record['startedUtc'], [ref]$start) -or
        -not [DateTimeOffset]::TryParse([string]$Record['finishedUtc'], [ref]$finish) -or
        -not [DateTimeOffset]::TryParse([string]$Record['trxStartedUtc'], [ref]$trxStart) -or
        -not [DateTimeOffset]::TryParse([string]$Record['trxFinishedUtc'], [ref]$trxFinish) -or
        $start.Offset -ne [TimeSpan]::Zero -or $finish.Offset -ne [TimeSpan]::Zero -or
        $trxStart.Offset -ne [TimeSpan]::Zero -or $trxFinish.Offset -ne [TimeSpan]::Zero -or
        $start -gt $finish -or
        $trxStart -lt $start.AddMinutes(-2) -or $trxFinish -gt $finish.AddMinutes(2) -or
        $trxStart -gt $trxFinish) {
        throw 'SOC completion record timestamps are inconsistent.'
    }
    $results = $Record['testResults']
    if ($results -isnot [System.Collections.IDictionary] -or
        $results['total'] -isnot [int] -or $results['total'] -le 0 -or
        $results['total'] -ne $results['executed'] -or
        $results['total'] -ne $results['passed'] -or $results['failed'] -ne 0) {
        throw 'SOC completion record counters incomplete.'
    }
    $requiredGroups = $Record['requiredGroups']
    if ($Record['methodScopedCases'] -isnot [int] -or
        $Record['methodScopedCases'] -lt 0 -or
        $Record['methodScopedCases'] -gt $results['total']) {
        throw 'SOC completion method-scoped count invalid.'
    }
    if ($requiredGroups -isnot [System.Collections.IDictionary]) { throw 'SOC completion groups missing.' }
    $verifiedGroupTotal = 0
    foreach ($name in @('NetworkInvestigation','IncidentTimeline','IncidentDetectionLinkVm')) {
        if ($requiredGroups[$name] -isnot [int] -or $requiredGroups[$name] -le 0) {
            throw "SOC completion missing group $name."
        }
        $verifiedGroupTotal += $requiredGroups[$name]
    }
    if ($requiredGroups.Count -ne 3 -or $verifiedGroupTotal -ne $results['total']) {
        throw 'SOC completion group counts must partition all executed tests.'
    }
    $stages = $Record['stages']
    $expected = @('sdk-version','restore','build-release','soc-tests')
    if ($stages -isnot [System.Collections.IDictionary] -or $stages.Count -ne $expected.Count) {
        throw 'SOC completion has missing or unexpected stages.'
    }
    foreach ($stage in $expected) {
        if (-not $stages.Contains($stage)) { throw "SOC completion missing stage $stage." }
        $entry = $stages[$stage]
        if ($entry -isnot [System.Collections.IDictionary] -or
            $entry['exitCode'] -isnot [int] -or $entry['exitCode'] -ne 0 -or
            $entry['logSha256'] -isnot [string] -or
            $entry['logSha256'] -cnotmatch '^[a-f0-9]{64}$' -or
            $entry['logFileName'] -cne ($stage + '.log')) {
            throw "SOC completion stage $stage did not pass."
        }
    }
    if ($Record['evidenceAdmitted'] -cne $false -or
        $Record['fieldAccuracyQualified'] -cne $false -or
        $Record['manualWpfValidated'] -cne $false) {
        throw 'SOC completion must not claim production, field or manual UI acceptance.'
    }
}

function Publish-SocWorkspaceCompletionRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Record,
        [Parameter(Mandatory)][string]$Path
    )
    Assert-SocWorkspaceCompletionRecord -Record $Record
    $target = [IO.Path]::GetFullPath($Path)
    $directory = [IO.Path]::GetDirectoryName($target)
    if (-not [IO.Directory]::Exists($directory) -or [IO.File]::Exists($target) -or
        [IO.Directory]::Exists($target)) { throw 'SOC completion target missing directory or already exists.' }
    $temporary = Join-Path $directory ('.completion-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $payload = $Record | ConvertTo-Json -Depth 8
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($payload + [Environment]::NewLine)
        $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew,
                                   [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
        } finally {
            $stream.Dispose()
        }
        [IO.File]::Move($temporary, $target)
    } finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

Export-ModuleMember -Function Get-SocWorkspaceTrxEvidence,Assert-SocWorkspaceCompletionRecord,Publish-SocWorkspaceCompletionRecord
