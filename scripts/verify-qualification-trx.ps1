# SPDX-License-Identifier: MIT
# Verify a reviewed TRX artifact; does not attest checkout identity or admit evidence.
[CmdletBinding(DefaultParameterSetName='Verify')]
param(
    [Parameter(Mandatory,ParameterSetName='Verify')][string]$Artifact,
    [Parameter(Mandatory,ParameterSetName='Verify')][string]$ExpectedSha256,
    [Parameter(Mandatory,ParameterSetName='Verify')][string[]]$TestName,
    [Parameter(Mandatory,ParameterSetName='Verify')][ValidateSet('Passed','Failed')][string]$Outcome,
    [Parameter(Mandatory,ParameterSetName='SelfTest')][switch]$SelfTest
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Test-QualificationTrx([byte[]]$bytes, [string]$digest, [string[]]$names, [string]$expected) {
    if ($bytes.Length -eq 0 -or $bytes.Length -gt 16777216) { throw 'TRX size outside bounds' }
    if (-not [regex]::IsMatch($digest, '\A[a-f0-9]{64}\z')) { throw 'Invalid SHA256' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $actual = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
    if ($actual -cne $digest) { throw 'TRX digest mismatch' }
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 16777216
    $stream = [IO.MemoryStream]::new($bytes)
    $reader = [Xml.XmlReader]::Create($stream,$settings)
    try {
        $xml = New-Object System.Xml.XmlDocument
        $xml.XmlResolver = $null
        $xml.Load($reader)
    } finally { $reader.Dispose(); $stream.Dispose() }
    $ns = [Xml.XmlNamespaceManager]::new($xml.NameTable)
    $ns.AddNamespace('t','http://microsoft.com/schemas/VisualStudio/TeamTest/2010')
    $run = $xml.SelectSingleNode('/t:TestRun',$ns)
    if ($null -eq $run) { throw 'Unsupported TRX root' }
    $results = $run.SelectNodes('t:Results/t:UnitTestResult',$ns)
    $summary = $run.SelectNodes('t:ResultSummary',$ns)
    if ($summary.Count -ne 1 -or $summary[0].GetAttribute('outcome') -cnotin @('Completed','Passed','Failed')) { throw 'Incomplete TRX run' }
    # A terminal summary must not contradict the actual result outcomes. Completed
    # remains neutral because older TRX producers use it for both pass and fail.
    # A terminal pass cannot hide aborted, timed-out, errored, or otherwise
    # non-passing results. Keep mixed Completed runs readable, but never
    # accept an unrecognized outcome as qualification evidence.
    $terminalOutcomes = @('Passed','Failed','Error','Timeout','Aborted','Inconclusive','NotExecuted','Pending')
    foreach ($resultNode in $results) {
        if ($resultNode.GetAttribute('outcome') -cnotin $terminalOutcomes) { throw 'Unknown TRX test outcome' }
    }
    # Every result name must identify one outcome, including unselected tests.
    # Otherwise an unrelated duplicate can undermine run-level accounting.
    $resultNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($resultNode in $results) {
        $resultName = $resultNode.GetAttribute('testName')
        if ([string]::IsNullOrWhiteSpace($resultName) -or $resultName.Length -gt 4096 -or
            $resultName -match '[\x00-\x1f\x7f]' -or -not $resultNames.Add($resultName)) { throw 'Missing, oversized or duplicate TRX result name' }
    }
    $nonPassing = @($results | Where-Object { $_.GetAttribute('outcome') -cne 'Passed' }).Count
    $observedFailures = @($results | Where-Object { $_.GetAttribute('outcome') -cin @('Failed','Error','Timeout','Aborted') }).Count
    if (($summary[0].GetAttribute('outcome') -ceq 'Passed' -and $nonPassing -gt 0) -or
        ($summary[0].GetAttribute('outcome') -ceq 'Failed' -and $observedFailures -eq 0)) {
        throw 'TRX summary outcome contradicts result nodes'
    }
    # When a producer supplies TRX counters, reconcile them with the actual
    # result nodes. A selected passing test cannot override a contradictory
    # run summary. Older minimal fixtures without counters remain supported.
    $counterNodes = $summary[0].SelectNodes('t:Counters',$ns)
    if ($counterNodes.Count -gt 1) { throw 'Duplicate TRX counters' }
    $counters = if ($counterNodes.Count -eq 1) { $counterNodes[0] } else { $null }
    if ($null -ne $counters) {
        $observed = @($results)
        $passed = @($observed | Where-Object { $_.GetAttribute('outcome') -ceq 'Passed' }).Count
        $failed = @($observed | Where-Object { $_.GetAttribute('outcome') -ceq 'Failed' }).Count
        foreach ($pair in @(@('total',$observed.Count),@('passed',$passed),@('failed',$failed))) {
            $value = $counters.GetAttribute($pair[0])
            $parsed = 0
            if (-not [regex]::IsMatch($value, '\A(?:0|[1-9][0-9]*)\z') -or
                -not [int]::TryParse($value, [ref]$parsed) -or
                $parsed -ne [int]$pair[1]) { throw 'TRX counter mismatch or invalid syntax' }
        }
        # The optional error counter must match observed Error results.
        if ($counters.HasAttribute('error')) {
            $errors = @($observed | Where-Object { $_.GetAttribute('outcome') -ceq 'Error' }).Count
            $reportedErrors = 0
            $errorValue = $counters.GetAttribute('error')
            if (-not [regex]::IsMatch($errorValue, '\A(?:0|[1-9][0-9]*)\z') -or
                -not [int]::TryParse($errorValue, [ref]$reportedErrors) -or
                $reportedErrors -ne $errors) { throw 'TRX error counter mismatch or invalid syntax' }
        }
        # Optional terminal counters must agree with observed nodes; never infer
        # execution or silently accept contradictory producer accounting.
        foreach ($counterName in @('timeout','aborted','inconclusive','notExecuted')) {
            if (-not $counters.HasAttribute($counterName)) { continue }
            $outcomeName = switch ($counterName) {
                'timeout' { 'Timeout' }
                'aborted' { 'Aborted' }
                'inconclusive' { 'Inconclusive' }
                'notExecuted' { 'NotExecuted' }
            }
            $observedCount = @($observed | Where-Object { $_.GetAttribute('outcome') -ceq $outcomeName }).Count
            $reportedCount = 0
            $counterValue = $counters.GetAttribute($counterName)
            if (-not [regex]::IsMatch($counterValue, '\A(?:0|[1-9][0-9]*)\z') -or
                -not [int]::TryParse($counterValue, [ref]$reportedCount) -or
                $reportedCount -ne $observedCount) { throw 'TRX terminal counter mismatch or invalid syntax' }
        }
        # Pending is a distinct non-executed outcome; if the producer reports
        # its optional count it must agree with the actual result nodes.
        if ($counters.HasAttribute('pending')) {
            $pendingCount = @($observed | Where-Object { $_.GetAttribute('outcome') -ceq 'Pending' }).Count
            $reportedPending = 0
            $pendingValue = $counters.GetAttribute('pending')
            if (-not [regex]::IsMatch($pendingValue, '\A(?:0|[1-9][0-9]*)\z') -or
                -not [int]::TryParse($pendingValue, [ref]$reportedPending) -or
                $reportedPending -ne $pendingCount) { throw 'TRX pending counter mismatch or invalid syntax' }
        }
        if ($passed + $failed -gt $observed.Count) { throw 'Invalid TRX result accounting' }
    }
    if ($names.Count -eq 0 -or $names.Count -gt 1000) { throw 'Invalid selection size' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in $names) {
        if ([string]::IsNullOrWhiteSpace($name) -or $name.Length -gt 4096 -or $name -match '[\x00-\x1f\x7f*?]' -or -not $seen.Add($name)) { throw 'Invalid, wildcard, oversized or duplicate requested test' }
        $matches = @($results | Where-Object { $_.GetAttribute('testName') -ceq $name })
        if ($matches.Count -ne 1) { throw "Missing or ambiguous test: $name" }
        if ($matches[0].GetAttribute('outcome') -cne $expected) { throw "Unexpected test outcome: $name" }
    }
    [pscustomobject]@{ artifactSha256=$actual; matchedTests=$seen.Count; outcome=$expected; checkoutAttested=$false; evidenceAdmitted=$false }
}
if ($SelfTest) {
    $xml = '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"><Results><UnitTestResult testName="Exact.Test" outcome="Passed"/></Results><ResultSummary outcome="Completed"/></TestRun>'
    function Invoke-Fixture([string]$body,[string[]]$names,[string]$outcome,[switch]$WrongHash,[switch]$TrailingHashLf) {
        $bytes = [Text.Encoding]::UTF8.GetBytes($body)
        $h = [Security.Cryptography.SHA256]::Create()
        try { $digest = [BitConverter]::ToString($h.ComputeHash($bytes)).Replace('-','').ToLowerInvariant() } finally { $h.Dispose() }
        if ($WrongHash) { $digest = '0' * 64 }
        if ($TrailingHashLf) { $digest += "`n" }
        Test-QualificationTrx $bytes $digest $names $outcome
    }
    function Reject-Fixture([scriptblock]$action) {
        $rejected = $false
        try { $null = & $action } catch { $rejected = $true }
        if (-not $rejected) { throw 'Invalid TRX fixture accepted' }
    }
    $ok = Invoke-Fixture $xml @('Exact.Test') 'Passed'
    if ($ok.matchedTests -ne 1 -or $ok.evidenceAdmitted) { throw 'Positive fixture failed' }
    Reject-Fixture { Invoke-Fixture $xml @('Exact.Test') 'Passed' -WrongHash }
    Reject-Fixture { Invoke-Fixture $xml @('Exact.Test') 'Passed' -TrailingHashLf }
    Reject-Fixture { Invoke-Fixture $xml @('exact.test') 'Passed' }
    Reject-Fixture { Invoke-Fixture $xml @('Exact.Test') 'Failed' }
    Reject-Fixture { Invoke-Fixture $xml @('Exact.Test','Exact.Test') 'Passed' }
    Reject-Fixture { Invoke-Fixture $xml @('Exact.*') 'Passed' }
    Reject-Fixture { Invoke-Fixture $xml @('Exact.Te?t') 'Passed' }
    Reject-Fixture { Invoke-Fixture $xml @('Exact.' + ('A' * 4097)) 'Passed' }
    Reject-Fixture { Invoke-Fixture $xml @("Exact.`nTest") 'Passed' }
    Reject-Fixture { Invoke-Fixture ($xml.Replace('</Results>','<UnitTestResult testName="Exact.Test" outcome="Passed"/></Results>')) @('Exact.Test') 'Passed' }
    # Unselected result identities must not contain control characters either.
    Reject-Fixture { Invoke-Fixture ($xml.Replace('</Results>','<UnitTestResult testName="Other.&#10;Test" outcome="Passed"/></Results>')) @('Exact.Test') 'Passed' }
    # Duplicate names outside the requested selection must also be rejected.
    $unrelatedDuplicate = $xml.Replace('</Results>','<UnitTestResult testName="Other.Test" outcome="Passed"/><UnitTestResult testName="Other.Test" outcome="Failed"/></Results>')
    Reject-Fixture { Invoke-Fixture $unrelatedDuplicate @('Exact.Test') 'Passed' }

    Reject-Fixture { Invoke-Fixture ($xml.Replace('Completed','Aborted')) @('Exact.Test') 'Passed' }
    $counted = $xml.Replace('<ResultSummary outcome="Completed"/>','<ResultSummary outcome="Completed"><Counters total="1" passed="1" failed="0"/></ResultSummary>')
    $countedOk = Invoke-Fixture $counted @('Exact.Test') 'Passed'
    if ($countedOk.matchedTests -ne 1) { throw 'Counted positive fixture failed' }
    # A second Counters node must not override or evade the reviewed accounting.
    Reject-Fixture { Invoke-Fixture ($counted.Replace('</ResultSummary>','<Counters total="0" passed="0" failed="0"/></ResultSummary>')) @('Exact.Test') 'Passed' }
    Reject-Fixture { Invoke-Fixture ($counted.Replace('passed="1"','passed="0"')) @('Exact.Test') 'Passed' }
    Reject-Fixture { Invoke-Fixture ($counted.Replace('total="1"','total="2"')) @('Exact.Test') 'Passed' }
    Reject-Fixture { Invoke-Fixture ($counted.Replace('failed="0"','failed="1"')) @('Exact.Test') 'Passed' }
    Reject-Fixture { Invoke-Fixture ($counted.Replace('total="1"','total="+1"')) @('Exact.Test') 'Passed' }
    Reject-Fixture { Invoke-Fixture ($counted.Replace('passed="1"','passed=" 1 "')) @('Exact.Test') 'Passed' }
    Reject-Fixture { Invoke-Fixture ($counted.Replace('failed="0"','failed="00"')) @('Exact.Test') 'Passed' }
    # XML character references preserve trailing LF; all mandatory numeric
    # attributes must reject noncanonical values even when node counts agree.
    foreach ($counterName in @('total','passed','failed')) {
        $originalValue = if ($counterName -eq 'total' -or $counterName -eq 'passed') { '1' } else { '0' }
        $needle = $counterName + '="' + $originalValue + '"'
        $replacement = $counterName + '="' + $originalValue + '&#10;"'
        Reject-Fixture { Invoke-Fixture ($counted.Replace($needle,$replacement)) @('Exact.Test') 'Passed' }
    }

    $withError = $counted.Replace('</Results>','<UnitTestResult testName="Other.Error" outcome="Error"/></Results>').Replace('total="1"','total="2"')
    $withError = $withError.Replace('failed="0"','failed="0"').Replace('passed="1"','passed="1"').Replace('failed="0"','failed="0"')
    $errorCounted = $withError.Replace('failed="0"','failed="0" error="1"')
    $errorOk = Invoke-Fixture $errorCounted @('Exact.Test') 'Passed'
    if ($errorOk.matchedTests -ne 1) { throw 'Error-counter positive fixture failed' }
    Reject-Fixture { Invoke-Fixture ($errorCounted.Replace('error="1"','error="0"')) @('Exact.Test') 'Passed' }
    Reject-Fixture { Invoke-Fixture ($errorCounted.Replace('error="1"','error="invalid"')) @('Exact.Test') 'Passed' }
    Reject-Fixture { Invoke-Fixture ($errorCounted.Replace('error="1"','error="+1"')) @('Exact.Test') 'Passed' }
    Reject-Fixture { Invoke-Fixture ($errorCounted.Replace('error="1"','error="1&#10;"')) @('Exact.Test') 'Passed' }
    # Optional terminal counters are exact; a zero control must pass and
    # each contradictory nonzero terminal count must fail closed.
    $terminalCounted = $counted.Replace('failed="0"','failed="0" timeout="0" aborted="0" inconclusive="0" notExecuted="0"')
    $terminalOk = Invoke-Fixture $terminalCounted @('Exact.Test') 'Passed'
    if ($terminalOk.matchedTests -ne 1) { throw 'Terminal-counter positive fixture failed' }
    foreach ($terminalName in @('timeout','aborted','inconclusive','notExecuted')) {
        Reject-Fixture { Invoke-Fixture ($terminalCounted.Replace(($terminalName + '="0"'),($terminalName + '="1"'))) @('Exact.Test') 'Passed' }
    }
    # Noncanonical and overflowing optional counters must fail even when observed zero.
    Reject-Fixture { Invoke-Fixture ($terminalCounted.Replace('timeout="0"','timeout="+0"')) @('Exact.Test') 'Passed' }
    Reject-Fixture { Invoke-Fixture ($terminalCounted.Replace('aborted="0"','aborted="00"')) @('Exact.Test') 'Passed' }
    Reject-Fixture { Invoke-Fixture ($terminalCounted.Replace('notExecuted="0"','notExecuted="2147483648"')) @('Exact.Test') 'Passed' }
    # A declared Pending count is independently checked, not inferred as executed.
    $pendingCounted = $counted.Replace('failed="0"','failed="0" pending="0"')
    $pendingOk = Invoke-Fixture $pendingCounted @('Exact.Test') 'Passed'
    if ($pendingOk.matchedTests -ne 1) { throw 'Pending-counter positive fixture failed' }
    Reject-Fixture { Invoke-Fixture ($pendingCounted.Replace('pending="0"','pending="1"')) @('Exact.Test') 'Passed' }
    Reject-Fixture { Invoke-Fixture ($pendingCounted.Replace('pending="0"','pending="+0"')) @('Exact.Test') 'Passed' }
    # Selected success must not override an inconsistent terminal run outcome.
    Reject-Fixture { Invoke-Fixture ($xml.Replace('outcome="Completed"','outcome="Failed"')) @('Exact.Test') 'Passed' }
    $mixed = $xml.Replace('</Results>','<UnitTestResult testName="Other.Failed" outcome="Failed"/></Results>')
    Reject-Fixture { Invoke-Fixture ($mixed.Replace('outcome="Completed"','outcome="Passed"')) @('Exact.Test') 'Passed' }
    $mixedOk = Invoke-Fixture $mixed @('Exact.Test') 'Passed'
    if ($mixedOk.matchedTests -ne 1) { throw 'Completed mixed-result control failed' }
    # Terminal Passed must not conceal error/timeout/non-executed nodes.
    foreach ($outcome in @('Error','Timeout','Aborted','Inconclusive','NotExecuted')) {
        $withOther = $xml.Replace('</Results>',('<UnitTestResult testName="Other.Case" outcome="' + $outcome + '"/></Results>'))
        Reject-Fixture { Invoke-Fixture ($withOther.Replace('outcome="Completed"','outcome="Passed"')) @('Exact.Test') 'Passed' }
    }
    Reject-Fixture { Invoke-Fixture ($xml.Replace('outcome="Passed"/></Results>','outcome="Unknown"/></Results>')) @('Exact.Test') 'Passed' }
    Reject-Fixture { Invoke-Fixture ('<!DOCTYPE TestRun [<!ENTITY x "bad">]>' + $xml) @('Exact.Test') 'Passed' }
    [pscustomobject]@{ selfTestsPassed=43; detectorTestsExecuted=0 } | ConvertTo-Json
} else {
    $item = Get-Item -LiteralPath $Artifact
    if ($item.PSIsContainer -or $item.Length -gt 16777216) { throw 'Invalid artifact size or type' }
    # Enforce the 16 MiB limit on the read itself, not only on a racy pre-read stat.
    $limit = 16777216
    $stream = [IO.File]::Open($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $buffer = New-Object byte[] 65536
        $output = [IO.MemoryStream]::new()
        try {
            while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                if ($output.Length + $count -gt $limit) { throw 'TRX size outside bounds during read' }
                $output.Write($buffer, 0, $count)
            }
            $bytes = $output.ToArray()
        } finally { $output.Dispose() }
    } finally { $stream.Dispose() }
    Test-QualificationTrx $bytes $ExpectedSha256 $TestName $Outcome | ConvertTo-Json
}
