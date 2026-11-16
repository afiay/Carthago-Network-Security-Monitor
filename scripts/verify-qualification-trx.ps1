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
    if ($digest -cnotmatch '^[a-f0-9]{64}$') { throw 'Invalid SHA256' }
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
    if ($names.Count -eq 0 -or $names.Count -gt 1000) { throw 'Invalid selection size' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in $names) {
        if ([string]::IsNullOrWhiteSpace($name) -or -not $seen.Add($name)) { throw 'Invalid or duplicate requested test' }
        $matches = @($results | Where-Object { $_.GetAttribute('testName') -ceq $name })
        if ($matches.Count -ne 1) { throw "Missing or ambiguous test: $name" }
        if ($matches[0].GetAttribute('outcome') -cne $expected) { throw "Unexpected test outcome: $name" }
    }
    [pscustomobject]@{ artifactSha256=$actual; matchedTests=$seen.Count; outcome=$expected; checkoutAttested=$false; evidenceAdmitted=$false }
}
if ($SelfTest) {
    $xml = '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"><Results><UnitTestResult testName="Exact.Test" outcome="Passed"/></Results><ResultSummary outcome="Completed"/></TestRun>'
    function Invoke-Fixture([string]$body,[string[]]$names,[string]$outcome,[switch]$WrongHash) {
        $bytes = [Text.Encoding]::UTF8.GetBytes($body)
        $h = [Security.Cryptography.SHA256]::Create()
        try { $digest = [BitConverter]::ToString($h.ComputeHash($bytes)).Replace('-','').ToLowerInvariant() } finally { $h.Dispose() }
        if ($WrongHash) { $digest = '0' * 64 }
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
    Reject-Fixture { Invoke-Fixture $xml @('exact.test') 'Passed' }
    Reject-Fixture { Invoke-Fixture $xml @('Exact.Test') 'Failed' }
    Reject-Fixture { Invoke-Fixture $xml @('Exact.Test','Exact.Test') 'Passed' }
    Reject-Fixture { Invoke-Fixture ($xml.Replace('</Results>','<UnitTestResult testName="Exact.Test" outcome="Passed"/></Results>')) @('Exact.Test') 'Passed' }
    Reject-Fixture { Invoke-Fixture ($xml.Replace('Completed','Aborted')) @('Exact.Test') 'Passed' }
    Reject-Fixture { Invoke-Fixture ('<!DOCTYPE TestRun [<!ENTITY x "bad">]>' + $xml) @('Exact.Test') 'Passed' }
    [pscustomobject]@{ selfTestsPassed=8; detectorTestsExecuted=0 } | ConvertTo-Json
} else {
    $item = Get-Item -LiteralPath $Artifact
    if ($item.PSIsContainer -or $item.Length -gt 16777216) { throw 'Invalid artifact size or type' }
    $bytes = [IO.File]::ReadAllBytes($item.FullName)
    Test-QualificationTrx $bytes $ExpectedSha256 $TestName $Outcome | ConvertTo-Json
}
