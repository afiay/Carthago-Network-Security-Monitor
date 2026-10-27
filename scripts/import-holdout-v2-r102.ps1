# SPDX-License-Identifier: MIT
# Prepare a DNS holdout candidate from packet-attributed external PCAP evidence.
# NEVER train/tune from the held-out result; this does NOT freeze or test anything.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CapturePath,
    [Parameter(Mandatory=$true)][string]$SourceAddress,
    [Parameter(Mandatory=$true)][string]$DnsRoot,
    [Parameter(Mandatory=$true)][ValidateSet('Benign','Malicious')][string]$Classification,
    [Parameter(Mandatory=$true)][ValidatePattern('^holdout-v2-r102-[a-z0-9-]+$')][string]$Name,
    [Parameter(Mandatory=$true)][string]$SourceUri,
    [Parameter(Mandatory=$true)][string]$SourceLicense,
    [Parameter(Mandatory=$true)][string]$IndependentLabelBasis,
    [Parameter(Mandatory=$true)][switch]$AnalystReviewedLabel,
    [int]$MaximumRecords=50,
    [int]$MaximumPacketsToScan=100000,
    [string]$OutputDirectory='build-verify/holdout-v2-import',
    [string]$TsharkPath='tshark'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($MaximumRecords -lt 3 -or $MaximumRecords -gt 500) {
    throw 'MaximumRecords must be 3..500.'
}
if ($MaximumPacketsToScan -lt 100 -or $MaximumPacketsToScan -gt 500000) {
    throw 'MaximumPacketsToScan must be 100..500000 to bound large PCAP decoding.'
}
if ($Classification -eq 'Malicious' -and $IndependentLabelBasis.Trim().Length -lt 20) {
    throw 'Malicious classification needs a substantive independent label basis.'
}
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$pcap=(Resolve-Path -LiteralPath $CapturePath).Path
$exe=Get-Command $TsharkPath -ErrorAction Stop
$domain=$DnsRoot.Trim().Trim('.').ToLowerInvariant()
if ($domain -notmatch '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$') {
    throw 'DnsRoot must be a valid multi-label DNS name.'
}
$manifest=Get-Content -LiteralPath (Join-Path $root 'docs/holdout-evaluation-v2-manifest.json') -Raw | ConvertFrom-Json
$entry=@($manifest.samples | Where-Object {
    [IO.Path]::GetFileNameWithoutExtension([string]$_.file) -eq $Name
})
if ($entry.Count -ne 1 -or $entry[0].primaryRule -ne 'R102' -or
    $entry[0].classification -ne $Classification -or
    $entry[0].sourceKind -ne 'external-pcap-reviewed') {
    throw 'Name, classification and primary rule must match the declared v2 manifest.'
}
$fields=@('frame.number','ip.src','ip.dst','ipv6.src','ipv6.dst',
          'udp.srcport','udp.dstport','tcp.srcport','tcp.dstport',
          'dns.qry.name','dns.qry.type')
$argsTshark=@('-n','-r',$pcap,'-c',"$MaximumPacketsToScan",'-Y',
             'dns.flags.response == 0 && (udp.dstport == 53 || tcp.dstport == 53)',
             '-T','fields','-E','separator=|','-E','quote=n','-E','occurrence=f')
foreach ($field in $fields) { $argsTshark+=@('-e',$field) }
$rows=@(& $exe.Source @argsTshark 2>&1)
if ($LASTEXITCODE -ne 0) { throw ('tshark failed: '+($rows -join ' ')) }
$qtypes=@{'1'='A';'28'='AAAA';'16'='TXT';'5'='CNAME';'15'='MX';'12'='PTR';'2'='NS';'33'='SRV';'6'='SOA';'10'='NULL'}
$records=[System.Collections.Generic.List[object]]::new()
$frames=[System.Collections.Generic.List[int]]::new()
$uniqueFrames=[System.Collections.Generic.HashSet[int]]::new()
foreach ($row in $rows) {
    if ($row -isnot [string]) { continue }
    $columns=$row.Split('|')
    if ($columns.Length -ne 11 -or $columns[0] -notmatch '^[0-9]+$') { continue }
    $frame=[int]$columns[0]
    if ($uniqueFrames.Contains($frame)) { continue }
    $src=$columns[1].Trim()
    $dst=$columns[2].Trim()
    $version=4
    if ($src.Length -eq 0 -or $dst.Length -eq 0) {
        $src=$columns[3].Trim(); $dst=$columns[4].Trim(); $version=6
    }
    if ($src -ne $SourceAddress) { continue }
    $nameValue=$columns[9].Trim().TrimEnd('.').ToLowerInvariant()
    if (-not ($nameValue -eq $domain -or $nameValue.EndsWith('.'+$domain,[StringComparison]::Ordinal))) { continue }
    if ($nameValue.Length -gt 253 -or $nameValue -notmatch '^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$') { continue }
    $typeNumber=$columns[10].Trim()
    if (-not $qtypes.ContainsKey($typeNumber)) { continue }
    $udp=$columns[5].Length -gt 0 -and $columns[6] -eq '53'
    $tcp=$columns[7].Length -gt 0 -and $columns[8] -eq '53'
    if ($udp -eq $tcp) { continue } # Require exactly one captured transport.
    $portString=if ($udp) { $columns[5] } else { $columns[7] }
    if ($portString -notmatch '^[0-9]{1,5}$' -or
        [int]$portString -lt 1 -or [int]$portString -gt 65535) { continue }
    $records.Add([ordered]@{
        source=$src;destination=$dst;ipVersion=$version;
        sourcePort=[int]$portString;destinationPort=53;
        protocol='DNS';applicationProtocol='DNS';
        isUdp=[bool]$udp;isTcp=[bool]$tcp;
        dnsQname=$nameValue;dnsQtype=$qtypes[$typeNumber]
    })
    $frames.Add($frame)
    [void]$uniqueFrames.Add($frame)
    if ($records.Count -ge $MaximumRecords) { break }
}
if ($records.Count -lt 3) {
    throw "Only $($records.Count) attributable DNS packets selected. Require >=3."
}
if ($Classification -eq 'Malicious' -and
    @($records | ForEach-Object { $_.dnsQname } | Sort-Object -Unique).Count -lt 3) {
    throw 'Malicious candidate requires >=3 distinct captured QNAMEs; do not synthesize repeats.'
}
$dir=Join-Path $root $OutputDirectory
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$samplePath=Join-Path $dir ($Name+'.json')
$provenancePath=Join-Path $dir ($Name+'.provenance.json')
if ((Test-Path -LiteralPath $samplePath) -or (Test-Path -LiteralPath $provenancePath)) {
    throw 'Candidate already exists. Refusing overwrite.'
}
# Keep expected-rule collections as arrays, including exactly one match.
# PowerShell statement subexpressions can otherwise unwrap singleton arrays.
if ($Classification -eq 'Malicious') {
    $expectedMatches=[string[]]@('R102')
    $expectedNonMatches=[string[]]@('R118','R163')
    $confidenceFloor=0.75
} else {
    $expectedMatches=[string[]]@()
    $expectedNonMatches=[string[]]@('R102','R118','R163')
    $confidenceFloor=0.0
}
$sample=[ordered]@{
    name=$Name;classification=$Classification;records=@($records.ToArray());
    expectedMatches=$expectedMatches;
    expectedNonMatches=$expectedNonMatches;
    expectedMinimumConfidence=$confidenceFloor
}
$provenance=[ordered]@{
    schemaVersion=1;sample=$Name;classification=$Classification;
    sourceKind='external-pcap-reviewed';sourceUri=$SourceUri;sourceLicense=$SourceLicense;
    independentLabelBasis=$IndependentLabelBasis;analystReviewedLabel=[bool]$AnalystReviewedLabel;
    captureFileName=[IO.Path]::GetFileName($pcap);
    captureSha256=(Get-FileHash -LiteralPath $pcap -Algorithm SHA256).Hash.ToLowerInvariant();
    frameNumbers=@($frames.ToArray());selectedRecordCount=$records.Count;
    sourceAddress=$SourceAddress;queryRoot=$domain;extractor='tshark';
    extractorVersion=((& $exe.Source -v | Select-Object -First 1) -join '');
    capturedTransportEvidence=$true;
    maximumPacketsToScan=$MaximumPacketsToScan;
    selectionMethod='First matching query records within bounded earliest PCAP packet range';
    transformations='Case-normalized QNAME, removed final dot; transport/IP/ports and DNS names otherwise retained.';
    privacyReviewRequired=$true;preparedAtUtc=[DateTime]::UtcNow.ToString('o')
}
$encoding=[Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText($samplePath, (($sample | ConvertTo-Json -Depth 15)+[Environment]::NewLine), $encoding)
[IO.File]::WriteAllText($provenancePath, (($provenance | ConvertTo-Json -Depth 15)+[Environment]::NewLine), $encoding)
Write-Host "PREPARED (NOT FROZEN): $($records.Count) packet-attributed records"
Write-Host "Inspected at most $MaximumPacketsToScan input packets (bounded candidate selection)."
Write-Host "Candidate: $samplePath"
Write-Host "Provenance: $provenancePath"
Write-Host 'Review labels, capture license and sensitive QNAME/IP data before publication.'
Write-Host 'No tests or holdout evaluation were executed.'
