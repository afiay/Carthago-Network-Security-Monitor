# SPDX-License-Identifier: MIT
# Offline provenance audit of four R102 v2 candidates against their source PCAPs.
# DOES NOT execute Carthago rules, benchmark, freeze files or label traffic.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CaptureDirectory,
    [string]$CandidateDirectory='build-verify/holdout-v2-import',
    [string]$TsharkPath='tshark'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$captures=(Resolve-Path -LiteralPath $CaptureDirectory).Path
$candidates=(Resolve-Path -LiteralPath $CandidateDirectory).Path
$exe=Get-Command $TsharkPath -ErrorAction Stop
$manifest=Get-Content -LiteralPath (Join-Path $root 'docs/holdout-evaluation-v2-manifest.json') -Raw | ConvertFrom-Json
if ($manifest.schemaVersion -ne 2 -or $manifest.approvalState -ne 'PENDING_EXTERNAL_CAPTURE_AND_REVIEW') {
    throw 'Source audit only applies to an unfrozen v2 candidate manifest.'
}
$entries=@($manifest.samples | Where-Object { $_.sourceKind -eq 'external-pcap-reviewed' })
if ($entries.Count -ne 4) { throw 'Exactly four external R102 slots must be declared.' }
$types=@{'1'='A';'28'='AAAA';'16'='TXT';'5'='CNAME';'15'='MX';'12'='PTR';'2'='NS';'33'='SRV';'6'='SOA';'10'='NULL'}
$fields=@('frame.number','ip.src','ip.dst','ipv6.src','ipv6.dst',
    'udp.srcport','udp.dstport','tcp.srcport','tcp.dstport','dns.qry.name','dns.qry.type')
foreach ($entry in $entries) {
    $name=[IO.Path]::GetFileNameWithoutExtension([string]$entry.file)
    $samplePath=Join-Path $candidates ($name+'.json')
    $provenancePath=Join-Path $candidates ($name+'.provenance.json')
    if (-not (Test-Path -LiteralPath $samplePath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $provenancePath -PathType Leaf)) {
        throw "Source audit: candidate or provenance missing for $name."
    }
    $sample=Get-Content -LiteralPath $samplePath -Raw | ConvertFrom-Json
    $p=Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json
    if ($sample.name -ne $name -or $sample.classification -ne $entry.classification -or
        $p.sample -ne $name -or $p.classification -ne $entry.classification -or
        $p.sourceKind -ne 'external-pcap-reviewed' -or -not $p.analystReviewedLabel -or
        -not $p.capturedTransportEvidence -or
        [string]::IsNullOrWhiteSpace($p.independentLabelBasis) -or
        [string]::IsNullOrWhiteSpace($p.sourceUri) -or
        [string]::IsNullOrWhiteSpace($p.sourceLicense)) {
        throw "Source audit: incomplete external attribution or label review for $name."
    }
    $fileName=[string]$p.captureFileName
    if ($fileName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*\.pcap(ng)?$' -or
        $fileName -ne [IO.Path]::GetFileName($fileName)) {
        throw "Source audit: invalid or unsafe PCAP file name for $name."
    }
    $pcap=Join-Path $captures $fileName
    if (-not (Test-Path -LiteralPath $pcap -PathType Leaf)) {
        throw "Source audit: original capture missing for $name : $fileName"
    }
    $hash=(Get-FileHash -LiteralPath $pcap -Algorithm SHA256).Hash
    if ($hash -ne [string]$p.captureSha256) {
        throw "Source audit: original PCAP SHA-256 mismatch for $name."
    }
    $records=@($sample.records)
    $frames=@($p.frameNumbers)
    if ($records.Count -lt 3 -or $records.Count -ne $frames.Count -or
        $records.Count -ne [int]$p.selectedRecordCount -or
        @($frames | Sort-Object -Unique).Count -ne $frames.Count) {
        throw "Source audit: packet-to-record cardinality mismatch for $name."
    }
    $expected=@{}
    for ($i=0; $i -lt $frames.Count; $i++) {
        $frame=[int]$frames[$i]
        if ($frame -le 0 -or $expected.ContainsKey($frame)) {
            throw "Source audit: invalid frame number for $name."
        }
        $expected[$frame]=$records[$i]
    }
    $filter='dns.flags.response == 0 && (udp.dstport == 53 || tcp.dstport == 53)'
    $argsTshark=@('-n','-r',$pcap,'-Y',$filter,'-T','fields',
        '-E','separator=|','-E','quote=n','-E','occurrence=f')
    foreach ($field in $fields) { $argsTshark+=@('-e',$field) }
    $output=@(& $exe.Source @argsTshark 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw ("Source audit: tshark failed for $name : "+($output -join ' '))
    }
    $matched=[System.Collections.Generic.HashSet[int]]::new()
    foreach ($row in $output) {
        if ($row -isnot [string]) { continue }
        $cols=$row.Split('|')
        if ($cols.Length -ne 11 -or $cols[0] -notmatch '^[0-9]+$') { continue }
        $frame=[int]$cols[0]
        if (-not $expected.ContainsKey($frame)) { continue }
        if (-not $matched.Add($frame)) {
            throw "Source audit: duplicate DNS packet frame $frame in $name."
        }
        $record=$expected[$frame]
        $src=$cols[1].Trim()
        $dst=$cols[2].Trim()
        $version=4
        if (-not $src -or -not $dst) {
            $src=$cols[3].Trim(); $dst=$cols[4].Trim(); $version=6
        }
        $udp=$cols[5].Length -gt 0 -and $cols[6] -eq '53'
        $tcp=$cols[7].Length -gt 0 -and $cols[8] -eq '53'
        if ($udp -eq $tcp) {
            throw "Source audit: ambiguous transport for frame $frame in $name."
        }
        $port=if ($udp) { $cols[5] } else { $cols[7] }
        $qname=$cols[9].Trim().TrimEnd('.').ToLowerInvariant()
        $qtype=$cols[10].Trim()
        if ($port -notmatch '^[0-9]{1,5}$' -or -not $types.ContainsKey($qtype) -or
            [string]$record.source -ne $src -or
            [string]$record.destination -ne $dst -or
            [int]$record.ipVersion -ne $version -or
            [int]$record.sourcePort -ne [int]$port -or
            [int]$record.destinationPort -ne 53 -or
            [bool]$record.isUdp -ne $udp -or [bool]$record.isTcp -ne $tcp -or
            [string]$record.protocol -ne 'DNS' -or
            [string]$record.applicationProtocol -ne 'DNS' -or
            [string]$record.dnsQname -cne $qname -or
            [string]$record.dnsQtype -ne $types[$qtype] -or
            $src -ne [string]$p.sourceAddress -or
            -not ($qname -eq [string]$p.queryRoot -or
                  $qname.EndsWith('.'+[string]$p.queryRoot,[StringComparison]::Ordinal))) {
            throw "Source audit: serialized record differs from decoded PCAP frame $frame for $name."
        }
    }
    if ($matched.Count -ne $records.Count) {
        throw "Source audit: $name references missing capture frames ($($matched.Count)/$($records.Count))."
    }
    Write-Host "SOURCE AUDIT PASS: $name; $($matched.Count) packet frames verified against original PCAP SHA-256."
}
Write-Host 'SOURCE AUDIT COMPLETE: four declared R102 candidate traces have captured transport provenance.'
Write-Host 'This verifies packet attribution only, not classification truth, privacy approval or rule accuracy.'
