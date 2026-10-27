# SPDX-License-Identifier: MIT
# Read-only DNS packet suitability inspection; this is NOT Carthago testing,
# ground truth labeling, source validation or a holdout freeze.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CapturePath,
    [string]$DnsRoot='',
    [switch]$ShowSourceAddresses,
    [switch]$ShowDnsRoots,
    [int]$MaximumPacketsToScan=100000,
    [string]$TsharkPath='tshark',
    [string]$OutputDirectory='build-verify/holdout-v2-profiles'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$capture=(Resolve-Path -LiteralPath $CapturePath).Path
$exe=Get-Command $TsharkPath -ErrorAction Stop
if ($MaximumPacketsToScan -lt 100 -or $MaximumPacketsToScan -gt 500000) {
    throw 'MaximumPacketsToScan must be 100..500000.'
}
$domain=$DnsRoot.Trim().Trim('.').ToLowerInvariant()
if ($domain.Length -gt 0 -and
    $domain -notmatch '^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$') {
    throw 'DnsRoot must be a valid multi-label suffix.'
}
$fields=@('frame.number','ip.src','ip.dst','ipv6.src','ipv6.dst',
    'udp.srcport','udp.dstport','tcp.srcport','tcp.dstport','dns.qry.name','dns.qry.type')
$argsTshark=@('-n','-r',$capture,'-c',"$MaximumPacketsToScan",'-Y',
    'dns.flags.response == 0 && (udp.dstport == 53 || tcp.dstport == 53)',
    '-T','fields','-E','separator=|','-E','quote=n','-E','occurrence=f')
foreach ($f in $fields) { $argsTshark+=@('-e',$f) }
$rows=@(& $exe.Source @argsTshark 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw ('Could not decode PCAP with tshark: '+($rows -join ' '))
}
$types=@{'1'='A';'28'='AAAA';'16'='TXT';'5'='CNAME';'15'='MX';'12'='PTR';'2'='NS';'33'='SRV';'6'='SOA';'10'='NULL'}
$groups=@{}
$seenFrames=[System.Collections.Generic.HashSet[int]]::new()
$skipped=0
foreach ($row in $rows) {
    if ($row -isnot [string]) { $skipped++; continue }
    $c=$row.Split('|')
    if ($c.Length -ne 11 -or $c[0] -notmatch '^[0-9]+$') { $skipped++; continue }
    $frame=[int]$c[0]
    if (-not $seenFrames.Add($frame)) { $skipped++; continue }
    $src=$c[1].Trim(); $dst=$c[2].Trim()
    if (-not $src -or -not $dst) { $src=$c[3].Trim(); $dst=$c[4].Trim() }
    $udp=$c[5].Length -gt 0 -and $c[6] -eq '53'
    $tcp=$c[7].Length -gt 0 -and $c[8] -eq '53'
    $qname=$c[9].Trim().TrimEnd('.').ToLowerInvariant()
    $type=$c[10].Trim()
    if (-not $src -or -not $dst -or $udp -eq $tcp -or
        -not $types.ContainsKey($type) -or
        $qname.Length -gt 253 -or
        $qname -notmatch '^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$') {
        $skipped++; continue
    }
    $labels=$qname.Split('.')
    foreach ($label in $labels) {
        if ($label.Length -gt 63 -or $label.Length -eq 0) {
            $qname=''; break
        }
    }
    if (-not $qname) { $skipped++; continue }
    $suffix=$domain
    if ($suffix.Length -gt 0) {
        if (-not ($qname -eq $suffix -or
                  $qname.EndsWith('.'+$suffix,[StringComparison]::Ordinal))) {
            continue
        }
    } else {
        # Two-label grouping is only for inspection, not the detector's
        # public-suffix-aware RootDomain calculation.
        $suffix=$labels[$labels.Length-2]+'.'+$labels[$labels.Length-1]
    }
    $key=$src+'|'+$suffix
    if (-not $groups.ContainsKey($key)) {
        $groups[$key]=[System.Collections.Generic.List[object]]::new()
    }
    $longest=($labels | Measure-Object -Maximum -Property Length).Maximum
    $groups[$key].Add([pscustomobject]@{
        Frame=$frame;Source=$src;Root=$suffix;Qname=$qname;Type=$types[$type];
        Udp=$udp;Tcp=$tcp;LongestLabelLength=[int]$longest
    })
}
$profiles=[System.Collections.Generic.List[object]]::new()
$ordinal=0
foreach ($key in @($groups.Keys | Sort-Object)) {
    $observations=@($groups[$key].ToArray())
    $ordinal++
    $txt=@($observations | Where-Object { $_.Type -eq 'TXT' })
    $encoded=@($txt | Where-Object { $_.LongestLabelLength -ge 50 })
    $distinctTxt=@($txt | Select-Object -ExpandProperty Qname -Unique).Count
    $distinctEncoded=@($encoded | Select-Object -ExpandProperty Qname -Unique).Count
    $clientLabel='Client-'+('{0:000}' -f $ordinal)
    $profile=[ordered]@{
        client=$clientLabel
        domain=$(if ($ShowDnsRoots) { $observations[0].Root } else { 'Domain-'+('{0:000}' -f $ordinal) })
        recordCount=$observations.Count
        uniqueFrameCount=@($observations | Select-Object -ExpandProperty Frame -Unique).Count
        txtQueries=$txt.Count
        distinctTxtNames=$distinctTxt
        distinctLongTxtNames=$distinctEncoded
        aQueries=@($observations | Where-Object { $_.Type -eq 'A' }).Count
        aaaaQueries=@($observations | Where-Object { $_.Type -eq 'AAAA' }).Count
        udpCount=@($observations | Where-Object { $_.Udp }).Count
        tcpCount=@($observations | Where-Object { $_.Tcp }).Count
        maximumDnsLabelLength=@($observations | Measure-Object -Property LongestLabelLength -Maximum)[0].Maximum
        meetsBasicThreeDistinctLongTxtShape=($distinctEncoded -ge 3)
    }
    if ($ShowSourceAddresses) { $profile.sourceAddress=$observations[0].Source }
    $profiles.Add($profile)
}
$dir=[IO.Path]::GetFullPath((Join-Path $root $OutputDirectory))
$privateRoot=[IO.Path]::GetFullPath((Join-Path $root 'build-verify'))
if (-not $dir.StartsWith($privateRoot+[IO.Path]::DirectorySeparatorChar,
                        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Inspection profiles must remain under the private build-verify directory.'
}
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$stem=[IO.Path]::GetFileNameWithoutExtension($capture)
$destination=Join-Path $dir ($stem+'-'+[Guid]::NewGuid().ToString('N')+'.json')
$summary=[ordered]@{
    schemaVersion=1
    captureFileName=[IO.Path]::GetFileName($capture)
    captureSha256=(Get-FileHash -LiteralPath $capture -Algorithm SHA256).Hash.ToLowerInvariant()
    tsharkVersion=((& $exe.Source -v | Select-Object -First 1) -join '')
    filterRoot=$(if ($domain) { $domain } else { '(approximate last two labels)' })
    maximumPacketsToScan=$MaximumPacketsToScan
    analysisMayBeTruncated=$true
    rawSourceAddressesIncluded=[bool]$ShowSourceAddresses
    rawDnsRootsIncluded=[bool]$ShowDnsRoots
    distinctSourceRootGroups=$profiles.Count
    skippedOrInvalidFrames=$skipped
    groups=@($profiles.ToArray())
    candidateSuitabilityOnly=$true
    independentMaliciousLabelsVerified=$false
    licenseAndPrivacyReviewed=$false
}
[IO.File]::WriteAllText($destination,
    (($summary | ConvertTo-Json -Depth 15)+[Environment]::NewLine),
    [Text.UTF8Encoding]::new($false))
Write-Host ("Source inspection: {0} DNS source/root group(s), {1} skipped/invalid frame(s)." -f $profiles.Count,$skipped)
Write-Host ("Groups with >=3 distinct long TXT QNAMEs: {0}" -f @($profiles | Where-Object { $_.meetsBasicThreeDistinctLongTxtShape }).Count)
Write-Host "Privacy-conscious local report: $destination"
Write-Host 'Raw QNAMEs are not exported; source IPs and DNS roots are hidden unless explicitly requested.'
Write-Host "At most $MaximumPacketsToScan input packets were scanned; this is not a whole-capture coverage claim."
Write-Host 'No alert evaluation, label approval, corpus change or test was performed.'
