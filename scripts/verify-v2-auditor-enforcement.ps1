# SPDX-License-Identifier: MIT
# PARKED: requires owner approval "now it's test time". Does not run on import.
# Entirely synthetic, private, local-only four-slot V2 auditor regression.
[CmdletBinding()]
param(
    [string]$TsharkPath = 'C:\Program Files\Wireshark\tshark.exe',
    [switch]$AuthorizedTestTime
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $AuthorizedTestTime) { throw 'PARKED: explicit -AuthorizedTestTime is required, after owner permission.' }
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$auditor = Join-Path $PSScriptRoot 'audit-holdout-v2-candidates.ps1'
$manifest = Get-Content (Join-Path $root 'docs/holdout-evaluation-v2-manifest.json') -Raw | ConvertFrom-Json
$entries = @($manifest.samples | Where-Object { $_.sourceKind -eq 'external-pcap-reviewed' })
if ($entries.Count -ne 4) { throw 'Fixture contract changed: four external slots required.' }
$work = Join-Path ([IO.Path]::GetTempPath()) ('carthago-v2-auditor-' + [guid]::NewGuid().ToString('N'))
$captureDir = Join-Path $work 'captures'
$candidateDir = Join-Path $work 'candidates'
[void][IO.Directory]::CreateDirectory($captureDir)
[void][IO.Directory]::CreateDirectory($candidateDir)
function Be16([int]$n) { return ,([byte[]]@([byte](($n -shr 8) -band 255),[byte]($n -band 255))) }
function Le32([uint32]$n) { return ,([byte[]]@([byte]($n -band 255),[byte](($n -shr 8) -band 255),[byte](($n -shr 16) -band 255),[byte](($n -shr 24) -band 255))) }
function JoinBytes([byte[][]]$parts) {
    $out = [Collections.Generic.List[byte]]::new()
    foreach ($p in $parts) { $out.AddRange($p) }
    return ,$out.ToArray()
}
function QueryBytes([string]$name) {
    $out = [Collections.Generic.List[byte]]::new()
    foreach ($part in $name.Split('.')) {
        $data = [Text.Encoding]::ASCII.GetBytes($part)
        if ($data.Length -gt 63) { throw 'Synthetic label exceeds DNS bound.' }
        $out.Add([byte]$data.Length); $out.AddRange($data)
    }
    $out.Add(0); $out.AddRange((Be16 16)); $out.AddRange((Be16 1))
    return ,(JoinBytes @([byte[]]@(0x12,0x34,0x01,0x00,0x00,0x01,0,0,0,0,0,0),$out.ToArray()))
}
function UdpFrame([string]$name,[byte[]]$src,[int]$sourcePort,[int]$id) {
    $dns = QueryBytes $name
    $udp = JoinBytes @((Be16 $sourcePort),(Be16 53),(Be16 (8+$dns.Length)),[byte[]]@(0,0),$dns)
    $ip = [byte[]]@(0x45,0,0,0,0,0,0,0,64,17,0,0,0,0,0,0,198,51,100,53)
    $total = Be16 (20+$udp.Length); $ip[2]=$total[0];$ip[3]=$total[1]
    $ident = Be16 $id; $ip[4]=$ident[0];$ip[5]=$ident[1]
    [Array]::Copy($src,0,$ip,12,4)
    $sum=0
    for($j=0;$j -lt 20;$j+=2) { $sum+=($ip[$j] -shl 8) + $ip[$j+1] }
    while($sum -gt 65535) { $sum=($sum -band 65535)+($sum -shr 16) }
    $checksum=Be16 ((-bnot $sum) -band 65535)
    $ip[10]=$checksum[0];$ip[11]=$checksum[1]
    return ,(JoinBytes @($ip,$udp))
}
function NewCapture([string]$path,[string[]]$names,[byte[]]$src,[int]$slot) {
    $bytes=[Collections.Generic.List[byte]]::new()
    $bytes.AddRange([byte[]]@(0xd4,0xc3,0xb2,0xa1,2,0,4,0,0,0,0,0,0,0,0,0,0xff,0xff,0,0,0x65,0,0,0))
    for($i=0;$i -lt $names.Count;$i++) {
        $frame=UdpFrame $names[$i] $src (53000+$slot) ($slot*10+$i)
        $bytes.AddRange((Le32 ([uint32](1700000000+$i))))
        $bytes.AddRange((Le32 0));$bytes.AddRange((Le32 ([uint32]$frame.Length)))
        $bytes.AddRange((Le32 ([uint32]$frame.Length)));$bytes.AddRange($frame)
    }
    [IO.File]::WriteAllBytes($path,$bytes.ToArray())
}
function SaveJson([string]$path,[object]$value) {
    [IO.File]::WriteAllText($path,($value | ConvertTo-Json -Depth 18),[Text.UTF8Encoding]::new($false))
}
function BuildFixture([string]$scenario) {
    Get-ChildItem $captureDir -File | Remove-Item -Force
    Get-ChildItem $candidateDir -File | Remove-Item -Force
    for($slot=0;$slot -lt 4;$slot++) {
        $entry=$entries[$slot]
        $name=[IO.Path]::GetFileNameWithoutExtension([string]$entry.file)
        $malicious=$entry.classification -eq 'Malicious'
        $source='192.0.2.'+(10+$slot)
        $src=[byte[]]@(192,0,2,[byte](10+$slot))
        $rootName=if($malicious){'exfil.example'}else{'normal.example'}
        $names=@()
        for($i=0;$i -lt 3;$i++) {
            $label=if($malicious){('a' * 54)+([char](98+$slot))+([char](49+$i))}else{'validation'+$slot+$i}
            $names+=($label+'.'+$rootName)
        }
        if ($scenario -eq 'A01' -and $slot -eq 3) {
            $names=@()
            for($i=0;$i -lt 3;$i++) {
                $names+=(('a' * 54)+([char](98+2))+([char](49+$i))+'.exfil.example')
            }
        }
        $pcapFile='synthetic-slot-'+$slot+'.pcap'
        $pcap=Join-Path $captureDir $pcapFile
        NewCapture $pcap $names $src $slot
        $hash=(Get-FileHash $pcap -Algorithm SHA256).Hash.ToLowerInvariant()
        $records=@()
        foreach($q in $names) {
            $records+=@{source=$source;destination='198.51.100.53';ipVersion=4;sourcePort=(53000+$slot);destinationPort=53;protocol='DNS';applicationProtocol='DNS';isUdp=$true;isTcp=$false;dnsQname=$q;dnsQtype='TXT'}
        }
        $sample=[ordered]@{name=$name;classification=[string]$entry.classification;records=$records;expectedMatches=$(if($malicious){@('R102')}else{@()});expectedNonMatches=$(if($malicious){@('R118','R163')}else{@('R102','R118','R163')});expectedMinimumConfidence=$(if($malicious){0.75}else{0.0})}
        $p=[ordered]@{sample=$name;classification=[string]$entry.classification;sourceKind='external-pcap-reviewed';analystReviewedLabel=$true;capturedTransportEvidence=$true;independentLabelBasis='synthetic-only';sourceUri='https://example.org/synthetic';sourceLicenseEvidenceUri='https://example.org/synthetic-rights';sourceLicense='CC0-1.0';captureFileName=$pcapFile;captureSha256=$hash;sourceAddress=$source;queryRoot=$rootName;frameNumbers=@(1,2,3);selectedRecordCount=3;originatingClientLabel=('synthetic-origin-'+$slot);collectionSessionId=('synthetic-session-'+$slot);collectionVantage='client'}
        if($scenario -eq 'A02' -and $slot -eq 3){$p.collectionSessionId='synthetic-session-2'}
        if($scenario -eq 'A03' -and $slot -eq 3){$p.originatingClientLabel='synthetic-origin-2'}
        if($scenario -eq 'A06' -and $slot -eq 2){$sample.records[0].dnsQname='tampered.example'}
        if($scenario -eq 'A09' -and $slot -eq 2){$p.captureSha256=('0'*64)}
        if($scenario -eq 'A11' -and $slot -eq 2){$p.analystReviewedLabel=$false}
        if($scenario -eq 'A12' -and $slot -eq 2){$sample.records[0].unreviewedPrivate='forbidden'}
        if($scenario -eq 'A14' -and $slot -eq 2){$sample.expectedMatches=@('R118')}
        SaveJson (Join-Path $candidateDir ($name+'.json')) $sample
        SaveJson (Join-Path $candidateDir ($name+'.provenance.json')) $p
    }
}
function InvokeAudit([string]$scenario,[bool]$expectReject) {
    BuildFixture $scenario
    $output=Join-Path $work 'private-auditor.log'
    & powershell.exe -NoProfile -NonInteractive -File $auditor -CaptureDirectory $captureDir -CandidateDirectory $candidateDir -TsharkPath $TsharkPath *> $output
    $exit=$LASTEXITCODE
    $rejected=$exit -ne 0
    # Error and success output must remain local; never print frame or QNAME data.
    if($rejected -ne $expectReject){
        throw ('AUDITOR CONTRACT FAIL: '+$scenario+' expectedReject='+$expectReject+' actualRejected='+$rejected+'; private log retained only until cleanup')
    }
    Write-Host ('AUDITOR CONTRACT: '+$scenario+' observed expected exit category.')
}
try {
    if(-not (Test-Path -LiteralPath $auditor)) { throw 'Auditor entry point unavailable.' }
    if(-not (Test-Path -LiteralPath $TsharkPath)) { throw 'TShark unavailable; cannot claim expected RED.' }
    # Baseline is an attribution-only control, not a source-label approval.
    InvokeAudit 'BASELINE' $false
    # A01–A03 are expected RED against legacy IP-only independence checks.
    foreach($scenario in @('A01','A02','A03','A06','A09','A11','A12','A14')) {
        InvokeAudit $scenario $true
    }
    Write-Host 'Synthetic auditor regression gate completed. No source approved or holdout frozen.'
} finally {
    if(Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Force -Recurse }
}
