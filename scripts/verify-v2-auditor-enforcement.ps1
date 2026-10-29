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
# Fixture mutation indices assume the current manifest's two benign, then two
# malicious R102 slots. Fail closed if the manifest ever changes its ordering.
$classes = (@($entries | ForEach-Object { [string]$_.classification }) -join ',')
if ($classes -cne 'Benign,Benign,Malicious,Malicious') {
    throw 'Fixture contract changed: expected ordered 2 benign and 2 malicious slots.'
}
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
        # A16: three captured TXT questions remain frame-aligned but include
        # only two *distinct* long labels. Do not fabricate a JSON-only mismatch.
        if($scenario -eq 'A16-distinct' -and $slot -eq 2) {
            $names[2] = $names[1]
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
        if($scenario -eq 'A08-qtype' -and $slot -eq 2){$sample.records[0]['dnsQtype']='A'}
        if($scenario -eq 'A08-port' -and $slot -eq 2){$sample.records[0]['sourcePort']=53042}
        if($scenario -eq 'A09' -and $slot -eq 2){$p.captureSha256=('0'*64)}
        if($scenario -eq 'A10' -and $slot -eq 2){$p.collectionVantage='unattributed-proxy'}
        if($scenario -eq 'A11' -and $slot -eq 2){$p.analystReviewedLabel=$false}
        if($scenario -eq 'A11-license' -and $slot -eq 2){$p.sourceLicense='Unlicensed'}
        if($scenario -eq 'A12' -and $slot -eq 2){$sample.records[0]['unreviewedPrivate']='forbidden'}
        if($scenario -eq 'A14' -and $slot -eq 2){$sample.expectedMatches=@('R118')}
        SaveJson (Join-Path $candidateDir ($name+'.json')) $sample
        SaveJson (Join-Path $candidateDir ($name+'.provenance.json')) $p
    }
    if($scenario -eq 'A04') {
        # Reuse the exact benign slot-0 PCAP bytes and records for benign slot 1,
        # retaining distinct *sample identifiers*. This isolates the global
        # (capture hash, frame) replay defense from malicious IP uniqueness.
        $firstName=[IO.Path]::GetFileNameWithoutExtension([string]$entries[0].file)
        $secondName=[IO.Path]::GetFileNameWithoutExtension([string]$entries[1].file)
        $oneSamplePath=Join-Path $candidateDir ($firstName+'.json')
        $twoSamplePath=Join-Path $candidateDir ($secondName+'.json')
        $oneProvPath=Join-Path $candidateDir ($firstName+'.provenance.json')
        $twoProvPath=Join-Path $candidateDir ($secondName+'.provenance.json')
        $originalSample=Get-Content $oneSamplePath -Raw | ConvertFrom-Json
        $mutatedSample=Get-Content $twoSamplePath -Raw | ConvertFrom-Json
        $originalProv=Get-Content $oneProvPath -Raw | ConvertFrom-Json
        $mutatedProv=Get-Content $twoProvPath -Raw | ConvertFrom-Json
        Copy-Item -LiteralPath (Join-Path $captureDir 'synthetic-slot-0.pcap') -Destination (Join-Path $captureDir 'synthetic-slot-1.pcap') -Force
        $mutatedSample.records=$originalSample.records
        $mutatedProv.captureSha256=$originalProv.captureSha256
        $mutatedProv.sourceAddress=$originalProv.sourceAddress
        $mutatedProv.queryRoot=$originalProv.queryRoot
        $mutatedProv.frameNumbers=$originalProv.frameNumbers
        SaveJson $twoSamplePath $mutatedSample
        SaveJson $twoProvPath $mutatedProv
    }
    if($scenario -eq 'A09-missing') {
        Remove-Item -LiteralPath (Join-Path $captureDir 'synthetic-slot-2.pcap') -Force
    }
}
function Get-ExpectedReason([string]$scenario) {
    # A rejection for an unrelated parser/TShark/fixture error must never
    # be credited as a successful negative control or security RED.
    switch ($scenario) {
        'A01'          { return 'SOURCE_INDEPENDENCE_MIRROR' }
        'A02'          { return 'SOURCE_SESSION_COLLISION' }
        'A03'          { return 'SOURCE_ORIGIN_COLLISION' }
        'A04'          { return 'same original PCAP packet frame reused' }
        'A06'          { return 'serialized record differs from decoded PCAP' }
        'A08-qtype'    { return 'serialized record differs from decoded PCAP' }
        'A08-port'     { return 'serialized record differs from decoded PCAP' }
        'A09'          { return 'original PCAP SHA-256 mismatch' }
        'A09-missing'  { return 'original capture missing' }
        'A10'          { return 'SOURCE_VANTAGE_UNREVIEWED' }
        'A11'          { return 'incomplete external attribution or label review' }
        'A11-license'  { return 'incomplete external attribution or label review' }
        'A12'          { return 'DNS packet record has missing, extra or invalid typed fields' }
        'A14'          { return 'R102 malicious expected rule/confidence was altered' }
        'A16-distinct' { return 'R102 malicious encoded-TXT requires three distinct captured TXT' }
        default        { throw 'Unexpected auditor regression scenario.' }
    }
}
function Assert-PrivateAuditOutput([string]$log) {
    # Never publish captured records; scan only the temporary private output.
    foreach($entry in $entries) {
        $name=[IO.Path]::GetFileNameWithoutExtension([string]$entry.file)
        $sample=Get-Content -LiteralPath (Join-Path $candidateDir ($name+'.json')) -Raw | ConvertFrom-Json
        $provenance=Get-Content -LiteralPath (Join-Path $candidateDir ($name+'.provenance.json')) -Raw | ConvertFrom-Json
        foreach($secret in @([string]$provenance.sourceAddress,'198.51.100.53')) {
            if(-not [string]::IsNullOrWhiteSpace($secret) -and
               $log.IndexOf($secret,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
                throw 'AUDITOR PRIVACY FAIL: raw source/destination address in child output.'
            }
        }
        foreach($record in @($sample.records)) {
            $secret=[string]$record.dnsQname
            if(-not [string]::IsNullOrWhiteSpace($secret) -and
               $log.IndexOf($secret,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
                throw 'AUDITOR PRIVACY FAIL: reversible DNS name in child output.'
            }
        }
    }
}
function InvokeAudit([string]$scenario,[bool]$expectReject) {
    BuildFixture $scenario
    $output=Join-Path $work 'private-auditor.log'
    & powershell.exe -NoProfile -NonInteractive -File $auditor -CaptureDirectory $captureDir -CandidateDirectory $candidateDir -TsharkPath $TsharkPath *> $output
    $exit=$LASTEXITCODE
    $log=Get-Content -LiteralPath $output -Raw
    Assert-PrivateAuditOutput $log
    $rejected=$exit -ne 0
    if($rejected -ne $expectReject) {
        # No unredacted child output, path, PCAP content or DNS values printed.
        throw ('AUDITOR CONTRACT FAIL: '+$scenario+' wrong exit category; private log is local and ephemeral.')
    }
    if($expectReject) {
        $expectedReason=Get-ExpectedReason $scenario
        if($log.IndexOf($expectedReason,[StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw ('AUDITOR CONTRACT FAIL: '+$scenario+' rejected for an unexpected reason; do not count as RED or GREEN.')
        }
    } else {
        if($log.IndexOf('SOURCE AUDIT COMPLETE:',[StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw ('AUDITOR CONTRACT FAIL: '+$scenario+' exited zero without an attribution-only completion statement.')
        }
        # A clean provenance review is NOT a human classification or source
        # independence decision. No success output may claim promotion/freeze.
        if($log -match '(?i)\b(approved|promoted|frozen|independence verified)\b') {
            throw 'AUDITOR CONTRACT FAIL: synthetic attribution misrepresented as approval.'
        }
    }
    Write-Host ('AUDITOR CONTRACT: '+$scenario+' observed expected exit category and reason; private output checked.')
}

try {
    if(-not (Test-Path -LiteralPath $auditor)) { throw 'Auditor entry point unavailable.' }
    if(-not (Test-Path -LiteralPath $TsharkPath)) { throw 'TShark unavailable; cannot claim expected RED.' }
    # Baseline is an attribution-only control, not a source-label approval.
    InvokeAudit 'BASELINE' $false
    # Disjoint sources remain review-only: success is *not* approval.
    InvokeAudit 'A13' $false
    # A01/A02/A03/A10 expect new stable privacy-safe reason codes and will
    # fail under the legacy auditor until its enforcement is implemented.
    foreach($scenario in @(
        'A01','A02','A03','A04','A06','A08-qtype','A08-port',
        'A09','A09-missing','A10','A11','A11-license','A12','A14',
        'A16-distinct')) {
        InvokeAudit $scenario $true
    }
    Write-Host 'Synthetic auditor regression gate completed. No source approved or holdout frozen.'
} finally {
    if(Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Force -Recurse }
}
