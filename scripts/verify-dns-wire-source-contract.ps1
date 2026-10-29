# SPDX-License-Identifier: MIT
# PARKED CONTRACT: do not execute without the owner's explicit test-time approval.
# Generates an entirely synthetic, temporary PCAP. No private capture, DNS name,
# source address or reversible label is written to the console or repository.
[CmdletBinding()]
param(
    [string]$TsharkPath = 'tshark',
    # Stage 6 is separately parked: leave Stage 5's RED/GREEN scope stable.
    [switch]$IncludeV2Provenance
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Contract([bool]$Condition, [string]$Code) {
    if (-not $Condition) { throw "DNS wire source contract: $Code" }
}

function Convert-HexToBytes([string]$Value) {
    $hex = $Value -replace '\s', ''
    Assert-Contract (($hex.Length % 2) -eq 0) 'invalid-synthetic-vector'
    $bytes = New-Object byte[] ($hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
    }
    return ,$bytes
}

function Join-Bytes([byte[][]]$Parts) {
    $result = [System.Collections.Generic.List[byte]]::new()
    foreach ($part in $Parts) { $result.AddRange($part) }
    return ,$result.ToArray()
}

function Convert-UInt16BigEndian([int]$Value) {
    Assert-Contract ($Value -ge 0 -and $Value -le 65535) 'synthetic-length-overflow'
    return ,([byte[]]@([byte]($Value -shr 8), [byte]($Value -band 255)))
}

function Convert-UInt32LittleEndian([uint32]$Value) {
    return ,([byte[]]@(
        [byte]($Value -band 255), [byte](($Value -shr 8) -band 255),
        [byte](($Value -shr 16) -band 255), [byte](($Value -shr 24) -band 255)))
}

function New-Ipv4Frame([byte]$Protocol, [byte[]]$Payload, [int]$Identification) {
    $header = New-Object byte[] 20
    $header[0] = 0x45; $header[1] = 0
    $totalLength = Convert-UInt16BigEndian (20 + $Payload.Length)
    $header[2] = $totalLength[0]; $header[3] = $totalLength[1]
    $id = Convert-UInt16BigEndian $Identification
    $header[4] = $id[0]; $header[5] = $id[1]
    $header[8] = 64; $header[9] = $Protocol
    $addresses = Convert-HexToBytes 'c000020ac6336435'
    for ($i = 0; $i -lt $addresses.Length; $i++) {
        $header[12 + $i] = $addresses[$i]
    }
    $sum = 0
    for ($i = 0; $i -lt 20; $i += 2) {
        $sum += (($header[$i] -shl 8) -bor $header[$i + 1])
    }
    while ($sum -gt 65535) { $sum = ($sum -band 65535) + ($sum -shr 16) }
    $checksum = Convert-UInt16BigEndian ((-bnot $sum) -band 65535)
    $header[10] = $checksum[0]; $header[11] = $checksum[1]
    return ,(Join-Bytes @($header, $Payload))
}

function New-UdpDnsFrame([byte[]]$DnsMessage, [int]$FrameId) {
    $udp = New-Object byte[] 8
    $sourcePort = Convert-UInt16BigEndian (53000 + $FrameId)
    $udp[0] = $sourcePort[0]; $udp[1] = $sourcePort[1]
    $udp[2] = 0; $udp[3] = 53
    $udpLength = Convert-UInt16BigEndian (8 + $DnsMessage.Length)
    $udp[4] = $udpLength[0]; $udp[5] = $udpLength[1]
    return ,(New-Ipv4Frame 17 (Join-Bytes @($udp, $DnsMessage)) $FrameId)
}

function New-TcpDnsFrame([byte[]]$DnsMessage, [int]$FrameId) {
    $tcp = New-Object byte[] 20
    $tcp[0] = 0xcf; $tcp[1] = 0x0a # synthetic source port 53002
    $tcp[2] = 0; $tcp[3] = 53
    $tcp[7] = 1; $tcp[11] = 1
    $tcp[12] = 0x50; $tcp[13] = 0x18; $tcp[14] = 0x10
    $framedDns = Join-Bytes @((Convert-UInt16BigEndian $DnsMessage.Length), $DnsMessage)
    return ,(New-Ipv4Frame 6 (Join-Bytes @($tcp, $framedDns)) $FrameId)
}

function Write-SyntheticPcap([string]$Path, [byte[][]]$Frames) {
    # PCAP v2.4, little-endian, DLT_RAW (101). Fixed timestamps/headers make
    # this capture deterministic across test runs and avoid link-layer noise.
    $data = [System.Collections.Generic.List[byte]]::new()
    $data.AddRange((Convert-HexToBytes 'd4c3b2a1020004000000000000000000ffff000065000000'))
    for ($i = 0; $i -lt $Frames.Length; $i++) {
        $frame = $Frames[$i]
        $data.AddRange((Convert-UInt32LittleEndian ([uint32](1700000000 + $i))))
        $data.AddRange((Convert-UInt32LittleEndian 0))
        $data.AddRange((Convert-UInt32LittleEndian ([uint32]$frame.Length)))
        $data.AddRange((Convert-UInt32LittleEndian ([uint32]$frame.Length)))
        $data.AddRange($frame)
    }
    [IO.File]::WriteAllBytes($Path, $data.ToArray())
}

function Assert-PrivateQuestion(
    [string]$Path, [string]$Hash, [int]$Frame, [int]$Ordinal,
    [string[]]$ExpectedLabels, [int]$Qtype, [string]$Transport,
    [string]$Tshark
) {
    # The eventual helper is a black box here: expected values are literal
    # fixture vectors, never computed by the helper being tested.
    $items = @(Read-DnsWireQuestion -CapturePath $Path -FrameNumber $Frame `
        -QuestionIndex $Ordinal -TsharkPath $Tshark 6>&1)
    Assert-Contract ($items.Count -eq 1 -and $items[0] -is [pscustomobject]) 'unexpected-helper-output'
    $actual = $items[0]
    Assert-Contract ([string]$actual.CaptureSha256 -eq $Hash) 'capture-sha-mismatch'
    Assert-Contract ([int]$actual.FrameNumber -eq $Frame) 'frame-provenance-mismatch'
    Assert-Contract ([int]$actual.QuestionIndex -eq $Ordinal) 'ordinal-provenance-mismatch'
    Assert-Contract ([int]$actual.Qtype -eq $Qtype) 'qtype-mismatch'
    Assert-Contract ([string]$actual.Transport -eq $Transport) 'transport-mismatch'
    $expectedPort = if ($Transport -eq 'TCP') { 53002 } else { 53000 + $Frame }
    Assert-Contract ([int]$actual.SourcePort -eq $expectedPort -and
        [int]$actual.DestinationPort -eq 53) 'port-attribution-mismatch'
    Assert-Contract ([string]$actual.SourceAddress -eq '192.0.2.10') 'source-attribution-mismatch'
    Assert-Contract ([string]$actual.DestinationAddress -eq '198.51.100.53') 'destination-attribution-mismatch'
    $labels = @($actual.DnsWireLabelsBase64)
    Assert-Contract ($labels.Count -eq $ExpectedLabels.Count) 'label-count-mismatch'
    for ($i = 0; $i -lt $labels.Count; $i++) {
        Assert-Contract ([string]$labels[$i] -ceq $ExpectedLabels[$i]) 'label-octets-mismatch'
    }
}

function Assert-QuestionRejected([string]$Path, [int]$Frame, [int]$Ordinal, [string]$Tshark) {
    $rejected = $false
    try {
        $unexpected = @(Read-DnsWireQuestion -CapturePath $Path `
            -FrameNumber $Frame -QuestionIndex $Ordinal -TsharkPath $Tshark 6>&1)
    } catch {
        $rejected = $true
        $details = [string]$_.Exception.Message
        # Failure reasons must be metadata-only even for corrupt questions.
        Assert-Contract (-not ($details -match 'QS7/|YmFzZQ|192\.0\.2\.|198\.51\.100\.|\\[0-9]{3}')) 'private-value-in-error'
    }
    Assert-Contract $rejected 'malformed-or-ambiguous-question-accepted'
}

function Assert-CandidateRejected(
    [string]$Path, [object]$Provenance, [object[]]$Records, [string]$Tshark
) {
    $rejected = $false
    try {
        $unexpected = @(Confirm-DnsWireCandidateBinding -CapturePath $Path `
            -Provenance $Provenance -Records $Records -TsharkPath $Tshark 6>&1)
    } catch {
        $rejected = $true
        $details = [string]$_.Exception.Message
        Assert-Contract (-not ($details -match 'QS7/|YmFzZQ|YWxwaGE=|192\.0\.2\.|198\.51\.100\.')) 'candidate-error-leaks-private-value'
    }
    Assert-Contract $rejected 'tampered-candidate-evidence-accepted'
}

function Assert-Stage6CandidateEvidence([string]$Path, [string]$Hash, [string]$Tshark) {
    # Proposed Task 6 boundary: the V2 importer and auditor must use this
    # shared original-frame/ordinal binding check before accepting a record.
    # This checks data fidelity only; no label/rights/client is approved here.
    Assert-Contract ($null -ne (Get-Command Confirm-DnsWireCandidateBinding -ErrorAction SilentlyContinue)) `
        'candidate-binding-not-implemented-red'
    $reference = [pscustomobject]@{
        provenance = [pscustomobject]@{
            captureSha256 = $Hash
            dnsWireNameEncoding = 'labels-base64-v1'
            frameNumbers = [int[]]@(1, 2)
            questionIndices = [int[]]@(0, 1)
            originatingClientLabel = 'synthetic-client-a'
            collectionSessionId = 'synthetic-session-1'
            collectionVantage = 'client'
            independentClientEvidenceUri = 'https://example.org/review-pending'
        }
        records = @(
            [pscustomobject]@{
                source = '192.0.2.10'; destination = '198.51.100.53'
                ipVersion = 4; sourcePort = 53001; destinationPort = 53
                isUdp = $true; isTcp = $false; dnsQtype = 'TXT'
                dnsWireLabelsBase64 = [string[]]@('QS7/', 'YmFzZQ==')
            },
            [pscustomobject]@{
                source = '192.0.2.10'; destination = '198.51.100.53'
                ipVersion = 4; sourcePort = 53002; destinationPort = 53
                isUdp = $true; isTcp = $false; dnsQtype = 'A'
                dnsWireLabelsBase64 = [string[]]@('YWxwaGE=', 'ZXhhbXBsZQ==')
            }
        )
    }
    $verified = @(Confirm-DnsWireCandidateBinding -CapturePath $Path `
        -Provenance $reference.provenance -Records $reference.records -TsharkPath $Tshark 6>&1)
    Assert-Contract ($verified.Count -eq 1 -and $verified[0] -is [pscustomobject]) 'candidate-helper-output-shape'
    Assert-Contract ([int]$verified[0].MatchedQuestionCount -eq 2) 'candidate-question-count-mismatch'
    Assert-Contract ([string]$verified[0].CaptureSha256 -eq $Hash) 'candidate-hash-binding-mismatch'
    Assert-Contract ($verified[0].PSObject.Properties.Name -notcontains 'DnsWireLabelsBase64') 'candidate-output-discloses-raw-labels'
    Assert-Contract ($verified[0].PSObject.Properties.Name -notcontains 'SourceAddress') 'candidate-output-discloses-source'

    # Every rejection uses a fresh JSON deep copy so tests cannot mutate the
    # reference or accidentally share a partly accepted record collection.
    $cases = @(
        { param($x) $x.provenance.captureSha256 = '00' * 32 },
        { param($x) $x.provenance.frameNumbers[0] = 2 },
        { param($x) $x.provenance.questionIndices[1] = 0 },
        { param($x) $x.provenance.questionIndices = @(0) },
        { param($x) $x.provenance.dnsWireNameEncoding = 'labels-base64-v0' },
        { param($x) $x.records[0].dnsWireLabelsBase64[0] = 'QS7+' },
        { param($x) $x.records[0].dnsWireLabelsBase64[0] = 'AR==' },
        { param($x) $x.records[0].dnsQtype = 'A' },
        { param($x) $x.records[0].source = '192.0.2.11' },
        { param($x) $x.records[0].sourcePort = 53042 },
        { param($x) $x.records[0].isUdp = $false },
        { param($x) $x.records[0].isTcp = $true },
        { param($x) $x.provenance.frameNumbers[1] = 1; $x.provenance.questionIndices[1] = 0 },
        { param($x) $x.provenance.originatingClientLabel = '' },
        { param($x) $x.provenance.collectionSessionId = '' },
        { param($x) $x.provenance.collectionVantage = 'unattributed-proxy' },
        { param($x) $x.provenance.independentClientEvidenceUri = 'http://example.org/unreviewed' },
        { param($x) $x.records[0] | Add-Member -NotePropertyName 'dnsWireUnreviewedDebug' -NotePropertyValue 'private' }
    )
    foreach ($change in $cases) {
        $mutant = ConvertFrom-Json -InputObject ($reference | ConvertTo-Json -Depth 12)
        & $change $mutant
        Assert-CandidateRejected $Path $mutant.provenance @($mutant.records) $Tshark
    }
    # A missing original PCAP never falls back to trusting JSON-only fields.
    Assert-CandidateRejected (Join-Path (Split-Path $Path) 'missing-original.pcap') `
        $reference.provenance @($reference.records) $Tshark
    Write-Host 'V2 frame/question binding contract: two source-bound records; nineteen tampering/missing-original cases rejected. Source syntax only.'
}

function New-SyntheticLogicalSource(
    [string]$Hash, [string]$Origin, [string]$Session, [string]$Address,
    [int[]]$Frames, [string[]]$FirstLabels, [string]$RootLabel = 'ZXhhbXBsZQ=='
) {
    Assert-Contract ($Frames.Count -eq $FirstLabels.Count) 'logical-source-fixture-cardinality'
    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($label in $FirstLabels) {
        $records.Add([pscustomobject]@{
            dnsWireLabelsBase64 = [string[]]@($label, $RootLabel)
            dnsQtype = 'TXT'
        })
    }
    return [pscustomobject]@{
        provenance = [pscustomobject]@{
            captureSha256 = $Hash
            sourceAddress = $Address
            frameNumbers = $Frames
            questionIndices = [int[]]@(0, 0, 0)
            originatingClientLabel = $Origin
            collectionSessionId = $Session
            collectionVantage = 'client'
            independentClientEvidenceUri = 'https://example.org/synthetic-review-only'
        }
        records = @($records.ToArray())
    }
}

function Assert-SourceReviewResult(
    [object[]]$Candidates, [bool]$Mirrored, [bool]$SharedSession,
    [bool]$SameOrigin, [bool]$ReusedFrame, [int]$Overlap
) {
    # This is a review-risk classifier, not an independence approval API.
    $items = @(Measure-DnsWireMaliciousSourceIndependence -Candidates $Candidates 6>&1)
    Assert-Contract ($items.Count -eq 1 -and $items[0] -is [pscustomobject]) 'source-review-output-shape'
    $result = $items[0]
    Assert-Contract ([bool]$result.CompleteNameSetOverlap -eq $Mirrored) 'source-mirror-risk-mismatch'
    Assert-Contract ([bool]$result.SharedCollectionSession -eq $SharedSession) 'source-session-risk-mismatch'
    Assert-Contract ([bool]$result.SameOriginatingClient -eq $SameOrigin) 'source-client-risk-mismatch'
    Assert-Contract ([bool]$result.ReusedOriginalFrame -eq $ReusedFrame) 'source-frame-reuse-risk-mismatch'
    Assert-Contract ([int]$result.OverlappingDistinctNameCount -eq $Overlap) 'source-name-overlap-count-mismatch'
    Assert-Contract ([bool]$result.RequiresAnalystReview) 'source-review-gate-bypassed'
    Assert-Contract (-not [bool]$result.IndependenceApproved) 'source-syntax-auto-approved'
    $summary = $result | ConvertTo-Json -Depth 8 -Compress
    foreach ($candidate in $Candidates) {
        foreach ($privateValue in @(
            $candidate.provenance.sourceAddress,
            $candidate.provenance.originatingClientLabel,
            $candidate.provenance.collectionSessionId)) {
            Assert-Contract (-not $summary.Contains([string]$privateValue)) `
                'source-review-output-exposes-private-attribution'
        }
        foreach ($record in @($candidate.records)) {
            foreach ($label in @($record.dnsWireLabelsBase64)) {
                Assert-Contract (-not $summary.Contains([string]$label)) `
                    'source-review-output-exposes-reversible-name'
            }
        }
    }
}

function Assert-Stage6LogicalSourceIndependence() {
    Assert-Contract ($null -ne (Get-Command Measure-DnsWireMaliciousSourceIndependence -ErrorAction SilentlyContinue)) `
        'logical-source-review-not-implemented-red'
    # Names and provenance are entirely synthetic. This check must identify
    # a mirrored DNS-name SET independently of source-IP and packet order.
    $first = New-SyntheticLogicalSource ('11' * 32) 'client-one' 'session-one' `
        '192.0.2.10' @(101, 102, 103) @('YQ==', 'Yg==', 'Yw==')
    $mirrored = New-SyntheticLogicalSource ('22' * 32) 'client-two' 'session-two' `
        '192.0.2.11' @(201, 202, 203) @('Qw==', 'Qg==', 'QQ==') 'RVhBTVBMRQ=='
    Assert-SourceReviewResult @($first, $mirrored) $true $false $false $false 3

    $disjoint = New-SyntheticLogicalSource ('22' * 32) 'client-two' 'session-two' `
        '192.0.2.11' @(201, 202, 203) @('eA==', 'eQ==', 'eg==')
    # A lack of overlap is never sufficient for automatic source approval.
    Assert-SourceReviewResult @($first, $disjoint) $false $false $false $false 0

    $partial = New-SyntheticLogicalSource ('22' * 32) 'client-two' 'session-two' `
        '192.0.2.11' @(201, 202, 203) @('Yg==', 'eQ==', 'eg==')
    Assert-SourceReviewResult @($first, $partial) $false $false $false $false 1

    $sessionCopy = New-SyntheticLogicalSource ('22' * 32) 'client-two' 'session-one' `
        '192.0.2.11' @(201, 202, 203) @('eA==', 'eQ==', 'eg==')
    Assert-SourceReviewResult @($first, $sessionCopy) $false $true $false $false 0

    $originCopy = New-SyntheticLogicalSource ('22' * 32) 'client-one' 'session-two' `
        '192.0.2.11' @(201, 202, 203) @('eA==', 'eQ==', 'eg==')
    Assert-SourceReviewResult @($first, $originCopy) $false $false $true $false 0

    $frameCopy = New-SyntheticLogicalSource ('11' * 32) 'client-two' 'session-two' `
        '192.0.2.11' @(101, 102, 103) @('eA==', 'eQ==', 'eg==')
    Assert-SourceReviewResult @($first, $frameCopy) $false $false $false $true 0

    # Non-ASCII octets must not be Unicode-case-folded into one identity.
    $binaryA = New-SyntheticLogicalSource ('33' * 32) 'client-three' 'session-three' `
        '192.0.2.12' @(301, 302, 303) @('gA==', 'Yg==', 'Yw==')
    $binaryB = New-SyntheticLogicalSource ('44' * 32) 'client-four' 'session-four' `
        '192.0.2.13' @(401, 402, 403) @('gQ==', 'eQ==', 'eg==')
    Assert-SourceReviewResult @($binaryA, $binaryB) $false $false $false $false 0

    Write-Host 'V2 logical-source contract: seven mirror, overlap, session, origin, frame-reuse and non-ASCII review scenarios defined. No source approved.'
}

$temporaryPath = Join-Path ([IO.Path]::GetTempPath()) `
    ('carthago-dns-wire-contract-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temporaryPath)
try {
    $capture = Join-Path $temporaryPath 'synthetic-dns-wire.pcap'
    # Frame 1: binary label A, dot octet, 0xff; second label "base"; TXT.
    # Frame 2: two questions, second QNAME compressed to first at offset 12.
    # Frame 3: forward pointer 0xc021 into in-bounds later bytes; reject.
    # Frame 4: self-referential pointer 0xc00c; reject.
    # Frame 5: length-prefixed TCP DNS with printable "www.example"; AAAA.
    # Frame 6: truncated five-octet label; reject.
    $dns1 = Convert-HexToBytes '12340100000100000000000003412eff04626173650000100001'
    $dns2 = Convert-HexToBytes '12350100000200000000000005616c706861076578616d706c650000100001c00c00010001'
    $dns3 = Convert-HexToBytes ('123601000001000000000000c02100100001' + ('00' * 15) + '0361626300')
    $dns4 = Convert-HexToBytes '123701000001000000000000c00c00100001'
    $dns5 = Convert-HexToBytes '12380100000100000000000003777777076578616d706c6500001c0001'
    $dns6 = Convert-HexToBytes '123901000001000000000000056162'
    $frames = @(
        (New-UdpDnsFrame $dns1 1), (New-UdpDnsFrame $dns2 2),
        (New-UdpDnsFrame $dns3 3), (New-UdpDnsFrame $dns4 4),
        (New-TcpDnsFrame $dns5 5), (New-UdpDnsFrame $dns6 6))
    Write-SyntheticPcap -Path $capture -Frames $frames
    $captureHash = (Get-FileHash -LiteralPath $capture -Algorithm SHA256).Hash.ToLowerInvariant()

    $tshark = (Get-Command $TsharkPath -ErrorAction Stop).Source
    # Independent TShark corroboration uses only raw DNS bytes and QTYPE,
    # never the potentially lossy dns.qry.name presentation field.
    $rawOutput = @(& $tshark -n -r $capture -Y 'frame.number == 1 || frame.number == 2 || frame.number == 5' `
        -T jsonraw 2>&1)
    Assert-Contract ($LASTEXITCODE -eq 0) 'tshark-jsonraw-failed'
    # jsonraw is a top-level JSON array. Windows PowerShell 5.1 may
    # preserve or enumerate that array differently when ConvertFrom-Json
    # emits into @(...). Decode through a single-object envelope so the
    # typed Frames property has stable cardinality across PS versions.
    # TShark output remains unmodified; never print raw DNS packet bytes.
    $rawJson = ($rawOutput -join [Environment]::NewLine).Trim()
    Assert-Contract ($rawJson.StartsWith('[') -and
        $rawJson.EndsWith(']')) 'tshark-jsonraw-not-array'
    $rawEnvelope = ConvertFrom-Json -InputObject ('{"Frames":'+$rawJson+'}')
    Assert-Contract ($null -ne $rawEnvelope -and
        $null -ne $rawEnvelope.PSObject.Properties['Frames'] -and
        $rawEnvelope.Frames -is [array]) 'tshark-jsonraw-frame-shape-invalid'
    [object[]]$rawFrames = $rawEnvelope.Frames
    Assert-Contract ($rawFrames.Count -eq 3) 'tshark-frame-count-mismatch'
    # Named, typed expected vectors prevent nested PowerShell tuple arrays
    # from being flattened/reshaped at evaluation boundaries. The expected
    # bytes remain the original, independently authored synthetic DNS vectors.
    $expectedVectors = @(
        [pscustomobject]@{ FrameNumber=1; Index=0; Bytes=[byte[]]$dns1 }
        [pscustomobject]@{ FrameNumber=2; Index=1; Bytes=[byte[]]$dns2 }
        [pscustomobject]@{ FrameNumber=5; Index=2; Bytes=[byte[]]$dns5 }
    )
    Assert-Contract ($expectedVectors.Count -eq 3 -and
        $expectedVectors[0].Bytes.Length -eq $dns1.Length -and
        $expectedVectors[1].Bytes.Length -eq $dns2.Length -and
        $expectedVectors[2].Bytes.Length -eq $dns5.Length) 'synthetic-reference-shape-invalid'
    foreach ($reference in $expectedVectors) {
        $frameIndex = [int]$reference.Index
        [byte[]]$expected = $reference.Bytes
        $rawField = @($rawFrames[$frameIndex]._source.layers.dns_raw)[0]
        Assert-Contract ($null -ne $rawField) 'tshark-dns-raw-unavailable'
        $fromTshark = Convert-HexToBytes ([string]$rawField)
        if([Convert]::ToBase64String($fromTshark) -cne
           [Convert]::ToBase64String($expected)) {
            # Only synthetic frame index and byte lengths. Do not emit actual
            # wire bytes, reversible labels, source identity, JSON or paths.
            Assert-Contract $false ('tshark-dns-wire-mismatch-frame-'+
                [string]$reference.FrameNumber+'-expected-length-'+
                [string]$expected.Length+'-actual-length-'+
                [string]$fromTshark.Length)
        }
    }

    $typeOutput = @(& $tshark -n -r $capture `
        -Y 'frame.number == 1 || frame.number == 2 || frame.number == 5' `
        -T fields -E 'separator=|' -E 'occurrence=a' `
        -e frame.number -e dns.qry.type -e udp.dstport -e tcp.dstport 2>&1)
    Assert-Contract ($LASTEXITCODE -eq 0 -and $typeOutput.Count -eq 3) 'tshark-qtype-fields-unavailable'
    $first = ([string]$typeOutput[0]).Split('|')
    $second = ([string]$typeOutput[1]).Split('|')
    $tcpFrame = ([string]$typeOutput[2]).Split('|')
    Assert-Contract ($first[0] -eq '1' -and $first[1] -eq '16' -and $first[2] -eq '53') 'tshark-udp-qtype-mismatch'
    Assert-Contract ($second[0] -eq '2' -and $second[1] -eq '16,1' -and $second[2] -eq '53') 'tshark-multi-question-mismatch'
    Assert-Contract ($tcpFrame[0] -eq '5' -and $tcpFrame[1] -eq '28' -and $tcpFrame[3] -eq '53') 'tshark-tcp-qtype-mismatch'

    $module = Join-Path $PSScriptRoot 'DnsWirePcap.psm1'
    Assert-Contract (Test-Path -LiteralPath $module -PathType Leaf) 'decoder-not-implemented-red'
    Import-Module -Name $module -Force -ErrorAction Stop
    Assert-Contract ($null -ne (Get-Command Read-DnsWireQuestion -ErrorAction SilentlyContinue)) 'decoder-api-unavailable'
    Assert-PrivateQuestion $capture $captureHash 1 0 @('QS7/', 'YmFzZQ==') 16 'UDP' $tshark
    Assert-PrivateQuestion $capture $captureHash 2 0 @('YWxwaGE=', 'ZXhhbXBsZQ==') 16 'UDP' $tshark
    Assert-PrivateQuestion $capture $captureHash 2 1 @('YWxwaGE=', 'ZXhhbXBsZQ==') 1 'UDP' $tshark
    Assert-PrivateQuestion $capture $captureHash 5 0 @('d3d3', 'ZXhhbXBsZQ==') 28 'TCP' $tshark
    Assert-QuestionRejected $capture 2 2 $tshark # out-of-range ordinal
    Assert-QuestionRejected $capture 3 0 $tshark # forward pointer
    Assert-QuestionRejected $capture 4 0 $tshark # pointer cycle
    Assert-QuestionRejected $capture 6 0 $tshark # truncated label
    Assert-QuestionRejected $capture 99 0 $tshark # absent source frame
    Write-Host 'DNS wire source contract: four source-bound questions corroborated; five invalid/ambiguous selections rejected. Synthetic evidence only.'
    if ($IncludeV2Provenance) {
        Assert-Stage6CandidateEvidence $capture $captureHash $tshark
        Assert-Stage6LogicalSourceIndependence
    }
} finally {
    # Remove only our own uniquely named temporary test fixture.
    if (Test-Path -LiteralPath $temporaryPath) {
        Remove-Item -LiteralPath $temporaryPath -Recurse -Force
    }
}
