# SPDX-License-Identifier: MIT
# PARKED CONTRACT: do not execute without the owner's explicit test-time approval.
# Generates an entirely synthetic, temporary PCAP. No private capture, DNS name,
# source address or reversible label is written to the console or repository.
[CmdletBinding()]
param(
    [string]$TsharkPath = 'tshark'
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
    $rawFrames = @(ConvertFrom-Json -InputObject ($rawOutput -join [Environment]::NewLine))
    Assert-Contract ($rawFrames.Count -eq 3) 'tshark-frame-count-mismatch'
    foreach ($reference in @(@(0, $dns1), @(1, $dns2), @(2, $dns5))) {
        $frameIndex = [int]$reference[0]
        $expected = [byte[]]$reference[1]
        $rawField = @($rawFrames[$frameIndex]._source.layers.dns_raw)[0]
        Assert-Contract ($null -ne $rawField) 'tshark-dns-raw-unavailable'
        $fromTshark = Convert-HexToBytes ([string]$rawField)
        Assert-Contract ([Convert]::ToBase64String($fromTshark) -ceq `
            [Convert]::ToBase64String($expected)) 'tshark-dns-wire-mismatch'
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
} finally {
    # Remove only our own uniquely named temporary test fixture.
    if (Test-Path -LiteralPath $temporaryPath) {
        Remove-Item -LiteralPath $temporaryPath -Recurse -Force
    }
}
