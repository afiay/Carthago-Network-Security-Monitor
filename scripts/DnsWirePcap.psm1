# SPDX-License-Identifier: MIT
# Selected original DNS question-byte extraction and private provenance binding.
# Source content never appears in errors/logs. TShark decodes packet boundaries;
# wire labels are decoded independently from dns_raw, not dns.qry.name text.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Fail-Wire([string]$Code) { throw $Code }
function Get-WireProp([object]$Obj,[string]$Name) {
    if($null -eq $Obj) {return $null}
    return $Obj.PSObject.Properties[$Name]
}
function Read-BE16([byte[]]$Data,[int]$Offset) {
    if($Offset -lt 0 -or $Offset+2 -gt $Data.Length) {
        Fail-Wire 'DNS_WIRE_TRUNCATED'
    }
    return (([int]$Data[$Offset] -shl 8) -bor [int]$Data[$Offset+1])
}
function Convert-WireHex([string]$Text) {
    if($null -eq $Text) { Fail-Wire 'DNS_WIRE_RAW_UNAVAILABLE' }
    $hex=$Text -replace '[:\s]',''
    if($hex.Length -eq 0 -or $hex.Length % 2 -ne 0 -or
       $hex.Length -gt 131070 -or $hex -cnotmatch '^[0-9A-Fa-f]+$') {
        Fail-Wire 'DNS_WIRE_INVALID_HEX'
    }
    $bytes=New-Object byte[] ($hex.Length/2)
    for($i=0;$i -lt $bytes.Length;$i++) {
        $bytes[$i]=[Convert]::ToByte($hex.Substring(2*$i,2),16)
    }
    return ,$bytes
}
# Wireshark -T jsonraw encodes one *_raw field as a descriptor array:
# [hex, frameOffset, byteLength, bitmask, fieldType, optional dataSource].
# Those 5/6 entries are metadata for ONE field, not multiple DNS payloads.
# Refuse ambiguous/nested/malformed descriptors and verify metadata length
# against the complete decoded hex bytes before transport-specific parsing.
function Convert-DnsJsonRawDescriptor([object]$Descriptor) {
    if($null -eq $Descriptor -or $Descriptor -isnot [array] -or
       $Descriptor.Count -notin @(5,6)) {
        Fail-Wire 'DNS_WIRE_RAW_AMBIGUOUS'
    }
    if($Descriptor[0] -isnot [string]) {
        Fail-Wire 'DNS_WIRE_RAW_AMBIGUOUS'
    }
    for($i=1;$i -lt $Descriptor.Count;$i++) {
        if($Descriptor[$i] -isnot [int] -and
           $Descriptor[$i] -isnot [long]) {
            Fail-Wire 'DNS_WIRE_RAW_AMBIGUOUS'
        }
        if([long]$Descriptor[$i] -lt 0) {
            Fail-Wire 'DNS_WIRE_RAW_AMBIGUOUS'
        }
    }
    if([long]$Descriptor[3] -ne 0) {
        # Protocol-level DNS bytes must not describe a masked bitfield.
        Fail-Wire 'DNS_WIRE_RAW_AMBIGUOUS'
    }
    $bytes=Convert-WireHex ([string]$Descriptor[0])
    if([long]$Descriptor[2] -ne $bytes.Length) {
        Fail-Wire 'DNS_WIRE_RAW_LENGTH_MISMATCH'
    }
    return ,$bytes
}
# DNS over TCP is preceded by a two-octet big-endian length per RFC 7766.
# In TShark 4.6.9 jsonraw the prefix is included in dns_raw for the
# synthetic TCP fixture. Enforce exact framing, never guess or silently
# truncate bytes. A single selected raw DNS record is one message only.
function Get-DnsMessageFromTransportRaw([byte[]]$RawBytes,[string]$Transport) {
    if($Transport -ceq 'UDP') {
        if($RawBytes.Length -lt 12) { Fail-Wire 'DNS_WIRE_TRUNCATED' }
        return ,$RawBytes
    }
    if($Transport -cne 'TCP') { Fail-Wire 'DNS_WIRE_TRANSPORT_AMBIGUOUS' }
    if($RawBytes.Length -lt 2) { Fail-Wire 'DNS_WIRE_TCP_PREFIX_TRUNCATED' }
    $declared=Read-BE16 $RawBytes 0
    if($declared -lt 12 -or $declared -ne ($RawBytes.Length-2)) {
        Fail-Wire 'DNS_WIRE_TCP_LENGTH_MISMATCH'
    }
    $message=New-Object byte[] $declared
    [Array]::Copy($RawBytes,2,$message,0,$declared)
    return ,$message
}
function Read-WireName([byte[]]$Message,[int]$At) {
    $labels=[Collections.Generic.List[byte[]]]::new()
    $cursor=$At
    $end=-1
    $steps=0
    $expanded=1
    $visited=[Collections.Generic.HashSet[int]]::new()
    while($true) {
        $steps++
        if($steps -gt 128 -or $cursor -lt 12 -or $cursor -ge $Message.Length) {
            Fail-Wire 'DNS_WIRE_NAME_INVALID'
        }
        if(-not $visited.Add($cursor)) { Fail-Wire 'DNS_WIRE_POINTER_CYCLE' }
        $length=[int]$Message[$cursor]
        if(($length -band 0xc0) -eq 0xc0) {
            if($cursor+2 -gt $Message.Length) {
                Fail-Wire 'DNS_WIRE_TRUNCATED'
            }
            $target=(($length -band 0x3f) -shl 8) -bor [int]$Message[$cursor+1]
            # Backward pointers only. Forward pointers may hide malicious
            # ambiguous bytes even when the offset is inside the packet.
            if($target -ge $cursor -or $target -lt 12) {
                Fail-Wire 'DNS_WIRE_FORWARD_OR_HEADER_POINTER'
            }
            if($end -lt 0) { $end=$cursor+2 }
            $cursor=$target
            continue
        }
        if(($length -band 0xc0) -ne 0) {
            Fail-Wire 'DNS_WIRE_RESERVED_LABEL'
        }
        if($length -eq 0) {
            if($end -lt 0) { $end=$cursor+1 }
            break
        }
        if($length -gt 63 -or $cursor+1+$length -gt $Message.Length) {
            Fail-Wire 'DNS_WIRE_TRUNCATED'
        }
        $expanded+=$length+1
        if($expanded -gt 255 -or $labels.Count -ge 127) {
            Fail-Wire 'DNS_WIRE_NAME_TOO_LONG'
        }
        $label=New-Object byte[] $length
        [Array]::Copy($Message,$cursor+1,$label,0,$length)
        $labels.Add($label)
        $cursor+=1+$length
    }
    return [pscustomobject]@{ Labels=$labels.ToArray();NextOffset=$end }
}
function Read-DnsQuestionsFromRaw([byte[]]$Message) {
    if($Message.Length -lt 12) { Fail-Wire 'DNS_WIRE_TRUNCATED' }
    $flags=Read-BE16 $Message 2
    if(($flags -band 0x8000) -ne 0) { Fail-Wire 'DNS_WIRE_NOT_QUERY' }
    $count=Read-BE16 $Message 4
    if($count -lt 1 -or $count -gt 64) {
        Fail-Wire 'DNS_WIRE_QUESTION_COUNT_INVALID'
    }
    $position=12
    $questions=[Collections.Generic.List[object]]::new()
    for($ordinal=0;$ordinal -lt $count;$ordinal++) {
        $name=Read-WireName $Message $position
        $position=[int]$name.NextOffset
        $type=Read-BE16 $Message $position
        $qclass=Read-BE16 $Message ($position+2)
        if($qclass -ne 1) { Fail-Wire 'DNS_WIRE_UNSUPPORTED_CLASS' }
        $position+=4
        $encoded=[Collections.Generic.List[string]]::new()
        foreach($label in $name.Labels) {
            $encoded.Add([Convert]::ToBase64String([byte[]]$label))
        }
        $questions.Add([pscustomobject]@{
            QuestionIndex=$ordinal
            Qtype=$type
            DnsWireLabelsBase64=[string[]]$encoded.ToArray()
        })
    }
    # Emit one object per question; the caller wraps pipeline output in @().
    # Do not use unary-comma here or multi-question packets become nested.
    return $questions.ToArray()
}

function Read-DnsWireQuestion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$CapturePath,
        [Parameter(Mandatory=$true)][int]$FrameNumber,
        [Parameter(Mandatory=$true)][int]$QuestionIndex,
        [string]$TsharkPath='tshark'
    )
    if($FrameNumber -lt 1 -or $QuestionIndex -lt 0 -or $QuestionIndex -gt 65535) {
        Fail-Wire 'DNS_WIRE_SELECTION_INVALID'
    }
    if(-not (Test-Path -LiteralPath $CapturePath -PathType Leaf)) {
        Fail-Wire 'DNS_WIRE_ORIGINAL_CAPTURE_MISSING'
    }
    try {
        $capture=(Resolve-Path -LiteralPath $CapturePath -ErrorAction Stop).Path
        $captureItem=Get-Item -LiteralPath $capture -Force -ErrorAction Stop
    } catch { Fail-Wire 'DNS_WIRE_ORIGINAL_CAPTURE_UNAVAILABLE' }
    if(($captureItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-Wire 'DNS_WIRE_UNTRUSTED_CAPTURE'
    }
    try { $tshark=Get-Command $TsharkPath -ErrorAction Stop }
    catch { Fail-Wire 'DNS_WIRE_TSHARK_UNAVAILABLE' }
    $filter='frame.number == '+$FrameNumber
    try {
        $raw=@(& $tshark.Source -n -r $capture -Y $filter -T jsonraw 2>&1)
    } catch { Fail-Wire 'DNS_WIRE_TSHARK_ERROR' }
    if($LASTEXITCODE -ne 0) { Fail-Wire 'DNS_WIRE_TSHARK_ERROR' }
    # Envelope top-level jsonraw so PowerShell 5.1 preserves frame array
    # cardinality. Never expose packet bytes or private source metadata.
    $rawJson=($raw -join [Environment]::NewLine).Trim()
    if(-not $rawJson.StartsWith('[') -or -not $rawJson.EndsWith(']')) {
        Fail-Wire 'DNS_WIRE_TSHARK_RAW_INVALID'
    }
    $envelope=$null
    try { $envelope=ConvertFrom-Json -InputObject ('{"Frames":'+$rawJson+'}') }
    catch { Fail-Wire 'DNS_WIRE_TSHARK_RAW_INVALID' }
    if($null -eq $envelope -or
       $null -eq $envelope.PSObject.Properties['Frames'] -or
       $envelope.Frames -isnot [array]) {
        Fail-Wire 'DNS_WIRE_TSHARK_RAW_INVALID'
    }
    [object[]]$frames=$envelope.Frames
    if($frames.Count -ne 1) { Fail-Wire 'DNS_WIRE_FRAME_NOT_UNIQUE' }
    $layers=$frames[0]._source.layers
    if($null -eq $layers) { Fail-Wire 'DNS_WIRE_RAW_UNAVAILABLE' }
    $rawProperty=Get-WireProp $layers 'dns_raw'
    if($null -eq $rawProperty) { Fail-Wire 'DNS_WIRE_RAW_UNAVAILABLE' }
    # dns_raw is a single jsonraw descriptor with five or six fields.
    # Do not treat its metadata fields as repeated DNS message values.
    $rawBytes=Convert-DnsJsonRawDescriptor -Descriptor $rawProperty.Value
    # Obtain independently decoded transport fields BEFORE interpreting
    # raw DNS header bytes: TCP jsonraw may include its two-octet prefix.
    # Extract only the selected frame's captured source/destination and
    # transport fields. They are NOT inferred from QNAME presentation text.
    $fields=@('frame.number','ip.src','ip.dst','ipv6.src','ipv6.dst',
              'udp.srcport','udp.dstport','tcp.srcport','tcp.dstport')
    $args=@('-n','-r',$capture,'-Y',$filter,'-T','fields',
            '-E','separator=|','-E','quote=n','-E','occurrence=f')
    foreach($field in $fields) {$args+=@('-e',$field)}
    try { $rawFields=@(& $tshark.Source @args 2>&1) }
    catch { Fail-Wire 'DNS_WIRE_TRANSPORT_UNAVAILABLE' }
    if($LASTEXITCODE -ne 0 -or $rawFields.Count -ne 1) {
        Fail-Wire 'DNS_WIRE_TRANSPORT_UNAVAILABLE'
    }
    $parts=([string]$rawFields[0]).Split('|')
    if($parts.Count -ne 9 -or $parts[0] -cne [string]$FrameNumber) {
        Fail-Wire 'DNS_WIRE_TRANSPORT_AMBIGUOUS'
    }
    $src=$parts[1].Trim()
    $dst=$parts[2].Trim()
    if($src.Length -eq 0 -or $dst.Length -eq 0) {
        $src=$parts[3].Trim()
        $dst=$parts[4].Trim()
    }
    $srcParsed=$null
    $dstParsed=$null
    if(-not [Net.IPAddress]::TryParse($src,[ref]$srcParsed) -or
       -not [Net.IPAddress]::TryParse($dst,[ref]$dstParsed)) {
        Fail-Wire 'DNS_WIRE_IP_ATTRIBUTION_INVALID'
    }
    $udp=$parts[5].Length -gt 0 -and $parts[6].Length -gt 0
    $tcp=$parts[7].Length -gt 0 -and $parts[8].Length -gt 0
    if($udp -eq $tcp) { Fail-Wire 'DNS_WIRE_TRANSPORT_AMBIGUOUS' }
    $transport=if($udp){'UDP'}else{'TCP'}
    $sourcePortText=if($udp){$parts[5]}else{$parts[7]}
    $destinationPortText=if($udp){$parts[6]}else{$parts[8]}
    if($sourcePortText -notmatch '^\d{1,5}$' -or
       $destinationPortText -notmatch '^\d{1,5}$') {
        Fail-Wire 'DNS_WIRE_PORT_INVALID'
    }
    $sourcePort=[int]$sourcePortText
    $destinationPort=[int]$destinationPortText
    if($sourcePort -lt 1 -or $sourcePort -gt 65535 -or
       $destinationPort -ne 53) {
        Fail-Wire 'DNS_WIRE_PORT_INVALID'
    }
    $message=Get-DnsMessageFromTransportRaw -RawBytes $rawBytes -Transport $transport
    $questions=@(Read-DnsQuestionsFromRaw $message)
    if($QuestionIndex -ge $questions.Count) {
        Fail-Wire 'DNS_WIRE_QUESTION_ORDINAL_INVALID'
    }
    try { $hash=(Get-FileHash -LiteralPath $capture -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
    catch { Fail-Wire 'DNS_WIRE_CAPTURE_HASH_UNAVAILABLE' }
    $q=$questions[$QuestionIndex]
    return [pscustomobject][ordered]@{
        CaptureSha256=$hash
        FrameNumber=$FrameNumber
        QuestionIndex=$QuestionIndex
        Qtype=[int]$q.Qtype
        Transport=$transport
        SourcePort=$sourcePort
        DestinationPort=$destinationPort
        SourceAddress=$src
        DestinationAddress=$dst
        DnsWireLabelsBase64=[string[]]@($q.DnsWireLabelsBase64)
    }
}
function Assert-CanonicalWireLabels([object]$Values) {
    if($null -eq $Values -or $Values -isnot [array] -or $Values.Count -gt 127) {
        Fail-Wire 'DNS_WIRE_RECORD_LABELS_INVALID'
    }
    $length=1
    foreach($label in $Values) {
        if($label -isnot [string] -or $label.Length -eq 0) {
            Fail-Wire 'DNS_WIRE_RECORD_LABELS_INVALID'
        }
        $raw=$null
        try { $raw=[Convert]::FromBase64String([string]$label) }
        catch { Fail-Wire 'DNS_WIRE_BASE64_INVALID' }
        if($raw.Length -lt 1 -or $raw.Length -gt 63 -or
           [Convert]::ToBase64String($raw) -cne [string]$label) {
            Fail-Wire 'DNS_WIRE_BASE64_NONCANONICAL'
        }
        $length+=($raw.Length+1)
        if($length -gt 255) { Fail-Wire 'DNS_WIRE_NAME_TOO_LONG' }
    }
}
# A record schema is an exact, case-sensitive set of NOTE property names.
# No Compare-Object/Sort-Object pipeline: empty and malformed inputs must
# fail deterministically rather than trigger PowerShell mandatory prompts.
function Test-DnsExactRecordFields([object]$Record,[string[]]$ExpectedFields) {
    if($null -eq $Record -or $null -eq $ExpectedFields) { return $false }
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($property in $Record.PSObject.Properties) {
        if($property.MemberType -ne [System.Management.Automation.PSMemberTypes]::NoteProperty) {
            return $false
        }
        if(-not $seen.Add([string]$property.Name)) { return $false }
    }
    if($seen.Count -ne $ExpectedFields.Count) { return $false }
    foreach($field in $ExpectedFields) {
        if(-not $seen.Contains([string]$field)) { return $false }
    }
    return $true
}
function Confirm-DnsWireCandidateBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$CapturePath,
        [Parameter(Mandatory=$true)][object]$Provenance,
        [Parameter(Mandatory=$true)][object[]]$Records,
        [string]$TsharkPath='tshark'
    )
    # No untrusted debugging fields may enter the private source record model.
    $fields=@('source','destination','ipVersion','sourcePort','destinationPort',
              'isUdp','isTcp','dnsQtype','dnsWireLabelsBase64')
    if($Records.Count -lt 1 -or $Records.Count -gt 500 -or
       $null -eq $Provenance -or
       [string]$Provenance.dnsWireNameEncoding -cne 'labels-base64-v1' -or
       [string]$Provenance.captureSha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or
       [string]$Provenance.originatingClientLabel -notmatch '^[A-Za-z0-9._:-]{3,128}$' -or
       [string]$Provenance.collectionSessionId -notmatch '^[A-Za-z0-9._:-]{3,128}$' -or
       [string]$Provenance.collectionVantage -cnotin @('client','endpoint','sensor') -or
       [string]$Provenance.independentClientEvidenceUri -notmatch '^https://[^/\s@?#]+') {
        Fail-Wire 'DNS_WIRE_CANDIDATE_INVALID'
    }
    $frames=@($Provenance.frameNumbers)
    $indices=@($Provenance.questionIndices)
    if($frames.Count -ne $Records.Count -or $indices.Count -ne $Records.Count) {
        Fail-Wire 'DNS_WIRE_CARDINALITY'
    }
    if(-not (Test-Path -LiteralPath $CapturePath -PathType Leaf)) {
        Fail-Wire 'DNS_WIRE_ORIGINAL_CAPTURE_MISSING'
    }
    try { $hash=(Get-FileHash -LiteralPath $CapturePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
    catch { Fail-Wire 'DNS_WIRE_CAPTURE_HASH_UNAVAILABLE' }
    if($hash -cne ([string]$Provenance.captureSha256).ToLowerInvariant()) {
        Fail-Wire 'DNS_WIRE_CAPTURE_HASH_MISMATCH'
    }
    $matched=[Collections.Generic.HashSet[string]]::new()
    for($i=0;$i -lt $Records.Count;$i++) {
        $record=$Records[$i]
        if(-not (Test-DnsExactRecordFields -Record $record -ExpectedFields $fields) -or
           $record.isUdp -isnot [bool] -or $record.isTcp -isnot [bool] -or
           ($record.isUdp -eq $record.isTcp)) {
            Fail-Wire 'DNS_WIRE_RECORD_SCHEMA'
        }
        $frame=[int]$frames[$i]
        $ordinal=[int]$indices[$i]
        if($frame -le 0 -or $ordinal -lt 0 -or $ordinal -gt 65535 -or
           -not $matched.Add(($frame.ToString()+':'+$ordinal.ToString()))) {
            Fail-Wire 'DNS_WIRE_DUPLICATE_QUESTION'
        }
        Assert-CanonicalWireLabels $record.dnsWireLabelsBase64
        $source=Read-DnsWireQuestion -CapturePath $CapturePath -FrameNumber $frame -QuestionIndex $ordinal -TsharkPath $TsharkPath
        $qtype=@{A=1;NS=2;CNAME=5;SOA=6;NULL=10;PTR=12;MX=15;TXT=16;AAAA=28;SRV=33}
        if($null -eq $qtype[[string]$record.dnsQtype]) {
            Fail-Wire 'DNS_WIRE_QTYPE_UNSUPPORTED'
        }
        $ipType=if($source.SourceAddress -match ':'){6}else{4}
        if([string]$record.source -cne [string]$source.SourceAddress -or
           [string]$record.destination -cne [string]$source.DestinationAddress -or
           [int]$record.ipVersion -ne $ipType -or
           [int]$record.sourcePort -ne [int]$source.SourcePort -or
           [int]$record.destinationPort -ne [int]$source.DestinationPort -or
           [bool]$record.isUdp -ne ($source.Transport -ceq 'UDP') -or
           [bool]$record.isTcp -ne ($source.Transport -ceq 'TCP') -or
           [int]$qtype[[string]$record.dnsQtype] -ne [int]$source.Qtype) {
            Fail-Wire 'DNS_WIRE_ATTRIBUTION_MISMATCH'
        }
        $actual=@($source.DnsWireLabelsBase64)
        $claimed=@($record.dnsWireLabelsBase64)
        if($actual.Count -ne $claimed.Count) {
            Fail-Wire 'DNS_WIRE_LABEL_COUNT_MISMATCH'
        }
        for($j=0;$j -lt $actual.Count;$j++) {
            if([string]$actual[$j] -cne [string]$claimed[$j]) {
                Fail-Wire 'DNS_WIRE_LABEL_BYTES_MISMATCH'
            }
        }
    }
    return [pscustomobject]@{
        MatchedQuestionCount=$matched.Count
        CaptureSha256=$hash
    }
}
# Canonical identity for logical overlap is ASCII case-folding of original
# DNS label octets ONLY. Non-ASCII label bytes remain distinct; UTF-8/Unicode
# transformations are never applied.
function Get-WireNameIdentity([object]$Labels) {
    Assert-CanonicalWireLabels $Labels
    $parts=[Collections.Generic.List[string]]::new()
    foreach($base64 in $Labels) {
        $bytes=[Convert]::FromBase64String([string]$base64)
        for($i=0;$i -lt $bytes.Length;$i++) {
            if($bytes[$i] -ge 65 -and $bytes[$i] -le 90) {
                $bytes[$i]=[byte]([int]$bytes[$i]+32)
            }
        }
        $parts.Add([Convert]::ToBase64String($bytes))
    }
    return ($parts -join '.')
}
function Measure-DnsWireMaliciousSourceIndependence {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][object[]]$Candidates)
    if($Candidates.Count -ne 2) { Fail-Wire 'DNS_SOURCE_PAIR_REQUIRED' }
    $nameSets=@()
    $frameSets=@()
    foreach($candidate in $Candidates) {
        if($null -eq $candidate.provenance -or
           $null -eq $candidate.records -or @($candidate.records).Count -eq 0) {
            Fail-Wire 'DNS_SOURCE_REVIEW_INPUT_INVALID'
        }
        $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach($record in @($candidate.records)) {
            [void]$names.Add((Get-WireNameIdentity $record.dnsWireLabelsBase64))
        }
        $frames=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $refs=@($candidate.provenance.frameNumbers)
        $ordinals=@($candidate.provenance.questionIndices)
        if($refs.Count -ne @($candidate.records).Count -or
           $ordinals.Count -ne $refs.Count) {
            Fail-Wire 'DNS_SOURCE_REVIEW_INPUT_INVALID'
        }
        for($i=0;$i -lt $refs.Count;$i++) {
            [void]$frames.Add(([string]$candidate.provenance.captureSha256+':'+$refs[$i]+':'+$ordinals[$i]))
        }
        $nameSets+=,$names
        $frameSets+=,$frames
    }
    $sharedNames=0
    foreach($name in $nameSets[0]) {
        if($nameSets[1].Contains($name)) { $sharedNames++ }
    }
    $sharedFrame=$false
    foreach($ref in $frameSets[0]) {
        if($frameSets[1].Contains($ref)) { $sharedFrame=$true;break }
    }
    $one=$Candidates[0].provenance
    $two=$Candidates[1].provenance
    return [pscustomobject][ordered]@{
        CompleteNameSetOverlap=($sharedNames -gt 0 -and
            $sharedNames -eq $nameSets[0].Count -and
            $sharedNames -eq $nameSets[1].Count)
        SharedCollectionSession=([string]$one.collectionSessionId -ieq [string]$two.collectionSessionId)
        SameOriginatingClient=([string]$one.originatingClientLabel -ieq [string]$two.originatingClientLabel)
        ReusedOriginalFrame=$sharedFrame
        OverlappingDistinctNameCount=$sharedNames
        RequiresAnalystReview=$true
        IndependenceApproved=$false
    }
}
Export-ModuleMember -Function Read-DnsWireQuestion,Confirm-DnsWireCandidateBinding,Measure-DnsWireMaliciousSourceIndependence
