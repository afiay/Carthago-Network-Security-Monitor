# SPDX-License-Identifier: MIT
# Private V2 provenance structural validation. No writes, networking, captures,
# detector execution, human-approval inference or source-data console output.
# Windows PowerShell 5.1 compatible; READ-ONLY by design.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Fail-Provenance([string]$Code) { throw $Code }

function Get-ProvenanceProp([object]$Obj,[string]$Name) {
    if($null -eq $Obj) { return $null }
    return $Obj.PSObject.Properties[$Name]
}

function Test-IntegerValue([object]$Value) {
    return $Value -is [int] -or $Value -is [long] -or
        $Value -is [short] -or $Value -is [byte] -or
        $Value -is [uint32] -or $Value -is [uint64]
}

function Assert-ProvenanceValue([string]$Name,[object]$Value,[object]$Spec) {
    $type=[string]$Spec.type
    $code='PROV_SCHEMA_TYPE'
    if($Name -eq 'schemaVersion'){$code='PROV_SCHEMA_VERSION'}
    elseif($Name -eq 'captureSha256'){$code='PROV_SCHEMA_CAPTURE_HASH'}
    elseif($Name -eq 'frameNumbers'){$code='PROV_SCHEMA_FRAME_INDEX'}
    elseif($Name -eq 'questionIndices'){$code='PROV_SCHEMA_QUESTION_INDEX'}
    elseif($Name -eq 'sourceLicense'){$code='PROV_SCHEMA_LICENSE'}
    elseif($Name -eq 'dnsWireNameEncoding'){$code='PROV_SCHEMA_ENCODING'}
    elseif($Name -eq 'collectionVantage'){$code='PROV_SCHEMA_VANTAGE'}
    elseif($Name -eq 'selectionMethod'){$code='PROV_SCHEMA_METHOD'}
    elseif($Name -eq 'queryRoot'){$code='PROV_SCHEMA_ROOT'}
    elseif($Name -eq 'reviewState'){$code='PROV_SCHEMA_REVIEW_STATE'}
    elseif($Name -match 'Uri$'){$code='PROV_SCHEMA_URI'}

    if($type -eq 'integer') {
        if(-not (Test-IntegerValue $Value)) { Fail-Provenance 'PROV_SCHEMA_TYPE' }
    } elseif($type -eq 'boolean') {
        if($Value -isnot [bool]) { Fail-Provenance 'PROV_SCHEMA_TYPE' }
    } elseif($type -eq 'string') {
        if($Value -isnot [string]) { Fail-Provenance 'PROV_SCHEMA_TYPE' }
    } elseif($type -eq 'array') {
        if($null -eq $Value -or $Value -isnot [array]) {
            Fail-Provenance 'PROV_SCHEMA_TYPE'
        }
    } else { Fail-Provenance 'PROV_SCHEMA_TYPE' }

    if($null -ne (Get-ProvenanceProp $Spec 'const')) {
        if($type -eq 'integer' -and $Value -ne $Spec.const) {
            Fail-Provenance $code
        }
        if($type -eq 'boolean' -and $Value -ne $Spec.const) {
            Fail-Provenance $code
        }
        if($type -eq 'string' -and [string]$Value -cne [string]$Spec.const) {
            Fail-Provenance $code
        }
    }
    if($null -ne (Get-ProvenanceProp $Spec 'enum')) {
        if(@($Spec.enum | Where-Object { [string]$_ -ceq [string]$Value }).Count -ne 1) {
            Fail-Provenance $code
        }
    }

    if($type -eq 'string') {
        if(($null -ne (Get-ProvenanceProp $Spec 'minLength') -and
            $Value.Length -lt [int]$Spec.minLength) -or
           ($null -ne (Get-ProvenanceProp $Spec 'maxLength') -and
            $Value.Length -gt [int]$Spec.maxLength)) {
            Fail-Provenance $code
        }
        if($null -ne (Get-ProvenanceProp $Spec 'pattern')) {
            if(-not [regex]::IsMatch($Value,[string]$Spec.pattern,
                [Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
                Fail-Provenance $code
            }
        }
        if($Name -eq 'preparedAtUtc') {
            $stamp=[datetimeoffset]::MinValue
            if($Value -notmatch '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$' -or
               -not [datetimeoffset]::TryParse($Value,
                   [Globalization.CultureInfo]::InvariantCulture,
                   [Globalization.DateTimeStyles]::None,[ref]$stamp)) {
                Fail-Provenance $code
            }
        }
        if($Name -eq 'sourceAddress') {
            $ip=$null
            if(-not [Net.IPAddress]::TryParse($Value,[ref]$ip)) {
                Fail-Provenance $code
            }
        }
    }
    if($type -eq 'integer') {
        if(($null -ne (Get-ProvenanceProp $Spec 'minimum') -and
            $Value -lt $Spec.minimum) -or
           ($null -ne (Get-ProvenanceProp $Spec 'maximum') -and
            $Value -gt $Spec.maximum)) {
            Fail-Provenance $code
        }
    }
    if($type -eq 'array') {
        if(($null -ne (Get-ProvenanceProp $Spec 'minItems') -and
            $Value.Count -lt [int]$Spec.minItems) -or
           ($null -ne (Get-ProvenanceProp $Spec 'maxItems') -and
            $Value.Count -gt [int]$Spec.maxItems)) {
            Fail-Provenance $code
        }
        foreach($element in $Value) {
            if(-not (Test-IntegerValue $element)) { Fail-Provenance $code }
            if($element -lt $Spec.items.minimum -or
               ($null -ne (Get-ProvenanceProp $Spec.items 'maximum') -and
                 $element -gt $Spec.items.maximum)) {
                Fail-Provenance $code
            }
        }
    }
}

function Confirm-HoldoutV2ProvenanceBatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$Candidates,
        [Parameter(Mandatory=$true)][string]$SchemaPath
    )
    if($Candidates.Count -ne 4) { Fail-Provenance 'PROV_BATCH_SHAPE:INPUT_COUNT' }
    $trustedSchema=Join-Path $PSScriptRoot '../docs/contracts/holdout-v2-private-provenance-v2.schema.json'
    $actualPath=[IO.Path]::GetFullPath($SchemaPath)
    $trustedPath=[IO.Path]::GetFullPath($trustedSchema)
    if($actualPath -ine $trustedPath -or
       -not (Test-Path -LiteralPath $actualPath -PathType Leaf)) {
        Fail-Provenance 'PROV_SCHEMA_UNTRUSTED'
    }
    $schemaFile=Get-Item -LiteralPath $actualPath
    if($schemaFile.Length -gt 65536) { Fail-Provenance 'PROV_SCHEMA_UNTRUSTED' }
    $schema=Get-Content -LiteralPath $actualPath -Encoding UTF8 -Raw | ConvertFrom-Json
    $required=@($schema.required)
    $expectedFields=@('schemaVersion','sample','classification','sourceKind',
        'sourceUri','sourceLicense','sourceLicenseEvidenceUri','independentLabelBasis',
        'analystReviewedLabel','capturedTransportEvidence','privacyReviewRequired',
        'captureFileName','captureSha256','frameNumbers','questionIndices',
        'selectedRecordCount','sourceAddress','queryRoot','originatingClientLabel',
        'collectionSessionId','collectionVantage','independentClientEvidenceUri',
        'dnsWireNameEncoding','extractor','extractorVersion','maximumPacketsToScan',
        'selectionMethod','transformations','preparedAtUtc','reviewState')
    if($schema.additionalProperties -ne $false -or $required.Count -ne 30 -or
       @(Compare-Object ($required | Sort-Object) ($expectedFields | Sort-Object)).Count -ne 0 -or
       @($schema.properties.PSObject.Properties.Name).Count -ne 30) {
        Fail-Provenance 'PROV_SCHEMA_UNTRUSTED'
    }

    $manifestFile=Join-Path $PSScriptRoot '../docs/holdout-evaluation-v2-manifest.json'
    $manifest=Get-Content -LiteralPath $manifestFile -Encoding UTF8 -Raw | ConvertFrom-Json
    if($manifest.schemaVersion -ne 2 -or
       $manifest.approvalState -cne 'PENDING_EXTERNAL_CAPTURE_AND_REVIEW') {
        Fail-Provenance 'PROV_BATCH_SHAPE:MANIFEST_STATE'
    }
    $slots=@($manifest.samples | Where-Object { $_.sourceKind -eq 'external-pcap-reviewed' })
    if($slots.Count -ne 4) { Fail-Provenance 'PROV_BATCH_SHAPE:MANIFEST_SLOTS' }
    $seenSample=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $seenQuestion=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $maliciousAddresses=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $maliciousOrigins=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $maliciousSessions=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach($candidate in $Candidates) {
        if($null -eq $candidate) { Fail-Provenance 'PROV_SCHEMA_TYPE' }
        $actual=@($candidate.PSObject.Properties.Name)
        if($actual.Count -ne $required.Count) {
            foreach($name in $required) {
                if($actual -cnotcontains $name) {
                    Fail-Provenance 'PROV_SCHEMA_REQUIRED_FIELD'
                }
            }
            Fail-Provenance 'PROV_SCHEMA_EXTRA_FIELD'
        }
        # Cross-field cardinality is a dedicated failure class, including
        # an array shortened below its independent schema minItems. Check
        # only when the three values already have their expected top-level
        # types: malformed scalar/array types must still report TYPE.
        $fProp=Get-ProvenanceProp $candidate 'frameNumbers'
        $qProp=Get-ProvenanceProp $candidate 'questionIndices'
        $nProp=Get-ProvenanceProp $candidate 'selectedRecordCount'
        # Type validation must precede ANY count comparison. A forged string
        # "3" must produce a stable PROV_SCHEMA_TYPE rejection, not an
        # incidental PowerShell coercion or runtime exception. This is only
        # the scalar precheck; standalone array lengths remain checked by
        # the schema validator after the cross-field cardinality check.
        if($null -ne $nProp -and
           -not (Test-IntegerValue $nProp.Value)) {
            Fail-Provenance 'PROV_SCHEMA_TYPE'
        }
        if($null -ne $fProp -and $null -ne $qProp -and $null -ne $nProp -and
           $fProp.Value -is [array] -and $qProp.Value -is [array]) {
            if($fProp.Value.Count -ne $qProp.Value.Count -or
               $fProp.Value.Count -ne [int]$nProp.Value) {
                Fail-Provenance 'PROV_SCHEMA_CARDINALITY'
            }
        }
        foreach($name in $required) {
            $prop=Get-ProvenanceProp $candidate $name
            if($null -eq $prop) { Fail-Provenance 'PROV_SCHEMA_REQUIRED_FIELD' }
            Assert-ProvenanceValue $name $prop.Value $schema.properties.PSObject.Properties[$name].Value
        }
        if([int]$candidate.schemaVersion -ne 2) {
            Fail-Provenance 'PROV_SCHEMA_VERSION'
        }
        if(-not $seenSample.Add([string]$candidate.sample)) {
            Fail-Provenance 'PROV_BATCH_DUPLICATE_SAMPLE'
        }
        $slot=@($slots | Where-Object {
            [IO.Path]::GetFileNameWithoutExtension([string]$_.file) -ceq [string]$candidate.sample
        })
        if($slot.Count -ne 1 -or
           [string]$slot[0].classification -cne [string]$candidate.classification) {
            Fail-Provenance 'PROV_BATCH_SHAPE:SLOT_MAPPING'
        }
        $frames=@($candidate.frameNumbers)
        $ordinals=@($candidate.questionIndices)
        if($frames.Count -ne $ordinals.Count -or
           $frames.Count -ne [int]$candidate.selectedRecordCount) {
            Fail-Provenance 'PROV_SCHEMA_CARDINALITY'
        }
        $localQuestion=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        for($i=0;$i -lt $frames.Count;$i++) {
            $key=[string]$candidate.captureSha256+':'+$frames[$i]+':'+$ordinals[$i]
            if(-not $localQuestion.Add($key)) {
                Fail-Provenance 'PROV_SCHEMA_DUPLICATE_QUESTION'
            }
            if(-not $seenQuestion.Add($key)) {
                Fail-Provenance 'PROV_BATCH_DUPLICATE_QUESTION'
            }
        }
        if([string]$candidate.classification -ceq 'Malicious') {
            if(-not $maliciousAddresses.Add([string]$candidate.sourceAddress)) {
                Fail-Provenance 'PROV_BATCH_IP_COLLISION'
            }
            if(-not $maliciousSessions.Add([string]$candidate.collectionSessionId)) {
                Fail-Provenance 'PROV_BATCH_SESSION_COLLISION'
            }
            if(-not $maliciousOrigins.Add([string]$candidate.originatingClientLabel)) {
                Fail-Provenance 'PROV_BATCH_ORIGIN_COLLISION'
            }
        }
    }
    if(@($Candidates | Where-Object {$_.classification -ceq 'Benign'}).Count -ne 2 -or
       @($Candidates | Where-Object {$_.classification -ceq 'Malicious'}).Count -ne 2) {
        Fail-Provenance 'PROV_BATCH_SHAPE:CLASS_COUNTS'
    }
    return [pscustomobject][ordered]@{
        CandidateCount=4
        SchemaValid=$true
        RequiresHumanReview=$true
        IsApproved=$false
        ApprovalState='PENDING_EXTERNAL_CAPTURE_AND_REVIEW'
    }
}
Export-ModuleMember -Function Confirm-HoldoutV2ProvenanceBatch
