# SPDX-License-Identifier: MIT
# Stage 8: read-only pending-review wire-to-legacy compatibility check.
# No imports, publication, freeze, labels, capture or original-source writes.
# Windows PowerShell 5.1 compatible. Error strings are fixed privacy-safe codes.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Fail-Bridge([string]$Code) { throw $Code }

# Private. Convert ONLY a byte-exact, canonical, lower-case ASCII DNS name.
# Legacy replay cannot express binary octets, embedded dots, or original
# upper-case octets without a lossy presentation-string transformation.
function Convert-BridgeWireLabelsToLegacyName([object]$Labels) {
    if($null -eq $Labels -or $Labels -isnot [array] -or
       $Labels.Count -lt 2 -or $Labels.Count -gt 127) {
        Fail-Bridge 'BRIDGE_NAME_NOT_LOSSLESS'
    }
    $result=[Collections.Generic.List[string]]::new()
    $wireLength=1
    $textLength=0
    foreach($encoded in $Labels) {
        if($encoded -isnot [string] -or $encoded.Length -eq 0) {
            Fail-Bridge 'BRIDGE_NAME_NOT_LOSSLESS'
        }
        $bytes=$null
        try { $bytes=[Convert]::FromBase64String([string]$encoded) }
        catch { Fail-Bridge 'BRIDGE_NAME_NOT_LOSSLESS' }
        if($bytes.Length -lt 1 -or $bytes.Length -gt 63 -or
           [Convert]::ToBase64String($bytes) -cne [string]$encoded) {
            Fail-Bridge 'BRIDGE_NAME_NOT_LOSSLESS'
        }
        $wireLength+=($bytes.Length+1)
        $textLength+=$bytes.Length
        if($wireLength -gt 255) { Fail-Bridge 'BRIDGE_NAME_NOT_LOSSLESS' }
        $chars=New-Object char[] $bytes.Length
        for($i=0;$i -lt $bytes.Length;$i++) {
            $octet=[int]$bytes[$i]
            if(($octet -ge 97 -and $octet -le 122) -or
               ($octet -ge 48 -and $octet -le 57) -or
               $octet -eq 45 -or $octet -eq 95) {
                $chars[$i]=[char]$octet
            } else {
                Fail-Bridge 'BRIDGE_NAME_NOT_LOSSLESS'
            }
        }
        $result.Add((-join $chars))
    }
    $textLength+=($Labels.Count-1)
    if($textLength -gt 253) { Fail-Bridge 'BRIDGE_NAME_NOT_LOSSLESS' }
    return ($result -join '.')
}

# Source-bound *diagnostic*, not a projection or admission API. Reuse the
# already-verified DnsWirePcap original PCAP + frame + question binder.
# The separate 30-field/four-slot schema, license, privacy, independent
# label review and downstream publisher/evaluator remain mandatory later.
function Confirm-HoldoutV2WireReplayCompatibility {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$CapturePath,
        [Parameter(Mandatory=$true)][object]$Provenance,
        [Parameter(Mandatory=$true)][object[]]$Records,
        [string]$TsharkPath='tshark'
    )
    if($null -eq $Provenance -or
       $null -eq $Provenance.PSObject.Properties['schemaVersion']) {
        Fail-Bridge 'BRIDGE_PENDING_ONLY'
    }
    $version=$Provenance.schemaVersion
    if(($version -isnot [int] -and $version -isnot [long]) -or
       [int]$version -ne 2 -or
       [string]$Provenance.reviewState -cne 'PENDING_EXTERNAL_CAPTURE_AND_REVIEW' -or
       [string]$Provenance.dnsWireNameEncoding -cne 'labels-base64-v1' -or
       [string]$Provenance.sourceKind -cne 'external-pcap-reviewed' -or
       $Provenance.privacyReviewRequired -isnot [bool] -or
       -not [bool]$Provenance.privacyReviewRequired -or
       $Provenance.analystReviewedLabel -isnot [bool] -or
       $Provenance.capturedTransportEvidence -isnot [bool]) {
        Fail-Bridge 'BRIDGE_PENDING_ONLY'
    }
    $declaredCount=$Provenance.selectedRecordCount
    if($null -eq $Records -or $Records.Count -lt 3 -or
       $Records.Count -gt 500 -or
       ($declaredCount -isnot [int] -and $declaredCount -isnot [long]) -or
       [int]$declaredCount -ne $Records.Count) {
        Fail-Bridge 'BRIDGE_CARDINALITY'
    }
    $root=[string]$Provenance.queryRoot
    if($root -cnotmatch '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$' -or
       $root.Length -gt 253) {
        Fail-Bridge 'BRIDGE_ROOT_INVALID'
    }

    # Never trust applicant fields as source proof. TShark reads ONLY the
    # owner-supplied local original PCAP; the binder verifies SHA-256, exact
    # original frame/question, original binary name and TCP/UDP/IP/port/QTYPE.
    # Suppress any underlying exception details to protect sensitive data.
    $module=Join-Path $PSScriptRoot 'DnsWirePcap.psm1'
    $binding=$null
    try {
        Import-Module -Name $module -ErrorAction Stop
        $args=@{
            CapturePath=$CapturePath
            Provenance=$Provenance
            Records=$Records
            TsharkPath=$TsharkPath
        }
        $binding=Confirm-DnsWireCandidateBinding @args
    } catch { Fail-Bridge 'BRIDGE_SOURCE_BINDING_FAILED' }
    if($null -eq $binding -or
       [int]$binding.MatchedQuestionCount -ne $Records.Count -or
       [string]$binding.CaptureSha256 -cne ([string]$Provenance.captureSha256).ToLowerInvariant()) {
        Fail-Bridge 'BRIDGE_SOURCE_BINDING_FAILED'
    }
    foreach($record in $Records) {
        $name=Convert-BridgeWireLabelsToLegacyName $record.dnsWireLabelsBase64
        if($name -cne $root -and
           -not $name.EndsWith('.'+$root,[StringComparison]::Ordinal)) {
            Fail-Bridge 'BRIDGE_ROOT_MISMATCH'
        }
    }
    # No projected records or DNS names leave this API. Even a true result
    # permits NEITHER private publication NOR human-source approval.
    return [pscustomobject][ordered]@{
        OriginalFrameQuestionsBound=$true
        TextProjectionPossible=$true
        ProjectionProduced=$false
        RecordCount=[int]$Records.Count
        ReviewState='PENDING_EXTERNAL_CAPTURE_AND_REVIEW'
        RequiresHumanReview=$true
        IsApproved=$false
        CanPublish=$false
        CanFreeze=$false
    }
}
Export-ModuleMember -Function Confirm-HoldoutV2WireReplayCompatibility
