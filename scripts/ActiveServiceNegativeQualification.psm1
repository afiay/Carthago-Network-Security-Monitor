# SPDX-License-Identifier: MIT
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Read-ActiveRejectionFile([string]$Path) {
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt 4096) { throw 'Invalid rejection record size.' }
        $bytes=New-Object byte[] ([int]$stream.Length)
        $offset=0
        while ($offset -lt $bytes.Length) {
            $n=$stream.Read($bytes,$offset,$bytes.Length-$offset)
            if ($n -le 0) { throw 'Incomplete rejection record.' }
            $offset+=$n
        }
        if ($stream.ReadByte() -ne -1) { throw 'Rejection record changed.' }
        return ([Text.UTF8Encoding]::new($false,$true).GetString($bytes) | ConvertFrom-Json)
    } finally { $stream.Dispose() }
}
function ConvertTo-RejectionTime($value) {
    if ($value -is [DateTimeOffset]) { return $value }
    if ($value -is [DateTime] -and $value.Kind -ne [DateTimeKind]::Unspecified) { return [DateTimeOffset]$value }
    if ($value -isnot [string] -or $value -notmatch '(Z|[+-][0-9]{2}:[0-9]{2})$') { throw 'Timestamp offset required.' }
    return [DateTimeOffset]::Parse($value,[Globalization.CultureInfo]::InvariantCulture)
}
function Assert-ActiveRejectionRecord($Record,[string]$ExpectedReason,[string]$ConfigHash,[DateTimeOffset]$Attempt,[DateTimeOffset]$Now) {
    $keys=@('schemaVersion','attemptId','processId','processStartedUtc','rejectedUtc','configSha256','reason','readinessPublished')
    $actual=@($Record.PSObject.Properties.Name)
    if ($actual.Count -ne $keys.Count -or @($actual | Where-Object {$_ -cnotin $keys}).Count -ne 0) { throw 'Unexpected rejection schema.' }
    $start=ConvertTo-RejectionTime $Record.processStartedUtc
    $rejected=ConvertTo-RejectionTime $Record.rejectedUtc
    if ($Record.schemaVersion -ne 1 -or ($Record.processId -isnot [int] -and $Record.processId -isnot [long]) -or $Record.processId -le 0 -or
        [Guid]$Record.attemptId -eq [Guid]::Empty -or $Record.readinessPublished -isnot [bool] -or $Record.readinessPublished -or
        $Record.reason -cne $ExpectedReason -or $ExpectedReason -cnotin @('NoValidGrant','PinnedGrantMismatch','SnmpCredentialUnavailable') -or
        $ConfigHash -notmatch '^[0-9a-fA-F]{64}$' -or $Record.configSha256 -ine $ConfigHash -or
        $start -lt $Attempt -or $rejected -lt $start -or $rejected -gt $Now) { throw 'Rejection reason, configuration or attempt identity unconfirmed.' }
}
Export-ModuleMember -Function Read-ActiveRejectionFile,Assert-ActiveRejectionRecord
