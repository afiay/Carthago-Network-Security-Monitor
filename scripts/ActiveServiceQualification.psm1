# SPDX-License-Identifier: MIT
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Read-ActiveHealthFile([string]$Path) {
    $share=[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,$share)
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt 16384) { throw 'Invalid health snapshot length.' }
        $bytes=New-Object byte[] ([int]$stream.Length)
        $offset=0
        while ($offset -lt $bytes.Length) {
            $n=$stream.Read($bytes,$offset,$bytes.Length-$offset)
            if ($n -le 0) { throw 'Incomplete health snapshot.' }
            $offset+=$n
        }
        if ($stream.ReadByte() -ne -1) { throw 'Health snapshot changed while reading.' }
        return ([Text.UTF8Encoding]::new($false,$true).GetString($bytes) | ConvertFrom-Json)
    } finally { $stream.Dispose() }
}
function ConvertTo-ActiveTimestamp($Value) {
    if ($Value -is [DateTimeOffset]) { return $Value }
    if ($Value -is [DateTime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { throw 'Timestamp offset missing.' }
        return [DateTimeOffset]$Value
    }
    if ($Value -isnot [string] -or $Value -notmatch '(Z|[+-][0-9]{2}:[0-9]{2})$') { throw 'Timestamp offset missing.' }
    return [DateTimeOffset]::Parse($Value,[Globalization.CultureInfo]::InvariantCulture)
}
function ConvertTo-ActiveHealthSample($Sample,[int]$ProcessId,[DateTimeOffset]$ProcessStarted,[DateTimeOffset]$Now) {
    $keys=@('schemaVersion','sessionId','processId','processStartedUtc','sampleUtc','schedulerOwned',
        'profiles','blockedProfiles','pendingProfiles','profilesWithFailures','responsiveProfiles','completedProbes','responsiveProbes',
        'deferredChecks','storageFailures','lastResponsiveUtc','earliestGrantExpiryUtc','latestGrantExpiryUtc','assessment')
    $actual=@($Sample.PSObject.Properties.Name)
    if ($actual.Count -ne $keys.Count -or @($actual | Where-Object {$_ -cnotin $keys}).Count -ne 0) { throw 'Unexpected health schema.' }
    foreach ($key in @('schemaVersion','processId','profiles','blockedProfiles','pendingProfiles','profilesWithFailures',
        'responsiveProfiles','completedProbes','responsiveProbes','deferredChecks','storageFailures')) {
        $v=$Sample.$key
        if (($v -isnot [int] -and $v -isnot [long]) -or $v -lt 0) { throw 'Invalid health counter.' }
    }
    $session=[Guid]$Sample.sessionId
    $start=ConvertTo-ActiveTimestamp $Sample.processStartedUtc
    $time=ConvertTo-ActiveTimestamp $Sample.sampleUtc
    $earliest=ConvertTo-ActiveTimestamp $Sample.earliestGrantExpiryUtc
    $latest=ConvertTo-ActiveTimestamp $Sample.latestGrantExpiryUtc
    if ($Sample.schemaVersion -ne 2 -or $session -eq [Guid]::Empty -or $ProcessId -le 0 -or
        $Sample.processId -ne $ProcessId -or $Sample.schedulerOwned -isnot [bool] -or -not $Sample.schedulerOwned -or
        [Math]::Abs(($start-$ProcessStarted).TotalSeconds) -gt 1 -or
        $time -lt $start -or $time -gt $Now -or ($Now-$time).TotalSeconds -gt 30 -or
        $earliest -gt $latest -or $latest -le $start -or
        $Sample.profiles -lt 1 -or $Sample.profiles -gt 16 -or
        $Sample.blockedProfiles -gt $Sample.profiles -or $Sample.pendingProfiles -gt $Sample.profiles -or
        $Sample.profilesWithFailures -gt $Sample.profiles -or
        $Sample.responsiveProfiles -gt $Sample.profiles -or
        $Sample.responsiveProfiles -gt $Sample.responsiveProbes -or
        ($Sample.responsiveProbes -gt 0 -and $Sample.responsiveProfiles -eq 0) -or
        $Sample.responsiveProbes -gt $Sample.completedProbes -or $Sample.storageFailures -gt $Sample.completedProbes -or
        $Sample.assessment -cnotin @('Unavailable','Degraded','Pending','ResponsiveObserved')) { throw 'Invalid or stale health sample.' }
    $last=$null
    if ($null -ne $Sample.lastResponsiveUtc) {
        $last=ConvertTo-ActiveTimestamp $Sample.lastResponsiveUtc
        if ($last -lt $start -or $last -gt $time -or $Sample.responsiveProbes -eq 0) { throw 'Invalid responsive timestamp.' }
    } elseif ($Sample.responsiveProbes -ne 0) { throw 'Missing responsive timestamp.' }
    [pscustomobject][ordered]@{
        schemaVersion=2;sessionId=$session.ToString('D');processId=$ProcessId
        processStartedUtc=$start.ToUniversalTime().ToString('o');sampleUtc=$time.ToUniversalTime().ToString('o')
        schedulerOwned=$true;profiles=$Sample.profiles;blockedProfiles=$Sample.blockedProfiles
        pendingProfiles=$Sample.pendingProfiles;profilesWithFailures=$Sample.profilesWithFailures;responsiveProfiles=$Sample.responsiveProfiles
        completedProbes=$Sample.completedProbes;responsiveProbes=$Sample.responsiveProbes
        deferredChecks=$Sample.deferredChecks;storageFailures=$Sample.storageFailures
        lastResponsiveUtc=if($null -ne $last){$last.ToUniversalTime().ToString('o')}else{$null}
        earliestGrantExpiryUtc=$earliest.ToUniversalTime().ToString('o');latestGrantExpiryUtc=$latest.ToUniversalTime().ToString('o')
        assessment=$Sample.assessment
    }
}
function Assert-ActiveHealthProgress($Previous,$Current,[int]$ExpectedProfiles) {
    if ($Current.profiles -ne $ExpectedProfiles -or $Current.profiles -ne $Previous.profiles -or
        $Current.sessionId -cne $Previous.sessionId -or $Current.processId -ne $Previous.processId -or
        $Current.processStartedUtc -cne $Previous.processStartedUtc -or
        $Current.earliestGrantExpiryUtc -cne $Previous.earliestGrantExpiryUtc -or
        $Current.latestGrantExpiryUtc -cne $Previous.latestGrantExpiryUtc -or
        [DateTimeOffset]$Current.sampleUtc -lt [DateTimeOffset]$Previous.sampleUtc) { throw 'Service session or grant window changed.' }
    foreach ($key in @('completedProbes','responsiveProbes','responsiveProfiles','deferredChecks','storageFailures')) {
        if ($Current.$key -lt $Previous.$key) { throw 'Health counter regression.' }
    }
    if ($Previous.lastResponsiveUtc -and (-not $Current.lastResponsiveUtc -or
        [DateTimeOffset]$Current.lastResponsiveUtc -lt [DateTimeOffset]$Previous.lastResponsiveUtc)) { throw 'Responsive timestamp regressed.' }
}
function Test-ActiveObservedScope($Sample,[int]$ExpectedProfiles) {
    return ($Sample.profiles -eq $ExpectedProfiles -and $Sample.responsiveProfiles -eq $ExpectedProfiles -and
        $Sample.pendingProfiles -eq 0 -and $Sample.blockedProfiles -eq 0 -and $Sample.profilesWithFailures -eq 0 -and
        $Sample.storageFailures -eq 0 -and $Sample.deferredChecks -eq 0 -and
        $Sample.completedProbes -ge $ExpectedProfiles -and $Sample.responsiveProbes -ge $ExpectedProfiles -and
        $Sample.assessment -ceq 'ResponsiveObserved')
}
Export-ModuleMember -Function Read-ActiveHealthFile,ConvertTo-ActiveHealthSample,Assert-ActiveHealthProgress,Test-ActiveObservedScope
