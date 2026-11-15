# SPDX-License-Identifier: MIT
[CmdletBinding()]
param([string]$RuntimeDirectory,[string[]]$HealthPaths,[switch]$SelfTest)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Read-Number($value) {
    if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) { throw 'Missing numeric evidence' }
    $n=[double]$value
    if ([double]::IsNaN($n) -or [double]::IsInfinity($n) -or $n -lt 0) { throw 'Invalid numeric evidence' }
    return $n
}
function Read-Time($value) {
    if ($null -eq $value -or [string]$value -notmatch '(Z|[+-]\d\d:\d\d)$') { throw 'Timestamp must include offset' }
    return [DateTimeOffset]::Parse([string]$value,[Globalization.CultureInfo]::InvariantCulture)
}
function Get-Delta($a,$b) {
    $d=(Read-Number $b)-(Read-Number $a)
    if ($d -lt 0) { throw 'Lifetime counter decreased' }
    return $d
}
function Get-ProviderIntervals($before,$after) {
    $result=[ordered]@{}
    foreach ($name in @('whois','reputation','vpn-proxy')) {
        if ($null -eq $before -or $null -eq $after) { continue }
        $a=$before.PSObject.Properties[$name]; $b=$after.PSObject.Properties[$name]
        if ($null -eq $a -or $null -eq $b) { continue }
        $d=[ordered]@{}
        $total=0
        foreach ($field in @('Success','Unavailable','Failed','TimedOut','Cancelled')) {
            $d[$field]=Get-Delta $a.Value.$field $b.Value.$field
            $total+=$d[$field]
        }
        $d['CacheHits']=Get-Delta $a.Value.CacheHits $b.Value.CacheHits
        $ms=Get-Delta $a.Value.TotalElapsedMs $b.Value.TotalElapsedMs
        $d['outcomes']=$total
        $d['meanElapsedMs']=$null
        $d['successShare']=$null
        if ($total -gt 0) { $d['meanElapsedMs']=$ms/$total; $d['successShare']=$d['Success']/$total }
        $result[$name]=[pscustomobject]$d
    }
    return [pscustomobject]$result
}
function Get-OptionalEvidence($snapshot,$name) {
    if ($null -eq $snapshot) { return $null }
    $p=$snapshot.PSObject.Properties[$name]
    if ($null -ne $p) { return $p.Value }
    return $null
}
function Get-GeoLookupInterval($a,$b) {
    if ($null -eq $a -or $null -eq $b) { return $null }
    $found=Get-Delta $a.Found $b.Found
    $notFound=Get-Delta $a.NotFound $b.NotFound
    $failed=Get-Delta $a.Failed $b.Failed
    $attempts=$found+$notFound+$failed
    $share=$null
    if ($attempts -gt 0) { $share=$failed/$attempts }
    return [pscustomobject]@{attempts=$attempts;found=$found;notFound=$notFound;failed=$failed;failureShare=$share}
}
function Get-GeoCacheInterval($a,$b) {
    if ($null -eq $a -or $null -eq $b) { return $null }
    $positive=Get-Delta $a.PositiveHits $b.PositiveHits
    $negative=Get-Delta $a.NegativeHits $b.NegativeHits
    $misses=Get-Delta $a.Misses $b.Misses
    $requests=$positive+$negative+$misses
    $share=$null
    if ($requests -gt 0) { $share=($positive+$negative)/$requests }
    return [pscustomobject]@{requests=$requests;positiveHits=$positive;negativeHits=$negative;misses=$misses;hitShare=$share;expired=(Get-Delta $a.Expired $b.Expired);evicted=(Get-Delta $a.Evicted $b.Evicted);occupancy=(Read-Number $b.Occupancy);capacity=(Read-Number $b.Capacity)}
}
function Get-CheckpointInterval($a,$b) {
    if ($null -eq $a -or $null -eq $b) { return $null }
    return [pscustomobject]@{writes=(Get-Delta $a.checkpointWrites $b.checkpointWrites);failures=(Get-Delta $a.checkpointFailures $b.checkpointFailures);diagnosticPresent=$b.checkpointDiagnosticPresent}
}
function Analyze($meta,$rows,$health) {
    if ($meta.status -ne 'sampling-completed' -or $rows.Count -lt 2 -or $rows.Count -ne $meta.samples) { throw 'Incomplete process evidence' }
    $start=Read-Time $meta.processStartUtc
    $first=$rows[0]; $last=$rows[-1]
    $prev=$null
    foreach ($r in $rows) {
        $t=Read-Time $r.utc
        if ($t -lt $start) { throw 'Sample predates process' }
        foreach ($field in @('elapsedSeconds','privateBytes','workingSetBytes','threads','cpuSeconds')) { Read-Number $r.$field | Out-Null }
        if ($null -ne $prev) {
            if ($t -le (Read-Time $prev.utc) -or (Read-Number $r.elapsedSeconds) -le (Read-Number $prev.elapsedSeconds)) { throw 'Process sample chronology invalid' }
            Get-Delta $prev.cpuSeconds $r.cpuSeconds | Out-Null
        }
        $prev=$r
    }
    $duration=(Read-Number $last.elapsedSeconds)-(Read-Number $first.elapsedSeconds)
    $cores=Read-Number $meta.logicalProcessors
    if ($cores -lt 1 -or $cores -ne [Math]::Floor($cores)) { throw 'Invalid processor count' }
    $intervals=@()
    $prev=$null
    foreach ($h in $health) {
        $t=Read-Time $h.sampledUtc
        if ($h.schemaVersion -ne 1 -or $h.processId -ne $meta.processId -or (Read-Time $h.processStartedUtc) -ne $start) { throw 'Health identity/schema mismatch' }
        if ($t -lt (Read-Time $first.utc) -or $t -gt (Read-Time $last.utc)) { throw 'Health snapshot outside sample window' }
        if ($null -ne $prev) {
            $seconds=($t-(Read-Time $prev.sampledUtc)).TotalSeconds
            if ($seconds -le 0) { throw 'Health chronology invalid' }
            $published=$null; $rate=$null; $ratio=$null; $mean=$null
            $fallback=Get-Delta $prev.fallbacks $h.fallbacks
            if ($null -ne $prev.coverage -and $null -ne $h.coverage) {
                $published=Get-Delta $prev.coverage.Published $h.coverage.Published
                $rate=$published/$seconds
                if ($published -gt 0) { $ratio=$fallback/$published }
            }
            if ($null -ne $prev.workers -and $null -ne $h.workers) {
                $terminal=0
                foreach ($field in @('Returned','Cancelled','Faulted')) { $terminal+=Get-Delta $prev.workers.$field $h.workers.$field }
                $ms=Get-Delta $prev.workers.ElapsedTotalMs $h.workers.ElapsedTotalMs
                if ($terminal -gt 0) { $mean=$ms/$terminal }
            }
            $intervals+= [pscustomobject]@{fromUtc=$prev.sampledUtc;toUtc=$h.sampledUtc;seconds=$seconds;published=$published;publishedPerSecond=$rate;fallbackRequests=$fallback;fallbackPerPublished=$ratio;workerMeanElapsedMs=$mean;providers=(Get-ProviderIntervals $prev.providers $h.providers);geoCity=(Get-GeoLookupInterval (Get-OptionalEvidence $prev 'geoCity') (Get-OptionalEvidence $h 'geoCity'));geoAsn=(Get-GeoLookupInterval (Get-OptionalEvidence $prev 'geoAsn') (Get-OptionalEvidence $h 'geoAsn'));geoCache=(Get-GeoCacheInterval (Get-OptionalEvidence $prev 'geoCache') (Get-OptionalEvidence $h 'geoCache'));checkpoints=(Get-CheckpointInterval (Get-OptionalEvidence $prev 'storage') (Get-OptionalEvidence $h 'storage'))}
        }
        $prev=$h
    }
    $growth=(Read-Number $last.privateBytes)-(Read-Number $first.privateBytes)
    return [pscustomobject]@{status='measured-not-qualified';checkoutHead=$meta.checkoutHead;processId=$meta.processId;seconds=$duration;privateBytesChange=$growth;privateBytesPerHour=$growth*3600/$duration;cpuPercent=100*(Get-Delta $first.cpuSeconds $last.cpuSeconds)/($duration*$cores);healthIntervals=$intervals;captureAccuracy='not-run';visual='not-run';performanceAcceptance='not-assessed'}
}
if ($SelfTest) {
    $m=[pscustomobject]@{status='sampling-completed';samples=2;processId=42;processStartUtc='2026-01-01T00:00:00Z';logicalProcessors=4;checkoutHead='fixture'}
    $rows=@(
        [pscustomobject]@{utc='2026-01-01T00:00:01Z';elapsedSeconds=1;privateBytes=100;workingSetBytes=80;threads=2;cpuSeconds=1},
        [pscustomobject]@{utc='2026-01-01T00:00:03Z';elapsedSeconds=3;privateBytes=120;workingSetBytes=90;threads=2;cpuSeconds=3})
    $h=@(
        [pscustomobject]@{schemaVersion=1;processId=42;processStartedUtc=$m.processStartUtc;sampledUtc=$rows[0].utc;fallbacks=0;coverage=[pscustomobject]@{Published=10};workers=$null;providers=$null},
        [pscustomobject]@{schemaVersion=1;processId=42;processStartedUtc=$m.processStartUtc;sampledUtc=$rows[1].utc;fallbacks=1;coverage=[pscustomobject]@{Published=14};workers=$null;providers=$null})
    $r=Analyze $m $rows $h
    if ($r.cpuPercent -ne 25 -or $r.privateBytesChange -ne 20 -or $r.healthIntervals[0].publishedPerSecond -ne 2 -or $r.healthIntervals[0].fallbackPerPublished -ne 0.25) { throw 'Valid fixture failed' }
    $h[1].coverage.Published=10
    if ($null -ne (Analyze $m $rows $h).healthIntervals[0].fallbackPerPublished) { throw 'Zero denominator accepted' }
    $h[1].coverage.Published=9
    $rejected=$false
    try { Analyze $m $rows $h | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw 'Counter reset accepted' }
    $h[1].coverage.Published=14; $h[1].processId=43
    $rejected=$false
    try { Analyze $m $rows $h | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw 'Identity mismatch accepted' }
    $p=[pscustomobject]@{whois=[pscustomobject]@{Success=1;Unavailable=0;Failed=0;TimedOut=0;Cancelled=0;CacheHits=2;TotalElapsedMs=10}}
    $q=[pscustomobject]@{whois=[pscustomobject]@{Success=2;Unavailable=0;Failed=0;TimedOut=0;Cancelled=1;CacheHits=5;TotalElapsedMs=30}}
    $d=(Get-ProviderIntervals $p $q).whois
    if ($d.outcomes -ne 2 -or $d.meanElapsedMs -ne 10 -or $d.successShare -ne 0.5 -or $d.CacheHits -ne 3) { throw 'Provider denominator fixture failed' }
    $d=(Get-ProviderIntervals $p $p).whois
    if ($null -ne $d.meanElapsedMs -or $null -ne $d.successShare) { throw 'Provider zero denominator fixture failed' }
    $rejected=$false
    try { Get-ProviderIntervals $q $p | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw 'Provider reset accepted' }
    $ga=[pscustomobject]@{Found=1;NotFound=2;Failed=0}
    $gb=[pscustomobject]@{Found=3;NotFound=3;Failed=1}
    $d=Get-GeoLookupInterval $ga $gb
    if ($d.attempts -ne 4 -or $d.failureShare -ne 0.25) { throw 'Geo lookup denominator fixture failed' }
    if ($null -ne (Get-GeoLookupInterval $ga $ga).failureShare -or $null -ne (Get-GeoLookupInterval $null $gb)) { throw 'Geo missing/zero fixture failed' }
    $ca=[pscustomobject]@{PositiveHits=1;NegativeHits=2;Misses=3;Expired=0;Evicted=0;Occupancy=5;Capacity=8}
    $cb=[pscustomobject]@{PositiveHits=3;NegativeHits=3;Misses=4;Expired=1;Evicted=2;Occupancy=4;Capacity=8}
    $d=Get-GeoCacheInterval $ca $cb
    if ($d.requests -ne 4 -or $d.hitShare -ne 0.75 -or $d.occupancy -ne 4 -or $d.evicted -ne 2) { throw 'Geo cache fixture failed' }
    $sa=[pscustomobject]@{checkpointWrites=10;checkpointFailures=1;checkpointDiagnosticPresent=$false}
    $sb=[pscustomobject]@{checkpointWrites=11;checkpointFailures=1;checkpointDiagnosticPresent=$true}
    $d=Get-CheckpointInterval $sa $sb
    if ($d.writes -ne 1 -or $d.failures -ne 0 -or -not $d.diagnosticPresent) { throw 'Checkpoint diagnostic fixture failed' }
    $rejected=$false
    try { Get-GeoLookupInterval $gb $ga | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw 'Geo reset accepted' }
    Write-Host 'PASS: twelve analyzer fixtures'
    return
}
if (-not $RuntimeDirectory -or $HealthPaths.Count -lt 2) { throw 'Specify RuntimeDirectory and at least two chronological HealthPaths' }
$meta=Get-Content -LiteralPath (Join-Path $RuntimeDirectory 'runtime.json') -Raw | ConvertFrom-Json
$rows=@(Import-Csv -LiteralPath (Join-Path $RuntimeDirectory 'samples.csv'))
$health=@(foreach ($path in $HealthPaths) { Get-Content -LiteralPath $path -Raw | ConvertFrom-Json })
Analyze $meta $rows $health | ConvertTo-Json -Depth 6
