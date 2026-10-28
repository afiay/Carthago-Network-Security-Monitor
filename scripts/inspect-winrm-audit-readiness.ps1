# SPDX-License-Identifier: MIT
# Read-only local Windows Security audit readiness check for R343.
# Never prints event XML, usernames, command lines, message bodies or tokens.
[CmdletBinding()]
param(
    [switch]$InspectRecentEvents,
    [ValidateRange(1, 120)][int]$LookbackMinutes = 30
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host 'CARTHAGO R343 WINDOWS AUDIT READINESS'
Write-Host 'Mode: read-only, unsigned candidate readiness; NEVER trusted execution attestation.'
Write-Host ('Recent-event inspection: {0}' -f [bool]$InspectRecentEvents)

if (-not [Environment]::OSVersion.Platform.Equals([PlatformID]::Win32NT)) {
    Write-Host 'Windows Security event source: NOT AVAILABLE (Windows only).'
    Write-Host 'STATUS: NOT READY — no audit events queried.'
    return
}

# This registry policy indicates whether Security 4688 may INCLUDE the
# command line. The separate Process Creation success-audit policy and the
# actual presence/content of Security events must also be verified.
$registryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$commandLinePolicy = 'UNKNOWN'
try {
    $policy = Get-ItemProperty -LiteralPath $registryPath -ErrorAction Stop
    if ($null -ne $policy.PSObject.Properties['ProcessCreationIncludeCmdLine_Enabled']) {
        $value = [int]$policy.ProcessCreationIncludeCmdLine_Enabled
        $commandLinePolicy = if ($value -eq 1) { 'CONFIGURED' } else { 'NOT CONFIGURED' }
    }
} catch {
    $commandLinePolicy = 'UNKNOWN (registry policy unreadable)'
}
Write-Host ('4688 include-command-line policy: {0}' -f $commandLinePolicy)
Write-Host 'Process Creation audit success policy: NOT VERIFIED (separate requirement).'

# Check Security log access without requesting elevation or reading records.
$logReadable = $false
try {
    $metadata = Get-WinEvent -ListLog Security -ErrorAction Stop
    if ($null -ne $metadata) {
        $logReadable = $true
    }
} catch [System.UnauthorizedAccessException] {
    Write-Host 'Security channel: ACCESS DENIED'
} catch {
    # Keep exception details private; Windows error text can disclose machine
    # names or paths and should not become part of a shared verification log.
    Write-Host 'Security channel: UNAVAILABLE OR NOT READABLE'
}
if ($logReadable) { Write-Host 'Security channel: metadata readable' }

if (-not $InspectRecentEvents) {
    Write-Host 'Recent 4624/4688 observations: NOT INSPECTED (opt in with -InspectRecentEvents).'
    Write-Host 'STATUS: READINESS ONLY — no events were inspected or signed.'
    return
}
if (-not $logReadable) {
    Write-Host 'STATUS: NOT READY — cannot inspect the local Security channel.'
    return
}

$from = (Get-Date).AddMinutes(-$LookbackMinutes)
foreach ($id in @(4624, 4688)) {
    $state = 'NOT OBSERVED'
    try {
        # Filter at the Windows event log provider; retrieve at most one
        # matching event for each ID. Do NOT access Message, ToXml,
        # Properties, UserId, MachineName, or the process command line.
        $event = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = $id
            StartTime = $from
        } -MaxEvents 1 -ErrorAction Stop
        if ($null -ne $event) {
            $state = 'OBSERVED (metadata only)'
        }
    } catch [System.UnauthorizedAccessException] {
        $state = 'ACCESS DENIED'
    } catch {
        $state = 'NOT OBSERVED OR UNAVAILABLE'
    }
    Write-Host ('Security {0} in last {1} minutes: {2}' -f
        $id, $LookbackMinutes, $state)
}
Write-Host 'STATUS: AUDIT READINESS CHECKED; no operation/outcome verified.'
Write-Host 'R343 remains blocked until authenticated source, process/session and outcome validation.'
