# SPDX-License-Identifier: MIT
# Read-only R343 Windows audit readiness. NEVER authenticates an operation.
# Do not print event XML, event Message, usernames, command lines or tokens.
[CmdletBinding()]
param(
    [switch]$InspectRecentEvents,
    [switch]$InspectAuditPolicy,
    [ValidateRange(1,120)][int]$LookbackMinutes = 30
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-SafeFailureCode {
    param([System.Management.Automation.ErrorRecord]$Failure)
    # Do not print exception.Message: the provider may embed machine names,
    # paths, or other sensitive strings in human-readable error messages.
    $id = [string]$Failure.FullyQualifiedErrorId
    if ($id -match '(^|,)NoMatchingEventsFound(,|$)') {
        return 'NO_MATCHING_EVENTS'
    }
    $exception = $Failure.Exception
    $firstType = if ($null -ne $exception) { $exception.GetType().Name } else { 'Unknown' }
    $firstHr = if ($null -ne $exception) {
        ('0x{0:X8}' -f [int]$exception.HResult)
    } else { 'UNKNOWN' }
    while ($null -ne $exception) {
        if ($exception -is [System.UnauthorizedAccessException] -or
            $exception -is [System.Security.SecurityException] -or
            $exception.HResult -eq -2147024891 -or
            ($exception -is [System.ComponentModel.Win32Exception] -and
                $exception.NativeErrorCode -eq 5)) {
            return 'ACCESS_DENIED'
        }
        if ($exception -is [System.Management.Automation.CommandNotFoundException]) {
            return 'COMMAND_UNAVAILABLE'
        }
        if ($exception.GetType().Name -eq 'EventLogNotFoundException') {
            return 'LOG_NOT_FOUND'
        }
        $exception = $exception.InnerException
    }
    # A stable error class and HRESULT are useful for diagnosing missing
    # channels/providers without exposing provider-specific message text.
    return ('OTHER_ERROR ({0}; {1})' -f $firstType, $firstHr)
}

Write-Host 'CARTHAGO R343 WINDOWS AUDIT READINESS'
Write-Host 'Mode: read-only, unsigned candidate readiness; NEVER trusted execution attestation.'
Write-Host ('Recent-event inspection: {0}' -f [bool]$InspectRecentEvents)
Write-Host ('Process-creation policy inspection: {0}' -f [bool]$InspectAuditPolicy)

if (-not [Environment]::OSVersion.Platform.Equals([PlatformID]::Win32NT)) {
    Write-Host 'Windows Security event source: UNAVAILABLE (Windows only).'
    Write-Host 'STATUS: NOT READY — no audit events queried.'
    return
}

try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    Write-Host ('Elevated administrator token: {0}' -f
        $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
} catch {
    Write-Host 'Elevated administrator token: UNKNOWN'
}

try {
    $service = Get-Service -Name EventLog -ErrorAction Stop
    Write-Host ('Windows Event Log service: {0}' -f $service.Status)
} catch {
    Write-Host ('Windows Event Log service: {0}' -f (Get-SafeFailureCode $_))
}

# Absence of this policy value is different from an access failure.
# The other "Audit Process Creation" success setting is independent.
$registryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$commandLinePolicy = 'NOT SET (local policy value absent)'
try {
    $policy = Get-ItemProperty -LiteralPath $registryPath -ErrorAction Stop
    if ($null -ne $policy.PSObject.Properties['ProcessCreationIncludeCmdLine_Enabled']) {
        $value = [int]$policy.ProcessCreationIncludeCmdLine_Enabled
        $commandLinePolicy = if ($value -eq 1) {
            'CONFIGURED'
        } elseif ($value -eq 0) {
            'DISABLED'
        } else {
            'UNKNOWN (unexpected policy value)'
        }
    }
} catch {
    if ($_.Exception -is [System.Management.Automation.ItemNotFoundException] -or
        $_.FullyQualifiedErrorId -match '(PathNotFound|ItemNotFound)') {
        $commandLinePolicy = 'NOT SET (local policy path absent)'
    } else {
        $commandLinePolicy = 'UNKNOWN (' + (Get-SafeFailureCode $_) + ')'
    }
}
Write-Host ('4688 include-command-line policy: {0}' -f $commandLinePolicy)
# Opt-in, read-only audit policy query. The /r switch requests CSV,
# but column names and values can be localized. Unknown formats fail closed.
$processCreationStatus = 'NOT INSPECTED (use -InspectAuditPolicy)'
if ($InspectAuditPolicy) {
    $subcategory = '{0CCE922B-69AE-11D9-BED3-505054503030}'
    try {
        $reportLines = @(& auditpol.exe /get "/subcategory:$subcategory" /r 2>$null)
        $auditExitCode = $LASTEXITCODE
        if ($auditExitCode -eq 0 -and $reportLines.Count -gt 1) {
            $csvRows = @($reportLines | ConvertFrom-Csv -ErrorAction Stop)
            $matches = @($csvRows | Where-Object {
                $_.'Subcategory GUID' -eq $subcategory
            })
            if ($matches.Count -eq 1) {
                $setting = [string]$matches[0].'Inclusion Setting'
                switch -Regex ($setting.Trim()) {
                    '^No Auditing

# A failure to read channel configuration does NOT prove that the event
# queries will fail, so never use this metadata result as a query gate.
$metadataStatus = 'NOT READABLE'
try {
    $metadata = Get-WinEvent -ListLog Security -ErrorAction Stop
    if ($null -ne $metadata) { $metadataStatus = 'READABLE' }
} catch {
    $metadataStatus = Get-SafeFailureCode $_
}
Write-Host ('Security channel metadata: {0}' -f $metadataStatus)

if (-not $InspectRecentEvents) {
    Write-Host 'Recent 4624/4688 observations: NOT INSPECTED (opt in with -InspectRecentEvents).'
    Write-Host 'STATUS: READINESS ONLY — no events inspected, permissions changed or claims signed.'
    return
}

# Probe event existence independently, even if -ListLog Security failed.
# No event XML, Message, Properties, identity or command line is accessed.
$from = (Get-Date).AddMinutes(-$LookbackMinutes)
$observed = 0
$unavailable = 0
foreach ($id in @(4624,4688)) {
    $state = 'NOT VERIFIED'
    try {
        $event = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = $id
            StartTime = $from
        } -MaxEvents 1 -ErrorAction Stop
        if ($null -ne $event) {
            $state = 'OBSERVED (event ID only)'
            $observed++
        }
    } catch {
        $failure = Get-SafeFailureCode $_
        if ($failure -eq 'NO_MATCHING_EVENTS') {
            # If the caller cannot read channel metadata, a no-match
            # query response does not independently establish that the
            # Security channel was accessible or auditing was enabled.
            $state = if ($metadataStatus -eq 'READABLE') {
                'NO MATCHING EVENTS (selected window)'
            } else {
                'NO MATCHES REPORTED (log access unverified)'
            }
        } else {
            $state = $failure
            $unavailable++
        }
    } finally {
        $event = $null
    }
    Write-Host ('Security {0} in last {1} minutes: {2}' -f
        $id, $LookbackMinutes, $state)
}

if ($unavailable -gt 0) {
    Write-Host 'STATUS: NOT READY — at least one Security event query failed.'
} elseif ($metadataStatus -eq 'ACCESS_DENIED' -and $observed -eq 0) {
    Write-Host 'STATUS: ACCESS UNVERIFIED — metadata denied and no events returned; neither log readability nor event absence is established.'
} elseif ($metadataStatus -ne 'READABLE' -and $observed -eq 0) {
    Write-Host 'STATUS: ACCESS UNVERIFIED — no metadata confirmation or returned events.'
} elseif ($observed -lt 2) {
    Write-Host 'STATUS: INCOMPLETE — one or both event IDs not returned in the selected window.'
} else {
    Write-Host 'STATUS: EVENT IDS OBSERVED — auditing policy, event fields and authenticated outcome remain NOT VERIFIED.'
}
Write-Host 'No events modified or signed. R343 remains blocked pending authenticated source, session and outcome evidence.'
       { $processCreationStatus = 'NO AUDITING'; break }
                    '^Success

# A failure to read channel configuration does NOT prove that the event
# queries will fail, so never use this metadata result as a query gate.
$metadataStatus = 'NOT READABLE'
try {
    $metadata = Get-WinEvent -ListLog Security -ErrorAction Stop
    if ($null -ne $metadata) { $metadataStatus = 'READABLE' }
} catch {
    $metadataStatus = Get-SafeFailureCode $_
}
Write-Host ('Security channel metadata: {0}' -f $metadataStatus)

if (-not $InspectRecentEvents) {
    Write-Host 'Recent 4624/4688 observations: NOT INSPECTED (opt in with -InspectRecentEvents).'
    Write-Host 'STATUS: READINESS ONLY — no events inspected, permissions changed or claims signed.'
    return
}

# Probe event existence independently, even if -ListLog Security failed.
# No event XML, Message, Properties, identity or command line is accessed.
$from = (Get-Date).AddMinutes(-$LookbackMinutes)
$observed = 0
$unavailable = 0
foreach ($id in @(4624,4688)) {
    $state = 'NOT VERIFIED'
    try {
        $event = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = $id
            StartTime = $from
        } -MaxEvents 1 -ErrorAction Stop
        if ($null -ne $event) {
            $state = 'OBSERVED (event ID only)'
            $observed++
        }
    } catch {
        $failure = Get-SafeFailureCode $_
        if ($failure -eq 'NO_MATCHING_EVENTS') {
            # If the caller cannot read channel metadata, a no-match
            # query response does not independently establish that the
            # Security channel was accessible or auditing was enabled.
            $state = if ($metadataStatus -eq 'READABLE') {
                'NO MATCHING EVENTS (selected window)'
            } else {
                'NO MATCHES REPORTED (log access unverified)'
            }
        } else {
            $state = $failure
            $unavailable++
        }
    } finally {
        $event = $null
    }
    Write-Host ('Security {0} in last {1} minutes: {2}' -f
        $id, $LookbackMinutes, $state)
}

if ($unavailable -gt 0) {
    Write-Host 'STATUS: NOT READY — at least one Security event query failed.'
} elseif ($metadataStatus -eq 'ACCESS_DENIED' -and $observed -eq 0) {
    Write-Host 'STATUS: ACCESS UNVERIFIED — metadata denied and no events returned; neither log readability nor event absence is established.'
} elseif ($metadataStatus -ne 'READABLE' -and $observed -eq 0) {
    Write-Host 'STATUS: ACCESS UNVERIFIED — no metadata confirmation or returned events.'
} elseif ($observed -lt 2) {
    Write-Host 'STATUS: INCOMPLETE — one or both event IDs not returned in the selected window.'
} else {
    Write-Host 'STATUS: EVENT IDS OBSERVED — auditing policy, event fields and authenticated outcome remain NOT VERIFIED.'
}
Write-Host 'No events modified or signed. R343 remains blocked pending authenticated source, session and outcome evidence.'
           { $processCreationStatus = 'SUCCESS AUDITING ENABLED'; break }
                    '^Success and Failure

# A failure to read channel configuration does NOT prove that the event
# queries will fail, so never use this metadata result as a query gate.
$metadataStatus = 'NOT READABLE'
try {
    $metadata = Get-WinEvent -ListLog Security -ErrorAction Stop
    if ($null -ne $metadata) { $metadataStatus = 'READABLE' }
} catch {
    $metadataStatus = Get-SafeFailureCode $_
}
Write-Host ('Security channel metadata: {0}' -f $metadataStatus)

if (-not $InspectRecentEvents) {
    Write-Host 'Recent 4624/4688 observations: NOT INSPECTED (opt in with -InspectRecentEvents).'
    Write-Host 'STATUS: READINESS ONLY — no events inspected, permissions changed or claims signed.'
    return
}

# Probe event existence independently, even if -ListLog Security failed.
# No event XML, Message, Properties, identity or command line is accessed.
$from = (Get-Date).AddMinutes(-$LookbackMinutes)
$observed = 0
$unavailable = 0
foreach ($id in @(4624,4688)) {
    $state = 'NOT VERIFIED'
    try {
        $event = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = $id
            StartTime = $from
        } -MaxEvents 1 -ErrorAction Stop
        if ($null -ne $event) {
            $state = 'OBSERVED (event ID only)'
            $observed++
        }
    } catch {
        $failure = Get-SafeFailureCode $_
        if ($failure -eq 'NO_MATCHING_EVENTS') {
            # If the caller cannot read channel metadata, a no-match
            # query response does not independently establish that the
            # Security channel was accessible or auditing was enabled.
            $state = if ($metadataStatus -eq 'READABLE') {
                'NO MATCHING EVENTS (selected window)'
            } else {
                'NO MATCHES REPORTED (log access unverified)'
            }
        } else {
            $state = $failure
            $unavailable++
        }
    } finally {
        $event = $null
    }
    Write-Host ('Security {0} in last {1} minutes: {2}' -f
        $id, $LookbackMinutes, $state)
}

if ($unavailable -gt 0) {
    Write-Host 'STATUS: NOT READY — at least one Security event query failed.'
} elseif ($metadataStatus -eq 'ACCESS_DENIED' -and $observed -eq 0) {
    Write-Host 'STATUS: ACCESS UNVERIFIED — metadata denied and no events returned; neither log readability nor event absence is established.'
} elseif ($metadataStatus -ne 'READABLE' -and $observed -eq 0) {
    Write-Host 'STATUS: ACCESS UNVERIFIED — no metadata confirmation or returned events.'
} elseif ($observed -lt 2) {
    Write-Host 'STATUS: INCOMPLETE — one or both event IDs not returned in the selected window.'
} else {
    Write-Host 'STATUS: EVENT IDS OBSERVED — auditing policy, event fields and authenticated outcome remain NOT VERIFIED.'
}
Write-Host 'No events modified or signed. R343 remains blocked pending authenticated source, session and outcome evidence.'
 { $processCreationStatus = 'SUCCESS AUDITING ENABLED'; break }
                    '^Failure

# A failure to read channel configuration does NOT prove that the event
# queries will fail, so never use this metadata result as a query gate.
$metadataStatus = 'NOT READABLE'
try {
    $metadata = Get-WinEvent -ListLog Security -ErrorAction Stop
    if ($null -ne $metadata) { $metadataStatus = 'READABLE' }
} catch {
    $metadataStatus = Get-SafeFailureCode $_
}
Write-Host ('Security channel metadata: {0}' -f $metadataStatus)

if (-not $InspectRecentEvents) {
    Write-Host 'Recent 4624/4688 observations: NOT INSPECTED (opt in with -InspectRecentEvents).'
    Write-Host 'STATUS: READINESS ONLY — no events inspected, permissions changed or claims signed.'
    return
}

# Probe event existence independently, even if -ListLog Security failed.
# No event XML, Message, Properties, identity or command line is accessed.
$from = (Get-Date).AddMinutes(-$LookbackMinutes)
$observed = 0
$unavailable = 0
foreach ($id in @(4624,4688)) {
    $state = 'NOT VERIFIED'
    try {
        $event = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = $id
            StartTime = $from
        } -MaxEvents 1 -ErrorAction Stop
        if ($null -ne $event) {
            $state = 'OBSERVED (event ID only)'
            $observed++
        }
    } catch {
        $failure = Get-SafeFailureCode $_
        if ($failure -eq 'NO_MATCHING_EVENTS') {
            # If the caller cannot read channel metadata, a no-match
            # query response does not independently establish that the
            # Security channel was accessible or auditing was enabled.
            $state = if ($metadataStatus -eq 'READABLE') {
                'NO MATCHING EVENTS (selected window)'
            } else {
                'NO MATCHES REPORTED (log access unverified)'
            }
        } else {
            $state = $failure
            $unavailable++
        }
    } finally {
        $event = $null
    }
    Write-Host ('Security {0} in last {1} minutes: {2}' -f
        $id, $LookbackMinutes, $state)
}

if ($unavailable -gt 0) {
    Write-Host 'STATUS: NOT READY — at least one Security event query failed.'
} elseif ($metadataStatus -eq 'ACCESS_DENIED' -and $observed -eq 0) {
    Write-Host 'STATUS: ACCESS UNVERIFIED — metadata denied and no events returned; neither log readability nor event absence is established.'
} elseif ($metadataStatus -ne 'READABLE' -and $observed -eq 0) {
    Write-Host 'STATUS: ACCESS UNVERIFIED — no metadata confirmation or returned events.'
} elseif ($observed -lt 2) {
    Write-Host 'STATUS: INCOMPLETE — one or both event IDs not returned in the selected window.'
} else {
    Write-Host 'STATUS: EVENT IDS OBSERVED — auditing policy, event fields and authenticated outcome remain NOT VERIFIED.'
}
Write-Host 'No events modified or signed. R343 remains blocked pending authenticated source, session and outcome evidence.'
           { $processCreationStatus = 'SUCCESS AUDITING NOT ENABLED'; break }
                    default               { $processCreationStatus = 'UNKNOWN (localized or unsupported policy value)' }
                }
            } else {
                $processCreationStatus = 'UNKNOWN (policy CSV schema or GUID unmatched)'
            }
        } elseif ($auditExitCode -eq 1314) {
            $processCreationStatus = 'ACCESS DENIED (ERROR_PRIVILEGE_NOT_HELD / 0x522)'
        } elseif ($auditExitCode -ne 0) {
            $processCreationStatus = ('UNAVAILABLE (exit {0})' -f $auditExitCode)
        } else {
            $processCreationStatus = 'UNKNOWN (empty policy report)'
        }
    } catch {
        $processCreationStatus = 'UNKNOWN (' + (Get-SafeFailureCode $_) + ')'
    }
}
Write-Host ('Process Creation success-audit policy: {0}' -f $processCreationStatus)
if ($processCreationStatus -eq 'NO AUDITING' -or
    $processCreationStatus -eq 'SUCCESS AUDITING NOT ENABLED') {
    Write-Host 'R343 telemetry prerequisite: BLOCKED (4688 process-creation auditing is not enabled).'
}
if ($commandLinePolicy -ne 'CONFIGURED') {
    Write-Host 'R343 command-line prerequisite: NOT VERIFIED (4688 command-line field is not confirmed enabled).'
}

# A failure to read channel configuration does NOT prove that the event
# queries will fail, so never use this metadata result as a query gate.
$metadataStatus = 'NOT READABLE'
try {
    $metadata = Get-WinEvent -ListLog Security -ErrorAction Stop
    if ($null -ne $metadata) { $metadataStatus = 'READABLE' }
} catch {
    $metadataStatus = Get-SafeFailureCode $_
}
Write-Host ('Security channel metadata: {0}' -f $metadataStatus)

if (-not $InspectRecentEvents) {
    Write-Host 'Recent 4624/4688 observations: NOT INSPECTED (opt in with -InspectRecentEvents).'
    Write-Host 'STATUS: READINESS ONLY — no events inspected, permissions changed or claims signed.'
    return
}

# Probe event existence independently, even if -ListLog Security failed.
# No event XML, Message, Properties, identity or command line is accessed.
$from = (Get-Date).AddMinutes(-$LookbackMinutes)
$observed = 0
$unavailable = 0
foreach ($id in @(4624,4688)) {
    $state = 'NOT VERIFIED'
    try {
        $event = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = $id
            StartTime = $from
        } -MaxEvents 1 -ErrorAction Stop
        if ($null -ne $event) {
            $state = 'OBSERVED (event ID only)'
            $observed++
        }
    } catch {
        $failure = Get-SafeFailureCode $_
        if ($failure -eq 'NO_MATCHING_EVENTS') {
            # If the caller cannot read channel metadata, a no-match
            # query response does not independently establish that the
            # Security channel was accessible or auditing was enabled.
            $state = if ($metadataStatus -eq 'READABLE') {
                'NO MATCHING EVENTS (selected window)'
            } else {
                'NO MATCHES REPORTED (log access unverified)'
            }
        } else {
            $state = $failure
            $unavailable++
        }
    } finally {
        $event = $null
    }
    Write-Host ('Security {0} in last {1} minutes: {2}' -f
        $id, $LookbackMinutes, $state)
}

if ($unavailable -gt 0) {
    Write-Host 'STATUS: NOT READY — at least one Security event query failed.'
} elseif ($metadataStatus -eq 'ACCESS_DENIED' -and $observed -eq 0) {
    Write-Host 'STATUS: ACCESS UNVERIFIED — metadata denied and no events returned; neither log readability nor event absence is established.'
} elseif ($metadataStatus -ne 'READABLE' -and $observed -eq 0) {
    Write-Host 'STATUS: ACCESS UNVERIFIED — no metadata confirmation or returned events.'
} elseif ($observed -lt 2) {
    Write-Host 'STATUS: INCOMPLETE — one or both event IDs not returned in the selected window.'
} else {
    Write-Host 'STATUS: EVENT IDS OBSERVED — auditing policy, event fields and authenticated outcome remain NOT VERIFIED.'
}
Write-Host 'No events modified or signed. R343 remains blocked pending authenticated source, session and outcome evidence.'
