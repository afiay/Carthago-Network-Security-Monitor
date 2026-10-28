# SPDX-License-Identifier: MIT
# CARTHAGO R343 lab Stage 1: harmless local Security 4688 correlation smoke check.
# Does not enable policies, print command lines, or attest WinRM.
[CmdletBinding()]
param(
    [ValidateRange(1, 10)][int]$Attempts = 5,
    [ValidateRange(100, 4096)][int]$MaxEventsPerAttempt = 512
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or
    $env:COMPUTERNAME -ine 'CARTHAGE') {
    throw 'This smoke check is restricted to Windows host CARTHAGE.'
}
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An authorized elevated Windows PowerShell session is required.'
}

function Convert-WindowsEventProcessId {
    param([string]$Value)
    if ($Value -match '^0[xX]([0-9a-fA-F]{1,8})$') {
        return [Convert]::ToInt64($Matches[1], 16)
    }
    if ($Value -match '^[0-9]{1,10}$') {
        return [long]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture)
    }
    return $null
}

# Read the setting without displaying CSV (which can contain host information).
$subcategory = '{0CCE922B-69AE-11D9-BED3-505054503030}'
$report = @(& auditpol.exe /get "/subcategory:$subcategory" /r 2>$null)
if ($LASTEXITCODE -ne 0 -or $report.Count -lt 2) {
    throw 'Could not read Process Creation audit policy. No test process started.'
}
$rows = @($report | ConvertFrom-Csv -ErrorAction Stop)
$selected = @($rows | Where-Object { $_.'Subcategory GUID' -eq $subcategory })
if ($selected.Count -ne 1 -or
    [string]$selected[0].'Inclusion Setting' -notin @('Success','Success and Failure')) {
    throw 'Process Creation success auditing is not confirmed enabled. No test process started.'
}
Write-Host 'CARTHAGO 4688 LOCAL PROCESS CORRELATION'
Write-Host 'Policy: Process Creation success auditing enabled.'
Write-Host 'Scope: harmless local process; no WinRM, encoded command, or secret arguments.'

$executable = Join-Path $env:WINDIR 'System32\cmd.exe'
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw 'Built-in harmless test executable is missing.'
}
$startedAt = Get-Date
try {
    $process = Start-Process -FilePath $executable -ArgumentList '/d /c exit 0' -NoNewWindow -Wait -PassThru -ErrorAction Stop
    $targetId = [long]$process.Id
} catch {
    throw 'Harmless local process could not be started. No Security events inspected.'
}
Write-Host 'Harmless process created; checking Security 4688 by process ID and image path.'

$matched = $false
$scannedAny = $false
for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
    if ($attempt -gt 1) { Start-Sleep -Milliseconds 500 }
    try {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 4688
            StartTime = $startedAt.AddSeconds(-5)
        } -MaxEvents $MaxEventsPerAttempt -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') {
            continue
        }
        throw 'Security 4688 query failed. Event details have not been printed.'
    }
    foreach ($record in $events) {
        $scannedAny = $true
        if ($record.Id -ne 4688 -or
            $record.ProviderName -ne 'Microsoft-Windows-Security-Auditing' -or
            $record.LogName -ne 'Security') {
            continue
        }
        try {
            # XML stays in process memory and is never printed, persisted,
            # or copied; select only NewProcessId and NewProcessName fields.
            $xml = [System.Xml.XmlDocument]::new()
            $xml.XmlResolver = $null
            $xml.LoadXml($record.ToXml())
            $nodes = $xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")
            $fields = @{}
            foreach ($node in $nodes) {
                if ($node.HasAttribute('Name')) {
                    $name = [string]$node.GetAttribute('Name')
                    if ($name -eq 'NewProcessId' -or $name -eq 'NewProcessName') {
                        if ($fields.ContainsKey($name)) { throw 'Duplicate identity field' }
                        $fields[$name] = [string]$node.InnerText
                    }
                }
            }
            if (-not $fields.ContainsKey('NewProcessId') -or
                -not $fields.ContainsKey('NewProcessName')) {
                continue
            }
            $eventPid = Convert-WindowsEventProcessId $fields['NewProcessId']
            if ($null -ne $eventPid -and $eventPid -eq $targetId -and
                [string]::Equals($fields['NewProcessName'], $executable,
                    [StringComparison]::OrdinalIgnoreCase)) {
                $matched = $true
                break
            }
        } catch {
            # Unexpected event fields are not trusted; no event bodies shown.
            continue
        }
    }
    if ($matched) { break }
}
if ($matched) {
    Write-Host 'PASS: event 4688 matched the harmless local process ID and image path.'
    Write-Host 'This does not prove command-line capture, WinRM attribution, or a signed outcome.'
} else {
    Write-Host ('INCONCLUSIVE: no exact 4688 match. Any 4688 records inspected: {0}' -f $scannedAny)
    throw 'Exact 4688 correlation could not be verified.'
}
