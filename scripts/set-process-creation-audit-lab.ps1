# SPDX-License-Identifier: MIT
# CARTHAGO R343 lab telemetry, Stage 1 ONLY: Security 4688 process creation.
# No command-line inclusion, no permissions changes, no R343 rule promotion.
# Run in a CARTHAGE elevated Windows PowerShell session.
[CmdletBinding()]
param(
    [ValidateSet('Status', 'Enable', 'Restore')]
    [string]$Mode = 'Status'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$subcategory = '{0CCE922B-69AE-11D9-BED3-505054503030}'
$registryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Windows is required.'
}
if ($env:COMPUTERNAME -ine 'CARTHAGE') {
    throw 'This lab policy script is restricted to the CARTHAGE computer.'
}

function Get-ProcessCreationPolicy {
    param([string]$Guid)

    # The CSV response is never printed: it may contain host information.
    $report = @(& auditpol.exe /get "/subcategory:$Guid" /r 2>$null)
    if ($LASTEXITCODE -ne 0 -or $report.Count -lt 2) {
        throw 'Unable to read effective Process Creation audit policy.'
    }
    $rows = @($report | ConvertFrom-Csv -ErrorAction Stop)
    $selected = @($rows | Where-Object { $_.'Subcategory GUID' -eq $Guid })
    if ($selected.Count -ne 1) {
        throw 'Unexpected or localized audit policy report schema. No changes made.'
    }
    $state = [string]$selected[0].'Inclusion Setting'
    switch ($state.Trim()) {
        'No Auditing'         { return 'No Auditing' }
        'Success'             { return 'Success' }
        'Failure'             { return 'Failure' }
        'Success and Failure' { return 'Success and Failure' }
        default               { throw 'Unknown audit setting. No changes made.' }
    }
}

function Test-CommandLineInclusionNotEnabled {
    # Refuse to enable Stage 1 where the inspected local command-line
    # policy is enabled. This script NEVER writes that registry value.
    if (-not (Test-Path -LiteralPath $registryPath)) { return $true }
    $policy = Get-ItemProperty -LiteralPath $registryPath -ErrorAction Stop
    $field = $policy.PSObject.Properties['ProcessCreationIncludeCmdLine_Enabled']
    if ($null -eq $field) { return $true }
    return ([int]$field.Value -eq 0)
}

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Elevated administrator PowerShell is required. No changes made.'
    }
}

function Set-SuccessAudit {
    param([string]$Setting)
    # Only change the Success flag. Do not touch the Failure flag or any
    # other audit subcategory; do not change Windows log retention.
    $output = @(& auditpol.exe /set "/subcategory:$subcategory" "/success:$Setting" 2>$null)
    if ($LASTEXITCODE -ne 0) {
        throw 'The scoped auditpol operation failed. Recheck effective policy.'
    }
}

Write-Host 'CARTHAGO R343 STAGE 1: PROCESS CREATION AUDITING'
Write-Host ('Mode: {0}' -f $Mode)
Write-Host 'Scope: Security 4688 success auditing only; no command lines.'

Assert-Elevated
$before = Get-ProcessCreationPolicy -Guid $subcategory
Write-Host ('Effective policy before: {0}' -f $before)

if ($Mode -eq 'Status') {
    $cmdLineOff = Test-CommandLineInclusionNotEnabled
    Write-Host ('Local command-line inclusion not enabled: {0}' -f $cmdLineOff)
    Write-Host 'STATUS ONLY: no changes applied.'
    return
}

if ($Mode -eq 'Enable') {
    if (-not (Test-CommandLineInclusionNotEnabled)) {
        throw 'Command-line inclusion is already enabled or has an unexpected value. Stage 1 aborted.'
    }
    if ($before -eq 'Success') {
        Write-Host 'ALREADY ENABLED: no changes applied.'
        return
    }
    if ($before -ne 'No Auditing') {
        throw 'Baseline is not No Auditing. Refusing to overwrite an unexpected audit policy.'
    }
    Set-SuccessAudit -Setting 'enable'
    $expected = 'Success'
} else {
    # Restore the previously verified CARTHAGE "No Auditing" baseline.
    # Fail closed if another administrator or policy manager changed it.
    if ($before -eq 'No Auditing') {
        Write-Host 'ALREADY RESTORED: no changes applied.'
        return
    }
    if ($before -ne 'Success') {
        throw 'Effective policy changed unexpectedly; refusing automatic restore.'
    }
    Set-SuccessAudit -Setting 'disable'
    $expected = 'No Auditing'
}

$after = Get-ProcessCreationPolicy -Guid $subcategory
Write-Host ('Effective policy after: {0}' -f $after)
if ($after -ne $expected) {
    throw 'Verification failed: effective policy differs from expected state. Review auditpol manually.'
}
if ($Mode -eq 'Enable') {
    Write-Host 'ENABLED: only Process Creation success auditing was changed.'
    Write-Host 'The command-line inclusion registry setting was NOT changed.'
    Write-Host 'Restore with: .\scripts\set-process-creation-audit-lab.ps1 -Mode Restore'
} else {
    Write-Host 'RESTORED: Process Creation success auditing is off.'
    Write-Host 'Previously written event records are not deleted.'
}
