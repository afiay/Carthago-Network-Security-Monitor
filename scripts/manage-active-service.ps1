# SPDX-License-Identifier: MIT
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('Preflight','Install','Start','Stop','Remove','Status')][string]$Action,
    [string]$MonitorExe,[string]$ConfigPath,[string]$Account,[string]$ExpectedExeSha256,
    [switch]$ConfirmAuthorizedDeployment
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ActiveServiceDeployment.psm1') -Force
if ($env:OS -ne 'Windows_NT') { throw 'Windows required.' }
$name='CarthagoActiveMonitor'
function Read-ServiceRegistration { Get-CimInstance Win32_Service -Filter "Name='CarthagoActiveMonitor'" }
function Assert-Administrator {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal=[Security.Principal.WindowsPrincipal]::new($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated PowerShell required.' }
    } finally { $identity.Dispose() }
}
if ($Action -eq 'Status') {
    $s=Read-ServiceRegistration
    [pscustomobject]@{ service=$name; registered=($null -ne $s); state=if($s){$s.State}else{'NotInstalled'}; executionValidated=$false } | ConvertTo-Json
    return
}
if (-not $MonitorExe -or -not $ConfigPath -or -not $Account -or -not $ExpectedExeSha256) {
    throw 'MonitorExe, ConfigPath, Account and ExpectedExeSha256 required.'
}
if ($Action -eq 'Preflight') {
    Get-ActiveServicePreflight $MonitorExe $ConfigPath $Account $ExpectedExeSha256 | ConvertTo-Json
    return
}
Assert-Administrator
if (-not $ConfirmAuthorizedDeployment) { throw 'Explicit -ConfirmAuthorizedDeployment required.' }
# Stop/remove must remain possible after grant expiry or loss of config/binaries.
# Verify registration identity and image without executing the deployed binary.
if ($Action -in @('Stop','Remove')) {
    $pre=[pscustomobject]@{imagePath=(Get-ActiveServiceImage $MonitorExe $ConfigPath);accountSid=(Get-ActiveAccountSid $Account)}
} else {
    $pre=Get-ActiveServicePreflight $MonitorExe $ConfigPath $Account $ExpectedExeSha256
}
$s=Read-ServiceRegistration
if ($Action -eq 'Install') {
    if ($s) { throw 'Service already registered; no overwrite.' }
    if (-not $PSCmdlet.ShouldProcess($name,'Register manual-start service')) { return }
    $credential=Get-Credential -UserName $Account -Message 'Enter the dedicated Windows service account credential'
    if ($null -eq $credential -or (Get-ActiveAccountSid $credential.UserName) -cne $pre.accountSid) { throw 'Credential account mismatch.' }
    # No password in process arguments; SCM receives credentials through New-Service.
    New-Service -Name $name -DisplayName 'CARTHAGO Active Monitor' -BinaryPathName $pre.imagePath -Credential $credential -StartupType Manual | Out-Null
    $s=Read-ServiceRegistration
    Assert-ActiveRegisteredService $s $pre
    if ($s.State -ne 'Stopped') { throw 'Registration not confirmed stopped.' }
    Write-Output 'Registered manual-start service; not started.'
    return
}
Assert-ActiveRegisteredService $s $pre
if ($Action -eq 'Start') {
    if ($s.State -ne 'Stopped') { throw 'Service must be stopped.' }
    if (-not $PSCmdlet.ShouldProcess($name,'Start authorized active service')) { return }
    Start-Service -Name $name
    $controller=Get-Service -Name $name
    $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(45))
    $controller.Refresh()
    if ($controller.Status -ne 'Running') { throw 'Service startup unconfirmed.' }
    Write-Output 'SCM running confirmed; sensor health and evidence not qualified.'
} elseif ($Action -eq 'Stop') {
    if ($s.State -eq 'Stopped') { Write-Output 'Already stopped.'; return }
    if ($s.State -ne 'Running') { throw 'Service transition in progress; inspect SCM before retry.' }
    if (-not $PSCmdlet.ShouldProcess($name,'Stop active service')) { return }
    Stop-Service -Name $name
    $controller=Get-Service -Name $name
    $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(45))
    $controller.Refresh()
    if ($controller.Status -ne 'Stopped') { throw 'Stop unconfirmed.' }
    Write-Output 'SCM stopped confirmed; inspect service exit code for cleanup failures.'
} elseif ($Action -eq 'Remove') {
    if ($s.State -ne 'Stopped') { throw 'Stop service before removal.' }
    if (-not $PSCmdlet.ShouldProcess($name,'Unregister stopped service; preserve data')) { return }
    & sc.exe delete $name | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'SCM removal failed.' }
    if (Read-ServiceRegistration) { throw 'Service deletion pending; close open SCM handles and verify.' }
    Write-Output 'Service unregistered; account, configuration, credentials and evidence preserved.'
}
