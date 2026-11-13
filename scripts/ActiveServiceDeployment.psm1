# SPDX-License-Identifier: MIT
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-ActiveLocalPath([string]$Path) {
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path -match '[\x00-\x1f"]' -or $Path.Substring(2).Contains(':')) {
        throw 'Absolute local drive path required.'
    }
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -ne $Path) { throw 'Canonical path required.' }
    $current = $full
    while ($current) {
        $item = Get-Item -LiteralPath $current -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point rejected.' }
        $current = [IO.Path]::GetDirectoryName($current)
    }
    return $full
}

function Get-ActiveServiceImage([string]$Exe, [string]$Config) {
    foreach ($p in @($Exe,$Config)) {
        if ($p -notmatch '^[A-Za-z]:\\' -or $p -match '[\x00-\x1f"]' -or $p.Substring(2).Contains(':') -or $p.EndsWith('\')) {
            throw 'Invalid service image path.'
        }
    }
    return ('"' + $Exe + '" active-service run --config "' + $Config + '"')
}

function Get-ActiveAccountSid([string]$Account) {
    $sid = ([Security.Principal.NTAccount]::new($Account)).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($sid -notmatch '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$') { throw 'Dedicated local/domain user required.' }
    return $sid
}

function Assert-ActiveDeploymentAcl([string]$Path, [string]$AccountSid, [switch]$Ancestor) {
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    # TrustedInstaller owns some Windows deployment ancestors.
    $trusted = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    if ($owner -notin $trusted) { throw 'Deployment owner is not trusted.' }
    # Include delete/rename, ACL/owner modification, write data and append.
    $write = [long]([Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership)
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        $sid = $rule.IdentityReference.Value
        if ($sid -in $trusted) { continue }
        $bits = [long]$rule.FileSystemRights
        # Drive/root ancestors may permit creation of unrelated children. They
        # must not permit deleting/replacing existing protected children.
        $mask = $write
        if ($Ancestor) { $mask = $mask -band (-bnot [long]([Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData)) }
        if (($bits -band $mask) -ne 0) { throw 'Untrusted deployment write permission.' }
    }
}

function Get-ActiveServicePreflight([string]$MonitorExe,[string]$ConfigPath,[string]$Account,[string]$ExpectedExeSha256) {
    $exe = Assert-ActiveLocalPath $MonitorExe
    $config = Assert-ActiveLocalPath $ConfigPath
    if ([IO.Path]::GetFileName($exe) -ine 'carthago-monitor.exe' -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Expected monitor executable.' }
    if ($ExpectedExeSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'Expected deployment SHA256 required.' }
    $sid = Get-ActiveAccountSid $Account
    $profileKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $sid
    $profile = [Environment]::ExpandEnvironmentVariables((Get-ItemProperty -LiteralPath $profileKey -Name ProfileImagePath).ProfileImagePath)
    # Initial deployment supports standard, non-redirected LocalAppData only.
    $expectedConfig = Join-Path $profile 'AppData\Local\Carthago\active-service\active-service.json'
    if ($config -ine $expectedConfig) { throw 'Configuration is not in the intended account standard profile.' }
    $dir = [IO.Path]::GetDirectoryName($exe)
    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    if (-not $dir.StartsWith($programFiles.TrimEnd('\') + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Deploy under Program Files.' }
    Assert-ActiveDeploymentAcl $dir $sid
    foreach ($entry in Get-ChildItem -LiteralPath $dir -Force -Recurse) {
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Deployment reparse point rejected.' }
        Assert-ActiveDeploymentAcl $entry.FullName $sid
    }
    $parent = [IO.Path]::GetDirectoryName($dir)
    while ($parent) { Assert-ActiveDeploymentAcl $parent $sid -Ancestor; $parent = [IO.Path]::GetDirectoryName($parent) }
    $hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    if ($hash -ine $ExpectedExeSha256) { throw 'Monitor executable hash mismatch.' }
    # Config is mutable by the dedicated account, not by general users.
    $root = [IO.Path]::GetDirectoryName($config)
    $acl = Get-Acl -LiteralPath $root
    if (-not $acl.AreAccessRulesProtected) { throw 'Service storage DACL is not protected.' }
    $trusted = @($sid,'S-1-5-18','S-1-5-32-544')
    foreach ($item in @((Get-Item -LiteralPath $root)) + @(Get-ChildItem -LiteralPath $root -Force)) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint -or ($item.PSIsContainer -and $item.FullName -ine $root)) { throw 'Unexpected service storage entry.' }
        $a = Get-Acl -LiteralPath $item.FullName
        if ($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw 'Untrusted service storage owner.' }
        foreach ($r in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($r.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $r.IdentityReference.Value -notin $trusted) { throw 'Unexpected service storage ACL.' }
        }
    }
    $raw = & $exe active-service validate --config $config
    if ($LASTEXITCODE -ne 0) { throw 'Configuration validation failed.' }
    $validated = $raw | ConvertFrom-Json
    if ($validated.configuration -ne 'valid') { throw 'Configuration validation unconfirmed.' }
    $json = Get-Content -LiteralPath $config -Raw | ConvertFrom-Json
    if ($json.accountSid -cne $sid) { throw 'Configuration account SID mismatch.' }
    [pscustomobject]@{ monitorExe=$exe; configPath=$config; accountSid=$sid; exeSha256=$hash;
        configSha256=(Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash;
        imagePath=(Get-ActiveServiceImage $exe $config); profileCount=$validated.profileCount;
        executionValidated=$false }
}

function Assert-ActiveRegisteredService($Service, $Preflight) {
    if ($null -eq $Service -or $Service.Name -cne 'CarthagoActiveMonitor' -or
        $Service.PathName -cne $Preflight.imagePath -or $Service.StartMode -ne 'Manual' -or
        (Get-ActiveAccountSid $Service.StartName) -cne $Preflight.accountSid) {
        throw 'Registered service identity, image or manual startup mismatch.'
    }
}

Export-ModuleMember -Function Assert-ActiveLocalPath,Get-ActiveServiceImage,Get-ActiveAccountSid,Get-ActiveServicePreflight,Assert-ActiveRegisteredService
