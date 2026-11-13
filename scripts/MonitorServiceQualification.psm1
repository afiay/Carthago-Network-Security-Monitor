# SPDX-License-Identifier: MIT
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-LocalPath {
    param([string]$Path,[switch]$Directory)
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path.Contains('"')) { throw 'Local absolute path required.' }
    $full = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $full -Force
    if ($item.PSIsContainer -ne [bool]$Directory) { throw 'Unexpected path type.' }
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse point rejected.' }
        $parent = Split-Path -Parent $item.FullName
        if (-not $parent -or $parent -eq $item.FullName) { break }
        $item = Get-Item -LiteralPath $parent -Force
    }
    return $full
}

function Invoke-MonitorJson {
    param([string]$Exe,[string[]]$Arguments,[int]$TimeoutSeconds=60)
    foreach ($arg in $Arguments) {
        if ($arg.Contains('"') -or $arg.EndsWith('\')) { throw 'Unsupported argument quoting.' }
    }
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = ($Arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = New-Object Diagnostics.Process
    $p.StartInfo = $psi
    try {
        if (-not $p.Start()) { throw 'Child launch failed.' }
        $stdout = $p.StandardOutput.ReadToEndAsync()
        $stderr = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
            try { $p.Kill() } catch {} # Only the child CLI, never the service.
            throw 'CLI timeout; SCM operation may still be pending.'
        }
        $p.WaitForExit()
        $raw = $stdout.GetAwaiter().GetResult()
        $null = $stderr.GetAwaiter().GetResult()
        if ($raw.Length -gt 1048576) { throw 'CLI response too large.' }
        $data = $null
        if (-not [string]::IsNullOrWhiteSpace($raw)) { $data = ConvertFrom-Json -InputObject $raw }
        return [pscustomobject]@{ code=$p.ExitCode; data=$data }
    } finally { $p.Dispose() }
}

function Test-BroadWrite {
    param([string]$Path)
    $mask = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($r in (Get-Acl -LiteralPath $Path).GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($r.IdentityReference.Value -in @('S-1-1-0','S-1-5-11','S-1-5-32-545') -and
            $r.AccessControlType -eq 'Allow' -and ($r.FileSystemRights -band $mask) -ne 0) { return $true }
    }
    return $false
}

function Get-MonitorPreflight {
    param([string]$MonitorExe,[string]$CliExe,[string]$ConfigPath)
    $checks = New-Object 'System.Collections.Generic.List[object]'
    function Check([string]$Name,[string]$State,[string]$Detail) {
        $checks.Add([pscustomobject]@{name=$Name;state=$State;detail=$Detail})
    }
    $monitor=$null; $cli=$null; $config=$null; $hashes=$null
    try {
        $monitor=Assert-LocalPath $MonitorExe
        $cli=Assert-LocalPath $CliExe
        $config=Assert-LocalPath $ConfigPath
        if ([IO.Path]::GetFileName($monitor) -ne 'carthago-monitor.exe' -or [IO.Path]::GetFileName($cli) -ne 'carthago.exe') { throw 'Wrong executable.' }
        $dir=Split-Path -Parent $monitor
        foreach ($name in @('Carthago.dll','Carthago.Contracts.dll','rules.json','service-names-port-numbers.csv','carthago-monitor.runtimeconfig.json','carthago-monitor.deps.json')) {
            $null=Assert-LocalPath (Join-Path $dir $name)
        }
        $hashes=[pscustomobject]@{monitor=(Get-FileHash -LiteralPath $monitor).Hash;cli=(Get-FileHash -LiteralPath $cli).Hash;config=(Get-FileHash -LiteralPath $config).Hash}
        Check 'deployment' 'pass' 'Required files and input hashes; no signature attestation.'
    } catch { Check 'deployment' 'fail' 'Required deployment file unavailable.' }
    $statusDir=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Carthago\ServiceStatus'
    try { $null=Assert-LocalPath $statusDir -Directory; Check 'status_directory' 'pass' 'Exists.' }
    catch { Check 'status_directory' 'fail' 'Provision service status directory.' }
    try {
        $runtime=& dotnet --list-runtimes 2>$null
        if ($LASTEXITCODE -ne 0 -or -not ($runtime -match '^Microsoft.WindowsDesktop.App 8\.')) { throw 'Runtime missing.' }
        Check 'desktop_runtime' 'pass' '.NET 8 Desktop visible to invoking shell.'
    } catch { Check 'desktop_runtime' 'fail' '.NET 8 Desktop not confirmed.' }
    try { $n=Get-Service npcap; Check 'npcap' 'pass' ('Registered; state '+$n.Status) }
    catch { Check 'npcap' 'fail' 'Npcap registration unavailable.' }
    try {
        if (-not $monitor -or -not $config) { throw 'Paths unavailable.' }
        $r=Invoke-MonitorJson $monitor @('service','validate','--config',$config,'--json')
        if ($r.code -ne 0 -or $r.data.configuration -ne 'valid') { throw 'Invalid config.' }
        $id=$r.data.interfaceId
        Check 'config' 'pass' 'Schema valid; BPF/permissions untested.'
        $r=Invoke-MonitorJson $monitor @('capture','interfaces','--json')
        if ($r.code -ne 0 -or @($r.data.interfaces | Where-Object {$_.id -ceq $id}).Count -ne 1) { throw 'Interface unavailable.' }
        Check 'interface' 'pass' 'Exact interface visible to invoking account.'
    } catch { Check 'config_or_interface' 'fail' 'Validation or enumeration failed.' }
    try {
        $s=Get-CimInstance Win32_Service -Filter "Name='CarthagoMonitor'"
        $expected='"'+$monitor+'" service run --config "'+$config+'"'
        if (-not $s -or $s.PathName -cne $expected -or $s.StartName -in @('LocalSystem','NT AUTHORITY\SYSTEM','.\LocalSystem')) { throw 'Registration mismatch.' }
        Check 'registration' 'pass' 'Exact ImagePath and non-LocalSystem identity.'
        if ($s.StartMode -eq 'Auto') { Check 'startup_mode' 'warn' 'Automatic startup already enabled.' }
    } catch { Check 'registration' 'fail' 'Missing service, mismatched ImagePath or LocalSystem.' }
    try {
        foreach ($path in @($monitor,$cli,$config,(Split-Path -Parent $monitor),(Split-Path -Parent $cli),(Split-Path -Parent $config),$statusDir,(Join-Path (Split-Path -Parent $monitor) 'rules.json'))) {
            if (Test-BroadWrite $path) { throw 'Broad write.' }
        }
        Check 'acl_screen' 'pass' 'No screened broad write ACE; not effective-access proof.'
    } catch { Check 'acl_screen' 'fail' 'Broad write grant or inspection unavailable.' }
    Check 'service_permissions' 'not_assessed' 'Review effective account access, all ancestors and binary provenance manually.'
    return [pscustomobject]@{schemaVersion=1;ready=(@($checks | Where-Object state -eq 'fail').Count -eq 0);checks=$checks.ToArray();hashes=$hashes}
}

function Get-JournalEvidence {
    param([string]$Path,[long]$Baseline,[datetimeoffset]$StartUtc)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 'no_journal' }
    $fs=$null
    try {
        $null=Assert-LocalPath $Path
        $fs=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        $length=$fs.Length
        if ($length -lt $Baseline) { return 'journal_shrank' }
        if ($length -eq $Baseline) { return 'no_new_records' }
        if ($length-$Baseline -gt 8388608) { return 'append_exceeds_limit' }
        $null=$fs.Seek($Baseline,[IO.SeekOrigin]::Begin)
        $bytes=New-Object byte[] ([int]($length-$Baseline))
        $offset=0
        while ($offset -lt $bytes.Length) {
            $n=$fs.Read($bytes,$offset,$bytes.Length-$offset)
            if ($n -eq 0) { return 'incomplete_read' }
            $offset+=$n
        }
        if ($bytes[$bytes.Length-1] -ne 10) { return 'incomplete_record' }
        $encoding=New-Object Text.UTF8Encoding($false,$true)
        $ids=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $count=0
        foreach ($line in ($encoding.GetString($bytes) -split "\r?\n")) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $count++
            if ($line.Length -gt 131072 -or $count -gt 20000) { return 'record_limit' }
            $row=ConvertFrom-Json -InputObject $line
            $id=[Guid]::Empty
            if (-not [Guid]::TryParse([string]$row.eventId,[ref]$id) -or $id -eq [Guid]::Empty -or -not $ids.Add($id.ToString('N'))) { return 'invalid_record' }
            $time=[DateTimeOffset]::Parse([string]$row.timestampUtc,[Globalization.CultureInfo]::InvariantCulture)
            if ($time.Offset -ne [TimeSpan]::Zero -or $time -lt $StartUtc -or [string]$row.deliveryStatus -cne 'Persisted') { return 'invalid_record' }
        }
        if ($count -eq 0) { return 'no_new_records' }
        return 'appended_persisted_records_observed'
    } catch { return 'journal_unavailable_or_invalid' }
    finally { if ($null -ne $fs) { $fs.Dispose() } }
}
Export-ModuleMember -Function Assert-LocalPath,Invoke-MonitorJson,Get-MonitorPreflight,Get-JournalEvidence
