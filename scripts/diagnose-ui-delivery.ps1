# SPDX-License-Identifier: MIT
# Read-only CARTHAGO UI delivery diagnostic for Windows PowerShell 5.1.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SessionPath,
    [string]$BaselinePath,
    [string]$ProcessName = 'Carthago',
    [int]$Samples = 6,
    [int]$IntervalSeconds = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Samples -lt 1 -or $Samples -gt 120) { throw 'Samples must be 1..120.' }
if ($IntervalSeconds -lt 1 -or $IntervalSeconds -gt 300) { throw 'IntervalSeconds must be 1..300.' }

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Read-Overview {
    param([string]$Path)
    $resolved = (Resolve-Path -LiteralPath $Path).ProviderPath
    $archive = [System.IO.Compression.ZipFile]::OpenRead($resolved)
    try {
        $entry = $archive.GetEntry('data/Overview.json')
        if ($null -eq $entry) { throw "Missing data/Overview.json: $resolved" }
        $stream = $entry.Open()
        $reader = New-Object System.IO.StreamReader($stream)
        try { $json = $reader.ReadToEnd() } finally { $reader.Dispose() }
        $snapshots = @($json | ConvertFrom-Json)
        if ($snapshots.Count -eq 0) { throw "No overview entries: $resolved" }
        $latest = $snapshots | Sort-Object { [datetime]$_.CapturedAtUtc } | Select-Object -Last 1
        foreach ($field in @('PacketsCaptured', 'PacketsParsedOk', 'PacketsDroppedByQueue')) {
            if ($null -eq $latest.$field) { throw "Missing $field in $resolved" }
        }
        return $latest
    } finally { $archive.Dispose() }
}

function Show-Overview {
    param([object]$Value, [string]$Label)
    Write-Host "`n[$Label] Snapshot UTC: $($Value.CapturedAtUtc)"
    Write-Host "  Captured: $($Value.PacketsCaptured) | Parsed: $($Value.PacketsParsedOk) | UI queue drops: $($Value.PacketsDroppedByQueue)"
    Write-Host "  Note: CSA traffic rows are bounded UI history; they are NOT the UI-delivered counter."
}

$current = Read-Overview -Path $SessionPath
Show-Overview -Value $current -Label 'Current CSA'

if (-not [string]::IsNullOrWhiteSpace($BaselinePath)) {
    $baseline = Read-Overview -Path $BaselinePath
    Show-Overview -Value $baseline -Label 'Baseline CSA'
    $baseCaptured = [double]$baseline.PacketsCaptured
    $newCaptured = [double]$current.PacketsCaptured
    if ($baseCaptured -gt 0 -and $newCaptured -gt 0) {
        $baseRate = 1000.0 * [double]$baseline.PacketsDroppedByQueue / $baseCaptured
        $newRate = 1000.0 * [double]$current.PacketsDroppedByQueue / $newCaptured
        Write-Host ("`nDrops/1,000 captured: baseline {0:N2}; new {1:N2}" -f $baseRate, $newRate)
        Write-Warning 'This is descriptive only. Sessions must have comparable traffic rates, durations, source and UI activity before attributing improvement.'
    }
}

Write-Host "`n[Process sampling] $Samples samples, $IntervalSeconds second(s) apart; process '$ProcessName'"
for ($i = 1; $i -le $Samples; $i++) {
    $processes = @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
    if ($processes.Count -eq 0) {
        Write-Host ('{0:HH:mm:ss} process not found (application may be stopped)' -f (Get-Date))
    } else {
        foreach ($process in $processes) {
            Write-Host ('{0:HH:mm:ss} pid={1} responding={2} cpuSeconds={3:N1} privateMB={4:N1} threads={5}' -f (Get-Date), $process.Id, $process.Responding, $process.CPU, ($process.PrivateMemorySize64 / 1MB), $process.Threads.Count)
        }
    }
    if ($i -lt $Samples) { Start-Sleep -Seconds $IntervalSeconds }
}

Write-Host "`n[Limits] This script does not access in-process UI queue depth, dispatcher wait, record age, or event-subscriber latency."
Write-Host 'To establish the stall cause, collect the Monitoring Health Flow diagnostic during capture and export a new CSA after the workload.'
