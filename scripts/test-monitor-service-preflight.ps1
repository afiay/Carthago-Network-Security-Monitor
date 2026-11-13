# SPDX-License-Identifier: MIT
[CmdletBinding()]
param([Parameter(Mandatory)][string]$MonitorExe,[Parameter(Mandatory)][string]$CliExe,[Parameter(Mandatory)][string]$ConfigPath)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'MonitorServiceQualification.psm1') -Force
$r=Get-MonitorPreflight $MonitorExe $CliExe $ConfigPath
$r | ConvertTo-Json -Depth 8
if (-not $r.ready) { exit 3 }
exit 0
