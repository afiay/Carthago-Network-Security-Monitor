# SPDX-License-Identifier: MIT
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ActiveServiceDeployment.psm1') -Force
function Require($condition,[string]$message) { if (-not $condition) { throw $message } }
function Reject([scriptblock]$action) { $rejected=$false; try { & $action | Out-Null } catch { $rejected=$true }; Require $rejected 'Expected rejection.' }
$exe='C:\Program Files\Carthago\Monitor\carthago-monitor.exe'
$config='C:\Users\Lab\AppData\Local\Carthago\active-service\active-service.json'
Require ((Get-ActiveServiceImage $exe $config) -ceq ('"' + $exe + '" active-service run --config "' + $config + '"')) 'Image quoting.'
Reject { Get-ActiveServiceImage 'C:\bad" name.exe' $config }
Reject { Get-ActiveServiceImage '\\server\share\monitor.exe' $config }
Reject { Get-ActiveServiceImage $exe 'relative.json' }
Reject { Get-ActiveServiceImage $exe 'C:\config.json:stream' }
Write-Output 'PASS AS-Q07G5C offline deployment contract'
