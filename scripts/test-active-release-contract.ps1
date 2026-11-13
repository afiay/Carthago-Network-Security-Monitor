# SPDX-License-Identifier: MIT
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $PSScriptRoot 'ActiveReleaseSource.psm1') -Force
function Require($condition) { if (-not $condition) { throw 'Release contract failed.' } }
# Parse all qualification sources without executing any live path.
$files=@('verify-active-sensors.ps1','scripts/ActiveReleaseSource.psm1','scripts/ActiveServiceDeployment.psm1',
    'scripts/ActiveServiceQualification.psm1','scripts/ActiveServiceNegativeQualification.psm1',
    'scripts/manage-active-service.ps1','scripts/verify-active-service.ps1','scripts/verify-active-service-negative.ps1',
    'scripts/verify-active-physical.ps1','scripts/observe-active-service-soak.ps1','scripts/verify-active-release.ps1',
    'scripts/test-active-service-deployment-contract.ps1','scripts/test-active-service-qualification-contract.ps1',
    'scripts/test-active-service-negative-contract.ps1','scripts/test-active-release-contract.ps1')
foreach ($path in $files) {
    $tokens=$null;$errors=$null
    $ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root $path),[ref]$tokens,[ref]$errors)
    if ($errors.Count -ne 0) { throw ('PowerShell parse failed: '+$path) }
    $functions=@($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]},$true))
    $duplicate=@($functions | Group-Object Name | Where-Object Count -gt 1)
    if ($duplicate.Count -ne 0) { throw ('Duplicate function definition: '+$path) }
}
Require (Test-ActivePhysicalOutcome 'GatewayMatch' 0 'Passed' 'BaselineMatch' $true)
Require (Test-ActivePhysicalOutcome 'GatewayMismatch' 1 'Failed' 'BaselineDifference' $false)
Require (Test-ActivePhysicalOutcome 'GatewayNoReply' 3 'Inconclusive' 'NoReply' $null)
Require (Test-ActivePhysicalOutcome 'GatewayContention' 3 'Inconclusive' 'CaptureReservationUnavailable' $null)
Require (Test-ActivePhysicalOutcome 'SnmpMatch' 0 'Passed' 'Observed' $true)
Require (Test-ActivePhysicalOutcome 'SnmpMismatch' 1 'Failed' 'Observed' $false)
Require (Test-ActivePhysicalOutcome 'SnmpTimeout' 3 'Inconclusive' 'TimedOut' $null)
Require (-not (Test-ActivePhysicalOutcome 'GatewayMatch' 0 'Passed' 'BaselineMatch' 'true'))
Require (-not (Test-ActivePhysicalOutcome 'SnmpMismatch' 1 'Failed' 'InvalidResponse' $false))
Require (-not (Test-ActivePhysicalOutcome 'GatewayContention' 3 'Inconclusive' 'OperationUnavailable' $null))
Require (-not (Test-ActivePhysicalOutcome 'SnmpTimeout' 3 'Inconclusive' 'TransportError' $null))
Require (-not (Test-ActivePhysicalOutcome 'SnmpMatch' 0 'Passed' 'Observed' $false))
Write-Output 'PASS AS-Q07G6 offline release contract'
