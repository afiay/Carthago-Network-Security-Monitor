# SPDX-License-Identifier: MIT
# SOURCE CANDIDATE — UNVERIFIED. Authoring is not execution authorization.
[CmdletBinding()]
param([switch]$AuthorizedTestTime)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $AuthorizedTestTime) { throw 'Requires fresh owner authorization for this revision and contract scope.' }
# This switch is a technical gate, not independent owner authorization.
Import-Module (Join-Path $PSScriptRoot 'RuleSourceInventory.psm1') -Force
function Assert-Contract([bool]$Condition, [string]$Name) {
    if (-not $Condition) { throw "Rule source inventory contract: $Name" }
}
# A changed ID grammar, lexicographic sorting, or treating comments as code
# must break these assertions. No detector, fixture or external producer runs.
$registry = @'
public static IReadOnlyList<IDetectionRule> CreateDefaultRules() {
 // new R002_FakeRule()
 return new IDetectionRule[] {
 new R3000_LastRule(), new R001_FirstRule(), new R1000_FourRule(),
 new R999_ThreeRule(), new R2999_PenultimateRule()
 }; }
'@
$files = @{}
foreach ($pair in @(@('R001','First'),@('R999','Three'),@('R1000','Four'),@('R2999','Penultimate'),@('R3000','Last'))) {
    $files["Carthago/Engine/Rules/$($pair[0]).cs"] = "public class $($pair[0])_$($pair[1])Rule {}"
}
$files['Carthago.Tests/ArbitraryGroupedName.cs'] = @'
// class R002FakeTests { [Fact] public void Fake() {} }
public class SharedTests {
 private string prose = "new R002_FakeRule()";
 private static readonly (string Id, int Count)[] Cases = { ("R1000", 1) };
 [Theory] [MemberData(nameof(Cases))] public void Case(string id) {
  var rule = id switch { "R1000" => new R1000_FourRule(), _ => null };
 }
}
public class R001AdvancedAccuracyBatchTests { [Fact] public void Example() {} }
'@
$a = Get-RuleSourceInventory -RegistrySource $registry -Sources $files -SourceSha ('a' * 40)
Assert-Contract (($a.rules.ruleId -join ',') -ceq 'R001,R999,R1000,R2999,R3000') 'numeric-core-order'
Assert-Contract (@($a.rules | Where-Object ruleId -eq 'R002').Count -eq 0) 'comments-and-prose-not-registration'
Assert-Contract (@(@($a.rules | Where-Object ruleId -eq 'R001')[0].associations | Where-Object kind -eq 'direct-class-candidate').Count -eq 1) 'individual-class-in-grouped-file'
$r = @($a.rules | Where-Object ruleId -eq 'R1000')[0]
Assert-Contract (@($r.associations | Where-Object kind -eq 'constructor-reference').Count -eq 1) 'grouped-constructor-discovered'
Assert-Contract (@($r.associations | Where-Object kind -eq 'data-row-candidate').Count -eq 2) 'grouped-tuple-discovered'
Assert-Contract ($null -eq $r.authoredInvocationCount -and $null -eq $r.authoredMethodCount) 'do-not-invent-counts'
Assert-Contract (-not $a.readyForExecutionSelection -and $a.testsExecutedByInventory -eq 0) 'never-authorizes-or-certifies'
Assert-Contract (@($a.rules | Where-Object ruleId -eq 'R999')[0].associationStatus -eq 'NO_ASSOCIATION_FOUND') 'missing-is-not-zero-tests'
$duplicate = $registry.Replace('new R999_ThreeRule(),','new R999_ThreeRule(), new R999_ThreeRule(),')
$b = Get-RuleSourceInventory -RegistrySource $duplicate -Sources $files -SourceSha ('a' * 40)
Assert-Contract (@($b.diagnostics | Where-Object code -eq 'DUPLICATE_CORE_ID').Count -eq 1) 'duplicate-not-silently-deduplicated'
$missing = @{} + $files
$missing.Remove('Carthago/Engine/Rules/R3000.cs')
$c = Get-RuleSourceInventory -RegistrySource $registry -Sources $missing -SourceSha ('a' * 40)
Assert-Contract (@($c.diagnostics | Where-Object code -eq 'REGISTERED_CLASS_UNRESOLVED').Count -eq 1) 'missing-class'
$unsupported = @{} + $files
$unsupported['Carthago.Tests/RawTests.cs'] = 'public class R999Tests { string text = """ [Fact] """; }'
$d = Get-RuleSourceInventory -RegistrySource $registry -Sources $unsupported -SourceSha ('a' * 40)
Assert-Contract (@($d.diagnostics | Where-Object code -eq 'UNSUPPORTED_SOURCE_SYNTAX').Count -eq 1) 'raw-string-review'
$bad = $registry.Replace('R3000_LastRule', 'R03000_LastRule')
$e = Get-RuleSourceInventory -RegistrySource $bad -Sources $files -SourceSha ('a' * 40)
Assert-Contract (@($e.diagnostics | Where-Object code -eq 'NONCANONICAL_CORE_ID').Count -eq 1) 'leading-zero-alias'
$pack = $registry.Replace('new R3000_LastRule(),', 'new PACK001_Rule(),')
$f = Get-RuleSourceInventory -RegistrySource $pack -Sources $files -SourceSha ('a' * 40)
Assert-Contract (@($f.diagnostics | Where-Object code -eq 'UNRESOLVED_REGISTRATION').Count -eq 1) 'pack-not-core'
Write-Host 'Source-inventory contract assertions completed; no rule accuracy or operational claim.'
