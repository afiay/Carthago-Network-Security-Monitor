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

# VC-002B: common grouped files contain simple interpolated helper strings.
# Such strings must not suppress real literal tuples or manufacture data rows.
$interpolated = @{} + $files
$interpolated['Carthago.Tests/GroupedInterpolated.cs'] = @'
public class SharedTests {
 private static string Host(int n) => $"10.0.{n / 2}.{n % 2}";
 private static readonly (string Id, int N)[] Rules = { ("R999", 1) };
 [Theory] [MemberData(nameof(Cases))] public void Case(string id) {}
}
'@
$g = Get-RuleSourceInventory -RegistrySource $registry -Sources $interpolated -SourceSha ('a' * 40)
Assert-Contract (@($g.diagnostics | Where-Object { $_.code -eq 'UNSUPPORTED_SOURCE_SYNTAX' -and $_.path -eq 'Carthago.Tests/GroupedInterpolated.cs' }).Count -eq 0) 'simple-interpolation-supported'
Assert-Contract (@(@($g.rules | Where-Object ruleId -eq 'R999')[0].associations |
    Where-Object kind -eq 'data-row-candidate').Count -eq 1) 'literal-grouped-row-retained'
$opaque = @{} + $files
$opaque['Carthago.Tests/InterpolatedDecoy.cs'] = @'
public class SharedTests {
 private static string Label(int n) => $"R999,{n}";
 [Fact] public void Example() {}
}
'@
$h = Get-RuleSourceInventory -RegistrySource $registry -Sources $opaque -SourceSha ('a' * 40)
Assert-Contract (@(@($h.rules | Where-Object ruleId -eq 'R999')[0].associations |
    Where-Object kind -eq 'data-row-candidate').Count -eq 0) 'interpolated-string-not-data-row'
$quoted = @{} + $files
$quoted['Carthago.Tests/NestedQuotedInterpolation.cs'] = @'
public class R999Tests {
 private static string Label(System.Guid id) => $"{id.ToString("N")}";
 [Fact] public void Example() {}
}
'@
$i = Get-RuleSourceInventory -RegistrySource $registry -Sources $quoted -SourceSha ('a' * 40)
Assert-Contract (@($i.diagnostics | Where-Object { $_.code -eq 'UNSUPPORTED_SOURCE_SYNTAX' -and $_.path -eq 'Carthago.Tests/NestedQuotedInterpolation.cs' }).Count -eq 1) 'quoted-interpolation-fails-closed'
$verbatim = @{} + $files
$verbatim['Carthago.Tests/VerbatimInterpolation.cs'] = @'
public class R999Tests {
 private static string Label(int n) => $@"R999-{n}";
 [Fact] public void Example() {}
}
'@
$j = Get-RuleSourceInventory -RegistrySource $registry -Sources $verbatim -SourceSha ('a' * 40)
Assert-Contract (@($j.diagnostics | Where-Object { $_.code -eq 'UNSUPPORTED_SOURCE_SYNTAX' -and $_.path -eq 'Carthago.Tests/VerbatimInterpolation.cs' }).Count -eq 1) 'verbatim-interpolation-fails-closed'
$conditional = @{} + $files
$conditional['Carthago.Tests/Guarded.cs'] = @'
#if CARTHAGO_DNS_WIRE_STAGE3
public class R999Tests { [Fact] public void FutureOnly() {} }
#endif
'@
$k = Get-RuleSourceInventory -RegistrySource $registry -Sources $conditional -SourceSha ('a' * 40)
Assert-Contract (@($k.diagnostics | Where-Object { $_.code -eq 'UNSUPPORTED_SOURCE_SYNTAX' -and $_.path -eq 'Carthago.Tests/Guarded.cs' }).Count -eq 1) 'compiler-guard-not-eligible'

# VC-002C: file co-location must not attribute sibling or nested methods.
$scoped = @{} + $files
$scoped['Carthago.Tests/Scoped.cs'] = @'
namespace Carthago.Tests;
public class R999Tests {
 [Fact] public void OwnCase() { var rule = new R999_ThreeRule(); }
 public class Nested { [Fact] public void NestedCase() {} }
}
public class R2999Helper { public void NotATest() { var rule = new R2999_PenultimateRule(); } }
public class UnrelatedTests { [Fact] public void SiblingCase() {} }
'@
$l = Get-RuleSourceInventory -RegistrySource $registry -Sources $scoped -SourceSha ('a' * 40)
$own = @(@($l.rules | Where-Object ruleId -eq 'R999')[0].associations |
    Where-Object { $_.path -eq 'Carthago.Tests/Scoped.cs' -and $_.kind -eq 'direct-class-candidate' })[0]
Assert-Contract ($own.owningClass -eq 'Carthago.Tests.R999Tests') 'qualified-class-owner'
Assert-Contract (($own.declaredTestMethods -join ',') -eq 'Carthago.Tests.R999Tests.OwnCase') 'no-sibling-or-nested-method-borrowing'
$ctor = @(@($l.rules | Where-Object ruleId -eq 'R999')[0].associations |
    Where-Object { $_.path -eq 'Carthago.Tests/Scoped.cs' -and $_.kind -eq 'constructor-reference' })[0]
Assert-Contract ($ctor.containingTestMethod -eq 'Carthago.Tests.R999Tests.OwnCase') 'constructor-in-own-test-method'
$helper = @(@($l.rules | Where-Object ruleId -eq 'R2999')[0].associations |
    Where-Object { $_.path -eq 'Carthago.Tests/Scoped.cs' -and $_.kind -eq 'constructor-reference' })[0]
Assert-Contract ($helper.declaredTestMethods.Count -eq 0 -and $null -eq $helper.containingTestMethod) 'helper-never-borrows-sibling-test'
$nested = @($l.testDeclarations | Where-Object { $_.identity -eq 'Carthago.Tests.R999Tests+Nested.NestedCase' })
Assert-Contract ($nested.Count -eq 1) 'nested-identity-separated'
$provider = @($a.testDeclarations | Where-Object { $_.identity -eq 'SharedTests.Case' })[0]
Assert-Contract (($provider.memberDataNames -join ',') -eq 'Cases') 'memberdata-nameof-reference-retained'
Assert-Contract ($provider.bindingStatus -eq 'SOURCE_DECLARATION_ONLY' -and -not $l.readyForExecutionSelection) 'declaration-not-execution-eligibility'


# VC-002D: literal InlineData belongs only to its declaring [Theory] method.
# This remains source evidence, never test execution or coverage certification.
$inline = @{} + $files
$inline['Carthago.Tests/InlineDataScoped.cs'] = @'
namespace Carthago.Tests;
public sealed class GroupedInlineTests {
 [Theory] [InlineData("R999")]
 [InlineData("R1000", "negative")]
 public void PerRule(string id, string? note = null) {}
 [Fact] [InlineData("R2999")] public void InvalidFact() {}
 [Theory] public void Unrelated(string id) {}
 private string decoy = "[InlineData(\"R3000\")]";
}
public sealed class SiblingInlineTests {
 [Theory] [InlineData("R3000")] public void Sibling(string id) {}
}
'@
$inlineInventory = Get-RuleSourceInventory -RegistrySource $registry -Sources $inline -SourceSha ('a' * 40)
$inlineR999 = @(@($inlineInventory.rules | Where-Object ruleId -eq 'R999')[0].associations |
    Where-Object { $_.path -eq 'Carthago.Tests/InlineDataScoped.cs' -and $_.kind -eq 'inline-data-attribute-candidate' })
Assert-Contract ($inlineR999.Count -eq 1 -and $inlineR999[0].containingTestMethod -eq 'Carthago.Tests.GroupedInlineTests.PerRule') 'single-argument-inline-theory-bound'
$inlineR1000 = @(@($inlineInventory.rules | Where-Object ruleId -eq 'R1000')[0].associations |
    Where-Object { $_.path -eq 'Carthago.Tests/InlineDataScoped.cs' -and $_.kind -eq 'inline-data-attribute-candidate' })
Assert-Contract ($inlineR1000.Count -eq 1 -and $inlineR1000[0].containingTestMethod -eq 'Carthago.Tests.GroupedInlineTests.PerRule') 'multi-argument-inline-theory-bound'
$inlineR2999 = @(@($inlineInventory.rules | Where-Object ruleId -eq 'R2999')[0].associations |
    Where-Object { $_.path -eq 'Carthago.Tests/InlineDataScoped.cs' -and $_.kind -eq 'inline-data-attribute-candidate' })
Assert-Contract ($inlineR2999.Count -eq 0) 'fact-with-inline-is-not-theory-coverage'
$inlineR3000 = @(@($inlineInventory.rules | Where-Object ruleId -eq 'R3000')[0].associations |
    Where-Object { $_.path -eq 'Carthago.Tests/InlineDataScoped.cs' -and $_.kind -eq 'inline-data-attribute-candidate' })
Assert-Contract ($inlineR3000.Count -eq 1 -and $inlineR3000[0].containingTestMethod -eq 'Carthago.Tests.SiblingInlineTests.Sibling') 'string-decoy-not-inline-and-sibling-not-borrowed'
Assert-Contract ($null -eq @($inlineInventory.rules | Where-Object ruleId -eq 'R999')[0].authoredMethodCount -and
    -not $inlineInventory.readyForExecutionSelection) 'inline-association-still-unverified'

# VC-002E: declaration candidates do not imply resolved rows or runnable tests.
$bindings = @($a.memberDataBindings | Where-Object { $_.theory -eq 'SharedTests.Case' })
Assert-Contract ($bindings.Count -eq 1 -and $bindings[0].providerName -eq 'Cases') 'memberdata-binding-recorded'
Assert-Contract ($bindings[0].bindingStatus -eq 'NEEDS_REVIEW') 'missing-provider-remains-unresolved'
Assert-Contract ($null -eq $bindings[0].authoredInvocationCount -and -not $bindings[0].readyForExecutionSelection) 'binding-never-certifies'

Write-Host 'Source-inventory contract assertions completed; no rule accuracy or operational claim.'
