# GA VC-002D — Method-scoped InlineData source associations

Date: 2026-11-03
Branch: feature/carthago-reliability-hardening
Parent SHA: `27b1a650aaea0a6031587883a9ba321eda9245b4`
Status: SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED.

## Gap and bounded change

VC-002C recognizes class-scoped xUnit methods, but generic tuple/InlineData
candidate matching required a comma and could miss valid single-argument
`[InlineData("RNNN")]`. It also did not establish whether the attribute
belonged to a particular Theory method.

Extend the existing `scripts/RuleSourceInventory.psm1` masked lexical view.
A literal rule ID inside `InlineData` now yields
`inline-data-attribute-candidate` only when attached to exactly one recognized
`[Theory]` method. `containingTestMethod` retains the source identity.
Single- and multi-argument InlineData are supported. Fact, helper, sibling,
comment and ordinary-string decoys do not become bound Theory candidates.
Tuple and switch literals remain separate unbound data-row candidates.

Five synthetic contract assertions were authored in the existing gated
`scripts/verify-rule-source-inventory-contract.ps1`, bringing its source
assertions from 26 to **31 authored, 0 executed**. The assertions cover
single/multiple argument binding, invalid Fact association, sibling/string
decoys, and the unchanged unverified selection boundary.

## Invariants and remaining work

This is source evidence only, not a compiler, xUnit runtime, semantic
`MemberData` binder, proof of scenario polarity or operational certification.
All associations remain NEEDS_REVIEW; method/invocation counts remain null;
`readyForExecutionSelection=false`. Unsupported syntax and compiler-stage
guards remain unresolved. No builds, tests, replays, holdouts, CI, live capture,
benchmarks or runner jobs were executed.

No rule, registration, producer, shared production validator, UI, session
saving, workflow, security policy, frozen holdout or automation settings
were modified. The expansion handoff marker is already present exactly
once; independent rule expansion and UI work continue unaffected.

Next: VC-002 provider-to-rule MemberData flow, especially grouped
NetworkBatch381390/531540, and compiler-stage eligibility. VC-003 production
core/pack classification and numeric catalog ordering still require the
owner-approved exclusive integration window.
