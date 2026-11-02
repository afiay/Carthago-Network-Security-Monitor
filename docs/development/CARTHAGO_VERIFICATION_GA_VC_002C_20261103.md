# GA VC-002C — Class-scoped source test declarations

SOURCE CANDIDATE — UNVERIFIED. TESTS AUTHORED — 0 EXECUTED.
Baseline: `f4a20596fffce8c48e75f98f5c4d45b82d25154b`.
Branch: `feature/carthago-reliability-hardening`.

## Concrete gap and implementation

VC-002B correctly retained more grouped files by masking simple interpolation,
but candidate associations still used a file-wide Fact/Theory check. A helper
class constructing R2999 could therefore sit alongside unrelated tests without
the output exposing that the helper itself declared no test methods.

Extend the same `RuleSourceInventory.psm1`; do not introduce another framework.
Use its existing position-preserving code view to balance class/method braces.
Record the innermost owning class, direct attributed public void/Task test
method declarations, and the containing test method when a reference is inside
one. Nested classes use a separate `Outer+Nested` source identity. Names are
source identities for review, NOT guaranteed xUnit filter strings.

The implementation was planned and authored as this sequence:
1. Add synthetic sibling/helper/nested-class and MemberData declaration assertions.
2. Add block-boundary and class/method declaration readers over existing masked text.
3. Attach ownership context to existing candidate associations and expose declarations.
4. Inspect source and exact changed paths; defer all execution.

JSON schema version becomes 2. Existing rule association kinds and statuses are
retained. New association fields are `owningClass`, `declaredTestMethods` and
`containingTestMethod`; the root adds `testDeclarations` with source path,
identity, owning class, simple `MemberData(nameof(Name))` references and
`bindingStatus=SOURCE_DECLARATION_ONLY`.

`declaredTestMethods` is the enclosing class's declaration list, not proof that
each listed method covers the referenced rule. Helper references have no
containing test method. A tuple elsewhere in a class remains a candidate row,
not proof that a particular provider returns it. No method is invoked and no
MemberData provider is evaluated. All associations still require review.

## Reused components and consumer boundary

Reuse VC-002B lexical masking, registry extraction, diagnostics, numeric ordering,
Git-object wrapper, and the existing standalone PowerShell assertion script.
No existing verifier consumes this candidate JSON yet. The wrapper serializes
the returned object without assuming schema version 1. No xUnit project,
production validator, registry, rule, capture, schema or workflow was changed.

Supported declaration shapes are deliberately explicit. Multiple namespaces or
unbalanced recognized class blocks produce unresolved scope diagnostics.
Generic/partial/inherited test resolution, custom attributes, expression-bodied
methods, qualified/literal MemberData forms, external providers, and compiler
conditions are not established. Unsupported declarations must not be treated
as missing tests or as zero coverage. Full semantic binding remains unfinished.

## Authored checks and deferred evidence

Seven additional assertions bring the existing contract script from 19 to 26:
qualified owner; no sibling/nested method borrowing; constructor's containing
test method; helper with no borrowed test; separate nested identity;
MemberData nameof reference; and declaration-only status with selection disabled.

Zero assertions, scripts, builds, restores, xUnit runs, replay, holdout, capture,
benchmarks or runner jobs were executed. No passing claim is made. Per-rule
method/invocation totals remain null; `readyForExecutionSelection` remains false.
This change neither grants certification nor invalidates independent executed
rule evidence for unrelated source. Historical holdout outcomes remain intact.

## Coordination reconciled

The prior scheduled coordinator run is recorded completed. Its result reports
VC-002B at this baseline. That result's statement that the handoff was still
pending is stale: a fresh automation read confirms CARTHAGO_VERIFICATION_HANDOFF_V2
appears exactly once in the enabled expansion task, updated_at
`2026-11-02T23:04:32.925072+00:00`, retaining hourly :26 Europe/Stockholm.
Do not append it again. Expansion and UI task settings were not changed here.

## Remaining milestone

VC-002 still needs actual provider-to-rule data-flow binding, descriptor/class
identity reconciliation and project/compiler eligibility before selection can
be enabled. This GA supplies missing declaration context; it does not claim
complete semantic discovery. Shared production core/pack ID and catalog-order
changes remain blocked pending the owner-approved exclusive integration window.
The next source task should resolve the existing grouped MemberData forms and
report unsupported forms explicitly, rather than author another inventory.
