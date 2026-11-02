# GA VC-002 — Conservative pinned-source association inventory

Status: SOURCE CANDIDATE — UNVERIFIED. TESTS AUTHORED — 0 EXECUTED.
Baseline: `02a2183bc435fcfb7d76894d1a10483fd12d449c` on `feature/carthago-reliability-hardening`.

## Design and implementation plan

Continue VC-001's approved source-only contract. Use the existing PowerShell
script/module and standalone contract-script conventions. Retain the existing
xUnit project and every execution entry point. A textual source index is small
and dependency-free; a full Roslyn semantic discovery service would require
additional dependencies and compilation/reference decisions. Choose the index
for candidate association only, never for automated acceptance.

- [x] Inspect live registry, existing verifiers, heterogeneous grouped tests,
  Windows test project, workflow and the prior VC-001 contract.
- [x] Author synthetic contract assertions before the helper implementation.
- [x] Implement `Get-RuleSourceInventory(RegistrySource, Sources, SourceSha)` in
  `scripts/RuleSourceInventory.psm1`: direct core factory registration extraction,
  numeric ordering, duplicate/noncanonical/gap/missing-class diagnostics, and
  individual/grouped candidate associations without a fixed catalog ceiling.
- [x] Add `scripts/inspect-rule-source-inventory.ps1` to read immutable Git blobs
  at a required full SHA and emit JSON to stdout. Never read mutable source files
  as if they were that revision. Record input paths and blob SHAs.
- [x] Review source text and publication paths without importing/running scripts.
- [ ] Execute authored contracts only after fresh owner authorization identifies
  revision, session and contract scope. No such authorization exists in this GA.
- [ ] Resolve semantic associations and compile-guard eligibility before any
  existing verifier consumes this output. This remains unfinished VC-002 work.

## Exact scope and safety contract

The module discovers **candidate associations**, not verified test coverage:

| Association | Evidence retained | Limitation |
| --- | --- | --- |
| direct-class-candidate | R-prefixed class declaration and source line | Does not bind methods to that class |
| constructor-reference | Exact registered class construction in test source | May occur in a helper or unreachable method |
| data-row-candidate | Explicit tuple/InlineData/switch rule ID and source line | Does not prove MemberData binding or count row expansion |

All associations remain NEEDS_REVIEW. Rules with no discovered association are
marked NO_ASSOCIATION_FOUND; this is not a claim that no tests exist. Filenames never prove association.
Comments and ordinary string contents are masked for declaration/constructor
recognition. Data-row patterns are deliberately candidate-only: strings or
unrelated calls can resemble tuple data. Raw/interpolated strings and preprocessor
directives cause that entire source file to be marked unsupported and omitted
from candidate association; no conditional compilation is guessed. This may
omit many legitimate tests until semantic review. Duplicate core registration,
noncanonical numeric IDs, unrecognized factory entries and missing/ambiguous
class definitions cannot become silent success. A numeric ID gap is diagnostic,
not permission to renumber or fabricate a missing rule.

`readyForExecutionSelection` is always false. Method/invocation counts and
operational counts are null, not zero. `testsExecutedByInventory=0` describes
this read-only tool, not historical test execution. No shell command strings,
runner filters or enable/promotion decisions are emitted. Output contains
source locations and IDs, not captured packets, secrets or source excerpts.

The direct factory parser recognizes the current `CreateDefaultRules` array
shape only. A changed factory expression aborts extraction. Pack constructors
are reported unresolved; this is not a new production core/pack validator.
Actual descriptor IDs, category/precision metadata and runtime registration
must be reconciled in later semantic discovery. The helper does not claim that
an ID inferred from a class prefix is a runtime-validated descriptor ID.

The wrapper reads only tracked C# blobs beneath the existing rule and test
folders, using full SHA Git reads. It does not inspect private TRX, holdout,
packet or replay payload files, run dotnet, or call verification wrappers.
It emits a review inventory even if diagnostics exist; process success is
**not** an acceptance gate. The helper implementation's own revision must be
recorded alongside `sourceSha` when later archiving output.

## Authored contract coverage (not run)

`scripts/verify-rule-source-inventory-contract.ps1` uses the repository's existing
standalone PowerShell assertion convention. It authors 13 assertions covering
numeric R001/R999/R1000/R2999/R3000 ordering; ignoring comment/prose registration;
grouped constructor and explicit data rows; unknown counts; disabled execution
selection; absent associations; duplicate IDs; missing classes; unsupported raw
strings; leading-zero aliases; and pack constructors not treated as core.
The authorization switch is only a technical guard and never independently
authorizes a run. No new testing framework or xUnit compile dependency was added.

These assertions do not yet cover a real Git-object wrapper invocation, all C#
syntax, descriptor mismatches, nested/partial classes, full producer paths, or
runtime test identity resolution. No claim of compilation or script execution
success is made.

## Reconciled baseline and unchanged blockers

The live registry adds R566 after VC-001. Existing R544 limits remain in
verify-all-rule-batches, verify-rule-batch, verify-local and report display
bounds. Existing `RuleIdValidator` still recognizes three-digit core IDs and
can classify R1000 as a pack ID. RuleCatalog and CreateAvailableRules still
sort lexicographically. Consumer review must include RuleCatalog,
RuleCatalogValidation and ContentPackValidator; no exclusive integration window
has been approved, so none were edited. The Windows xUnit project still
references the application; filtering does not isolate compilation.

The single manual detection-quality workflow and all execution scripts remain
unchanged. Independent frozen V1 historical FAILED 4/6 is preserved. V2 remains
pending independent evidence/review. No confidence, mode, policy, producer,
journal, schema, capture, UI or rule expansion changes were made.

## Automation coordination

Expansion task `6ae4c4286f7c8191ba8c33575eb9afc6` was read in full, including its
prompt, schedule, enabled state and latest completed result. Observed updated_at:
`2026-11-02T22:36:12.793603+00:00`. CARTHAGO_VERIFICATION_HANDOFF_V2 is absent.
Its recorded latest result is GA R566 at `3020b6331b88fcac063a979478d883bbd5e2ee4e`.
UI task remains enabled and reports completed UI-96 at the audited baseline.
The management interface still lacks a guaranteed expected-version lease;
therefore no prompt overwrite or trigger was attempted. The exact proposed
amendment remains in VC-001, pending owner-controlled application. No independent
automation settings were changed.

## Next meaningful work

Finish VC-002 with semantic class/method/data-provider association and explicit
compile eligibility, without interpreting unknown cases as coverage. Then
prepare VC-004 profile consumption while preserving existing composite outcomes.
VC-003 production validator/order integration remains approval-dependent.
VC-005 certification must reuse descriptors and executed evidence, not this
candidate index as a second authoritative rule catalog.

## Publication reconciliation

Before publication HEAD advanced to
`66e07c3649ce2878d371171537fed195e724504c` (session auto-save). Its seven changed
paths concern the session merger, its tests, WPF session menus and session docs;
none overlap these four coordinator-owned files. The candidate tree is based
on that newer parent so those changes are retained. Publication requires one
non-forced expected_sha update against that exact parent; any further movement
must be reviewed again. This is source reconciliation, not runtime validation.
