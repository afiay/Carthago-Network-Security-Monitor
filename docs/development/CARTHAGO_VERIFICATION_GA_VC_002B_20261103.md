# GA VC-002B — Preserve grouped-test candidates with simple interpolation

Date: 2026-11-03
Branch: feature/carthago-reliability-hardening
Parent SHA: 27cf9cba7f6ccaa9788b8c0214ede3420af99f10
Status: SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED.

## Confirmed discovery gap

VC-002's read-only source inventory discarded every C# file containing an
ordinary interpolated string. Existing grouped accuracy suites such as
NetworkBatch371380AccuracyTests.cs and NetworkBatch381390AccuracyTests.cs use
interpolated helper strings, so a filename-independent inventory could miss
their direct-class and explicit tuple associations. That omission must not be
interpreted as an absence of authored tests.

## Implemented narrow correction

The existing RuleSourceInventory PowerShell module now masks simple
interpolated C# strings as opaque source and opaque data while retaining
surrounding class declarations, constructor references and explicit literal
data rows. It does not interpret interpolation expressions as code or as
test-case data. Nested-quoted interpolation, raw/verbatim interpolation and
conditional compilation remain unsupported, with explicit diagnostics and
manual review required.

The existing source-only contract script adds six authored assertions:
ordinary interpolation accepted; literal grouped tuple retained; interpolation
does not fabricate a data row; nested quoted interpolation rejected; verbatim
interpolation rejected; compiler-guarded test source rejected. The earlier
13 assertions remain. Total authored assertions in this script: 19.
**None have been executed.**

## Unchanged boundaries

All discovered associations remain NEEDS_REVIEW, all method and invocation
counts remain null, and readyForExecutionSelection remains false. This is not
Roslyn semantic binding, MemberData expansion, compilation eligibility, test
execution or operational certification. The existing xUnit project, registry,
production validators, verifier entry points, workflow, holdouts, UI, capture,
rule-expansion files and policies are untouched. No build, test, replay,
holdout, benchmark, runner or live capture was invoked.

## Next step

Continue VC-002 with conservative class/method/provider binding and explicit
compiler-stage eligibility before feeding any selector into VC-004 profiles.
Do not treat candidate association as verified coverage. VC-003 production
four-digit ID compatibility still requires owner-approved shared-code
integration. The expansion automation handoff remains unmodified because its
management API does not provide an atomic expected-version precondition; the
exact proposed amendment is retained in VC-001.
