# VC-002E — Scoped MemberData declaration candidates

SOURCE CANDIDATE — UNVERIFIED. No builds, tests or scripts executed.

The existing RuleSourceInventory now emits a separate memberDataBindings projection for [Theory] methods using nameof(MemberData). The projection retains the declaring class, consuming theory and provider name, and distinguishes a unique lexical declaration candidate from unresolved or ambiguous providers. It deliberately does not resolve provider rows, foreach expansions, test invocation counts, compiler-stage eligibility, or operational certification. A provider declared after the theory or with a computed/unsupported declaration remains NEEDS_REVIEW. These conservative candidates must not drive automated test selection.

The grouped R381–R390 and R531–R540 suites contain distinct providers for adversarial variations and profile contracts. Future work must associate each provider with its exact source tuple collection and preserve ambiguity when expressions cannot be statically resolved. All counts remain null until evidence is independently established.

Existing scripts and test project are reused. Threat-rule expansion, UI, confidence floors, frozen holdouts and CI controls are untouched. This is an incremental source index, not a compiler or verification result.
