# Rule hardening batch 20 — R096–R100

**CANDIDATE — UNVERIFIED.** Five DNS precision detectors, one shared evidence helper and **43 advanced xUnit facts** (R096: 9; R097: 8; R098: 8; R099: 8; R100: 10). Source, tests and this documentation were authored without running builds, xUnit, replay, holdout or any Windows runner.

| Rule | Evidence and state changes | Advanced facts |
| --- | --- | ---: |
| **R096 — Fast-Flux DNS Pattern** | Requires an attributable **DNS response**, coherent UDP/TCP and qtype, noncontradictory RCODE and bounded answer field. Counts distinct, syntactically valid **A/AAAA address tokens** rather than any dotted substring in answer prose; rejects malformed, repeated and wrong-family tokens. Retains the existing four-address threshold, TTL settings, confidence and cooldown. | 9 |
| **R097 — Excessive Unique Subdomains** | Requires an attributable **DNS question** before mutating the existing source/root distinct-label window. Preserves 25-distinct-label/5-minute defaults, label complexity, benign-root exclusion, cooldown and confidence. | 8 |
| **R098 — Suspicious Dynamic DNS Provider** | Requires a typed DNS question and counts **distinct record IDs** in the existing provider/query repeat window, so replaying the same record cannot inflate repetition. First-seen status now comes only from the durable baseline; in-process cache novelty is no longer substituted on baseline failure. Random-looking labels can still generate candidates under the existing Shadow/readiness policy. | 8 |
| **R099 — DNS Query to Newly Registered Domain** | Requires a typed DNS question, rejects missing/future/too-old reputation timestamps, invalid scores and unavailable baseline storage. The detector now describes its observable signal as **recent reputation activity**, not verified domain registration age; no registration date exists in `TrafficRecord`. Preserves the seven-day setting, confidence, risk scoring and baseline suppression. | 8 |
| **R100 — DNS Query for Internal Name to External Resolver** | Supports valid single-label names and internal suffixes; requires a private client and a syntactically valid, globally routable resolver IP, excluding CGNAT, RFC1918, documentation, benchmark and multicast destinations. Counts **distinct packet IDs** per client/resolver/qname to resist duplicate-record threshold inflation. Preserves three-event/ten-minute defaults, elevated WPAD fallback requirement and confidence. | 10 |

## Shared source contract

`Carthago/Engine/Rules/Abstractions/NetworkBatch096100Evidence.cs` provides a fail-closed DNS question/response validator, A/AAAA address-token counting, and private-client/public-resolver classification. It checks a real packet ID, UTC time, coherent endpoint IP families, port 53, transport flags, declared DNS parser protocol, DNS qname syntax, supported query type, nonresponse/response direction, and contradictory HTTP/QUIC/ICMP metadata. R100 explicitly permits single-label internal names; the other four require dotted qnames. DNS response RCODEs other than NOERROR are rejected for R096.

These rules retain `DnsPrecisionDetectionRuleBase`, their `RulePrecisionProfile` definitions, configured thresholds, minimum-confidence values, cooldowns, Shadow/Disabled behavior and approval/readiness policies. No changes were made to R102=80%, R118=86%, R163=84%, frozen holdout, asset approval or rule registration/configuration.

## Deferred test coverage

`Carthago.Tests/NetworkBatch096100Context.cs` provides deterministic typed DNS contexts. New `Carthago.Tests/R096AdvancedAccuracyBatchTests.cs` through `R100AdvancedAccuracyBatchTests.cs` cover real positive DNS shapes, realistic benign alternatives, malformed/duplicate A/AAAA answers, mixed-family evasions, missing or contradictory DNS/HTTP/transport fields, state isolation, distinct-record replay behavior, time-window expiry, WPAD fallback volume, invalid reputation enrichment, baseline persistence failure, cancellation and evidence keys.

No new replay fixture was fabricated: the existing replay format does not by itself prove parser-attributed DNS answer/RCODE, durable baseline or reputation provenance. The consolidated `scripts/verify-all-rule-batches.ps1` remains the **single deferred Windows acceptance entry point** and discovers these 43 cases by their established filenames. No test result or detection-quality percentage is asserted.

## Material limitations and follow-up

- **R096:** A low-TTL multi-address response is not independent proof of fast-flux infrastructure; CDNs, WAFs and sinkholes behave similarly. The answer parser accepts syntactically valid TEST-NET/IPv6 documentation addresses for offline fixture compatibility, so its count is **not** evidence of global routability. Production DNS answer parser formats and TCP/UDP direction require deferred adapter review.
- **R097:** Distinct-label windows remain shared process memory; out-of-order timestamps, unbounded root-key cardinality and long-running process memory need separate stress evaluation. Do not interpret high-cardinality CDN/service-discovery domains as exfiltration without corroboration.
- **R098:** A scanner's first-seen status requires durable baseline history. A random-looking DDNS name can still be a legitimate NAS, lab or VPN endpoint; no baseline-readiness gate or asset policy was weakened.
- **R099:** **ReputationLastSeen is not registration time.** The existing rule name is historical; verify the enrichment source semantics and add an independently authenticated registration-date field before making registration-age claims. The old R099 test relies on the default baseline location; its behavior after the new fail-closed storage guard is an **unverified regression risk**.
- **R100:** Strict private-client/global-resolver classification deliberately misses public-addressed enterprise clients and nonstandard/private resolvers. This is a precision tradeoff requiring labeled real-world validation. RFC address classifications should be reviewed for the deployment environment.
- **Privacy:** Existing DNS event builder persists raw qnames in structured evidence, event summaries and baseline keys. This batch does not anonymize internal DNS names or claim privacy compliance. Validate retention, access controls and pseudonymization separately.
- **Acceptance:** These 43 xUnit cases are authored, **not executed**. The batch remains **CANDIDATE — UNVERIFIED** until the owner explicitly declares “now it's test time” and the consolidated Windows run plus evidence review completes.

**Next five to author: R101–R105.**
