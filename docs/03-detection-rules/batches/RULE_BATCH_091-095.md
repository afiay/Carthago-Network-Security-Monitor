# Rule hardening batch 19 — R091–R095

**Status: CANDIDATE — UNVERIFIED.** Five rule implementations, a shared evidence validator, a typed development test factory, and **35 advanced xUnit facts** (seven for each rule). No builds, xUnit, benchmark, replay, frozen holdout, Windows runner or other automated project tests were executed.

| Rule | Prior code risk | Candidate change and evidence contract | Facts |
| --- | --- | --- | ---: |
| **R091 — Nmap/Masscan/Zgrab User-Agent** | Legacy matching of any substring in a supplied User-Agent could flag ordinary applications; alert evidence repeated the raw header, including potential tokens. | Requires coherent structured HTTP request and recognizable, boundary-delimited scanner self-identification in a bounded User-Agent. Excludes packet `Info`, hostnames and incidental substrings. Alert description is constant, not the User-Agent. | 7 |
| **R092 — Known Malware HTTP URI Pattern** | `/bot`, `/panel` and `/cnc` paths are shared by benign applications and legacy event evidence copied the URI with tokens. | Requires structured HTTP request and narrowly delimited `/gate.php` or `/c2/gate.php` endpoint path. Query parameters cannot manufacture evidence. Reports suspicious gate-like URI, **not independently confirmed malware**. | 7 |
| **R093 — Suspicious PowerShell Download Cradle over HTTP** | Legacy matching joined all normalized packet text and accepted PowerShell plus an unrelated download keyword. Original content could be included in evidence. | Requires an observed, bounded HTTP request target with a PowerShell/pwsh executable, a recognized remote retrieval operation, **and** an invocation operation. Info and unrelated protocol metadata are excluded. | 7 |
| **R094 — DGA-Like Domain Query** | Mature DNS precision logic already requires SLD entropy, vowel scarcity, digit mix, benign-root exclusion and baseline suppression, but its input method could accept a qname grafted onto contradictory telemetry. | Preserves rule precision profile, original configured entropy/length thresholds, confidence math, severity and baseline logic. Adds coherent structured DNS question, attributable IP endpoints, valid qtype/domain labels and nonresponse transport validation before the existing precision logic. | 7 |
| **R095 — Newly Observed Domain With High Entropy** | Same weak question attribution; baseline read failures were treated as first-seen candidates through global in-process novelty. Punycode exclusion was inconsistent with R094. | Same structured DNS question gate, rejects punycode SLDs, and explicitly fails closed on **baseline unavailable**. Preserves global novelty and persistent baseline logic when storage is available, including existing learning/Shadow policy and entropy/length thresholds. | 7 |

## Source, tests and coverage

`NetworkBatch091095Evidence.cs` centralizes bounded regexes for HTTP candidates (50 ms timeout), structured network validation, DNS question syntax and transport validation. R091–R093 reuse `NetworkBatch081085Dedup` to prevent duplicate record-ID alerts and its privacy-conscious event builder. R094/R095 remain `DnsPrecisionDetectionRuleBase` descendants with their existing `RulePrecisionProfile` and confidence evaluation: they are not replaced by a generic heuristic.

Five new `Carthago.Tests/RNNNAdvancedAccuracyBatchTests.cs` files and `NetworkBatch091095Context.cs` cover positive detections, benign lookalikes, evasive/request-encoded examples, missing and contradictory fields, duplicated records and previously known DNS observations, per-instance operational sequences, cancellation and private-content protection. DNS positive candidates use scoped `BaselineStore` test directories; these new cases have not been executed. No newly labeled replay sample was added where no faithful structured parser provenance exists.

The single deferred verifier `scripts/verify-all-rule-batches.ps1` remains unchanged and discovers the new classes automatically by filename.

## Material limitations

R091 scanner identity is self-declared and **not** independent proof of unauthorized scanning. R092 path shape alone does not authenticate malware; legitimate tools, security exercises or unrelated applications may use the same endpoint. R093 covers request targets, not encrypted traffic, payload bodies or execution outcomes. Literal/partly encoded patterns outside these contracts may be missed. Capture parser provenance and false-negative effects require review before any promotion.

R094 and R095 still use the legacy DNS precision event builder: it deliberately includes the queried domain in structured evidence, event summary and baseline keys for investigation and suppression. This batch **does not claim complete DNS-name pseudonymization**; review DNS retention/privacy policies separately before alerting on potentially identifying internal names. The detector's entropy is a noisy shape heuristic, not proof of DGA or compromise. New DNS validation can fail closed on limited capture metadata; test live UDP/TCP DNS adapters during the deferred acceptance. Baseline persistence remains a required trust dependency for novel-domain claims; no automatic promotion during learning or absence of assets was added.

R095's existing legacy test expects a candidate on first observation and may need reconciliation with the stronger no-unavailable-baseline guard if its test environment cannot write the default baseline. This is a known **UNVERIFIED regression risk**, not evidence of a pass.

## Governance

Configured defaults and thresholds, confidence floors **R102=80%, R118=86%, R163=84%**, Shadow/Disabled runtime policy, asset approvals, learning/readiness safeguards, frozen holdout and unrelated rules were not edited. Severity and existing precision policy remain unchanged; no malicious evidence relabeled and no accuracy/F1 percentage claimed.

**Status remains CANDIDATE — UNVERIFIED until the owner explicitly says “now it's test time” and the consolidated one-run Windows evidence is reviewed.**

**Next authoring batch: R096–R100.**
