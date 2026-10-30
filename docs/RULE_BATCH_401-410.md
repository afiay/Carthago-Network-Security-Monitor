# GA R401–R410 — Malware-family attribution provenance

**SOURCE CANDIDATE — UNVERIFIED · 2026-10-30.** Existing branch:
`feature/carthago-reliability-hardening`. Live pre-change HEAD:
`1995ffe2d2fde5366527617d1d65597cc8c4301f` (includes the independent UI-05 publication).
Source commit: `e36e782ed7d62c4e703f85746d85b9d87931c01b`. Authored-test commit: `265c85829b42a191f403ca148a888b4ff9ff2f12`.
Final documentation/publication commit is the live feature HEAD after the
single non-forced expected-HEAD update; it cannot contain its own SHA.

## Evidence contract and original profiles

The original [R401–R410 implementations](../Carthago/Engine/Rules/Expansion/)
all inherit `MalwareC2PrecisionDetectionRuleBase` and the shared
[EvidenceDrivenPrecisionRuleBase](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs).
They use generic `TextIndicators`, common web paths and protocol tokens.
Those are not independently validated malware-family signatures. The
[PacketHandler](../Carthago/Services/PacketHandler.cs) produces bounded flow,
early HTTP, DNS and TLS observations; it does not establish malware payload
identity, authenticated Telegram agent behavior, SMTP exfiltration outcome,
removable-media LNK execution, or cross-process delivery chains. `Info`,
`ProcessName`, HTTP headers and client-provided Host are not authenticated
attestations. TLS is not decrypted. A synthetic fixture cannot substitute for
a trusted producer.

The source candidate adds a **per-ID fail-closed guard** after the existing
core/protocol/boundary checks and before generic signal scoring, burst state,
confidence, cooldown mutation or event/evidence construction. It preserves
the existing rule classes, profiles, config keys and runtime modes. No validated
malware-family positive can be represented at this evidence boundary.

| Rule | Original name | Disposition | Severity / floor / mode | Threshold / window / cooldown | Missing trusted evidence | Legitimate traffic false-positive risk |
| --- | --- | --- | --- | --- | --- | --- |
| R401 | Empire Stager URI Pattern | **BLOCKED** | High / 86 / Alert | 1 / 30m / 45m | Vetted Empire-specific stager URI/payload signature and independent response correlation | Common staging URLs, admin download endpoints, approved red-team activity |
| R402 | AsyncRAT Telegram C2 Pattern | **BLOCKED** | Critical / 86 / Alert | 1 / 30m / 45m | Attributable AsyncRAT agent behavior and authenticated Telegram message context | Ordinary Telegram bot automation and notification services |
| R403 | Remcos RAT C2 Pattern | **BLOCKED** | Critical / 86 / Alert | 1 / 30m / 45m | Validated Remcos-specific packet/payload protocol signature with flow provenance | Generic TCP/TLS sessions and approved remote-support tools |
| R404 | AgentTesla SMTP Exfil Pattern | **BLOCKED** | Critical / 86 / Alert | 1 / 30m / 45m | SMTP envelope/content provenance, transfer outcome and Agent Tesla attribution | Legitimate mail clients, SMTP relays and scheduled reports |
| R405 | QakBot URI Pattern | **BLOCKED** | High / 86 / Alert | 1 / 30m / 45m | Validated QakBot-specific HTTP request/payload signature | Ordinary website paths, content delivery and incident-response replay |
| R406 | Emotet Loader URI Pattern | **BLOCKED** | High / 86 / Alert | 1 / 30m / 45m | Versioned Emotet loader payload/response signature | Legitimate downloads, updates and staging paths |
| R407 | Bumblebee Loader URI Pattern | **BLOCKED** | High / 86 / Alert | 1 / 30m / 45m | Validated Bumblebee loader delivery/payload signature | Normal software download, packaging and update traffic |
| R408 | SocGholish FakeUpdate Pattern | **BLOCKED** | High / 86 / Alert | 1 / 30m / 45m | Vetted fake-update delivery/payload evidence and browser-to-execution correlation | Genuine browser and software update notices |
| R409 | Raspberry Robin Short LNK Pattern | **BLOCKED** | Medium / 86 / Alert | 1 / 30m / 45m | Trusted removable-media LNK file/shortcut execution telemetry | Ordinary shortcuts, USB administration and generic Windows process names |
| R410 | Redline Stealer Exfil Pattern | **BLOCKED** | Critical / 86 / Alert | 1 / 30m / 45m | Validated RedLine payload or exfiltration content and response correlation | Ordinary uploads, backup, synchronization and browser traffic |

All ten have original `MinimumSignals=2`, enabled default, outbound-external
requirement, and the listed 86% confidence floor. R401, R405, R406 and R407
also require HTTP context. The original threshold 1 and cooldown 45m remain
configured but cannot generate a family-attributed alert without a validated
producer. Rule descriptive names, `RequiredTelemetry` arrays, and maturity
metadata are not proof that those producers exist.

## Changed source, privacy and compatibility

- Production source: [EvidenceDrivenPrecisionRuleBase.cs](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs).
- Authored tests: [NetworkBatch401410AccuracyTests.cs](../Carthago.Tests/NetworkBatch401410AccuracyTests.cs).
- Documentation: this batch file and [progress ledger](RULE_HARDENING_PROGRESS.md).

The guard is scoped **only** to R401–R410. It does not alter the ten
rule files, any WPF/UI, models, services, capture, shared API, other rule IDs,
profile thresholds, runtime modes, suppression, approvals, baseline, journal,
or frozen evidence. No new credential capture, raw payload retention, URL
logging or secret-bearing event is added. Blocked rules emit no events.
Legitimate mail, bot automation, updates, backups, and authorized security
testing would otherwise be vulnerable to generic-path/family-name false
attribution. Blocking unsupported attribution can miss genuine malware:
this is a precision safety boundary, **not validated recall**.

## Authored xUnit scenario inventory — ZERO EXECUTED

[NetworkBatch401410AccuracyTests.cs](../Carthago.Tests/NetworkBatch401410AccuracyTests.cs)
contains **2 theory methods and 120 concrete invocations**:
10 rule IDs × 11 adversarial/benign cases, plus 10 profile invariants.
Every rule receives all 12 scenarios:

| # | Scenario | Contract |
| --- | --- | --- |
| 1 | plausible | Network-attributed HTTP request and named behavior; exact missing-producer reason, no event |
| 2 | descriptor-spoof | Free-form Info claims successful authenticated family callback; no event |
| 3 | generic-path | Generic /jquery/api/v1/callback and beacon tokens; no event |
| 4 | forged-audit | Client-controlled X-Audit-Result / X-Family-Verified headers; no event |
| 5 | tls-only | Encrypted TLS metadata without visible request/payload; no family inference |
| 6 | missing-source | No source attribution; no match |
| 7 | malformed-target | Malformed percent-encoding; no match |
| 8 | privacy-token | Synthetic token-like query/header; no evidence/event exposure |
| 9 | benign-browser | Common browser update request; no malware-family alert |
| 10 | family-specific-claim | R402 Telegram bot URL, R404 SMTP DATA, R409 shortcut/process claim; all untrusted without provenance; other family names in Info also untrusted |
| 11 | burst | Eight repeated generic requests cannot satisfy missing identity proof or generate an event |
| 12 | profile-invariant | Original Alert mode, threshold 1, floor 86, 30-minute window, 45-minute cooldown |

The cases assert no unsupported family match or event; the plausible/burst
cases additionally require the exact missing-producer reason. No positive
malware-family case is sound without independently validated family evidence.
**120 TEST-AUTHORED; 0 TEST-EXECUTED.** No build, xUnit, replay, holdout,
benchmark, CI, runner, or production capture was executed. No compile,
pass, accuracy, precision, recall or certification result is claimed.

## Static divergence review and outstanding quality GAs

- Pre-change: checked live `1995ffe2d2fde5366527617d1d65597cc8c4301f`, R391–R400 publication, the ten
  original R401–R410 classes, existing shared evaluator, packet producer,
  prior unexecuted tests and documentation standard.
- Pre-publication: verify exact source/test/docs-only paths and the live
  remote HEAD; publish all three commits with a single non-forced,
  expected-HEAD-protected ref update. No partial branch publication.
- Outstanding: Windows compilation; 120 authored cases; independently
  vetted, versioned family signatures; benign/malicious traffic corpora;
  packet attribution; SMTP outcome and LNK execution producers; privacy
  review; precision and recall measurements. These are separate GAs.
- Frozen R102 V1 **FAILED 4/6**, V2 **0/4 approved sources**; floors R102
  80%, R118 86%, R163 84%, external R102 0.75 preserved. R343/R295/R275/R163
  replay expectations remain separate. Historical 4,940/4,940 full test
  checkpoint predates these source candidates.

**Next contiguous ten-rule GA: R411–R420**, subject to live HEAD review
after coherent publication.

## References

- [MITRE ATT&CK — Command and Control](https://attack.mitre.org/tactics/TA0011/)
  — command/control behaviors are not inherently family-unique.
- [MITRE ATT&CK — Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
  — service usage alone is not proof of a particular stealer.
- [Microsoft — C# identifier naming](https://learn.microsoft.com/en-us/dotnet/csharp/fundamentals/coding-style/identifier-names)
  — preserve stable public rule IDs and compatible source conventions.
