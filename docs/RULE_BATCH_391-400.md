# GA R391–R400 — Overlay attribution and malware C2 provenance

**SOURCE CANDIDATE — UNVERIFIED · 2026-10-30.** Existing branch:
`feature/carthago-reliability-hardening`. Live pre-change HEAD:
`1bc051104de3973e04bf2d734f69e92819f8c37e` (includes the unrelated UI-04 publication).
Source candidate: `135aee3dc8c834680c19a63234cfea0588591dd3`.
Authored-test candidate: `5ef9f6752e1f6c127f87f1702c63a07e7c3ab0c3`.
Final documentation/publication SHA is the feature branch HEAD after the
single non-forced expected-HEAD update; it cannot be embedded in its own commit.

## Evidence contract and original profiles

The existing [packet producer](../Carthago/Services/PacketHandler.cs)
populates [TrafficRecord](../Carthago/Models/TrafficRecord.cs) flow, HTTP,
DNS and TLS fields; `HttpRequestHeaders`, `HttpHost`, `HttpUri` and `Info`
are not authenticated security attestations. No trusted ZeroTier node/controller
membership, server-role asset inventory, provider-specific C2 payload signature,
validated Sliver handshake, or authenticated C2 agent outcome producer was found
in the inspected rule evaluation path. A test fixture cannot supply that proof.

The original rules' generic name-token, process, protocol and URI signal
collector could turn ordinary traffic into family-specific alerts. The
[shared evaluation gate](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs)
now returns a rule-specific `InsufficientEvidence` reason **before** generic
signal scoring, burst counting, confidence calculation, cooldown mutation or
evidence construction. This is an intentional fail-closed precision correction,
not an operational detector or proof of accuracy. No new producer is invented.

| Rule | Original name | Disposition | Severity / confidence floor | Threshold / window / cooldown | Required missing evidence | Existing telemetry limitation | Legitimate false-positive risk |
| --- | --- | --- | --- | --- | --- | --- | --- |
| R391 | ZeroTier Network Join Indicator | **BLOCKED** | Medium / 82 | 1 / 15m / 30m | ZeroTier local node/controller join-state, network ID and authorization result | UDP/9993 or zerotier-one process is only connectivity, not join confirmation | Approved overlay/VPN management and peer traffic |
| R392 | Public Cloud CLI UserAgent From Server | **BLOCKED** | Medium / 82 | 1 / 15m / 30m | Trusted server asset role plus attributed HTTP User-Agent or authenticated process execution | HTTP User-Agent and ProcessName/Info cannot establish server role or CLI identity | Cloud administration, deployment agents and monitoring |
| R393 | Cobalt Strike Beacon URI Pattern | **BLOCKED** | Critical / 86 | 4 / 60m / 45m | Vetted profile-specific URI/payload plus independent beacon corroboration | /jquery and /api/v1 are generic; repetition cannot authenticate Beacon | Websites, CDNs, red-team ranges, sandboxes |
| R394 | Cobalt Strike Malleable C2 Header Pattern | **BLOCKED** | Critical / 86 | 1 / 30m / 45m | Verified profile-specific header grammar with independent payload/flow corroboration | Client-controlled HTTP headers are not a Malleable C2 signature | Custom applications and security testing |
| R395 | Sliver C2 MTLS Pattern | **BLOCKED** | Critical / 86 | 1 / 30m / 45m | Validated Sliver-specific handshake/fingerprint with packet attribution | Generic TLS/mTLS does not identify a Sliver implant | Enterprise mTLS and service meshes |
| R396 | Mythic Agent Callback Pattern | **BLOCKED** | High / 86 | 1 / 30m / 45m | Vetted Mythic payload or agent protocol signature | /callback or agent vocabulary is generic | Webhooks, integration callbacks, testing |
| R397 | Metasploit Meterpreter Stager Pattern | **BLOCKED** | Critical / 86 | 1 / 30m / 45m | Vetted stager payload/response correlation | /stage or packet length cannot prove Meterpreter | Legitimate staged downloads, penetration tests |
| R398 | Havoc C2 Callback Pattern | **BLOCKED** | Critical / 86 | 1 / 30m / 45m | Validated Havoc-specific callback signature | Generic callback route cannot establish Havoc | Webhooks and test harnesses |
| R399 | Brute Ratel Badger Pattern | **BLOCKED** | Critical / 86 | 1 / 30m / 45m | Validated Badger-specific protocol or payload signature | Beacon tokens and HTTPS flows cannot establish family | Monitoring beacons and approved exercises |
| R400 | Covenant Grunt Callback Pattern | **BLOCKED** | High / 86 | 1 / 30m / 45m | Validated Grunt callback payload/protocol evidence | /login/process and generic callback routes are not Grunt identifiers | Web apps and approved security exercises |

All ten retain original `Alert` mode, enabled/configuration keys,
severity, minimum confidence, threshold, time window, cooldown, approval,
baseline and journal contracts. The original `R393` four-in-60-minute
threshold remains configured but **cannot trigger without validated C2
identity**. R391/R392 remain at 82; R393–R400 remain at 86.
Legacy per-rule `TextIndicators` and `PathIndicators` metadata is **not**
validated signature evidence; the new fail-closed guard prevents it from
emitting events. A future authenticated producer requires a separately
reviewed GA before any rule can be promoted to CONDITIONAL/OPERATIONAL.

## Source ownership and privacy

Modified production source: only
[EvidenceDrivenPrecisionRuleBase.cs](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs).
Authored tests:
[NetworkBatch391400AccuracyTests.cs](../Carthago.Tests/NetworkBatch391400AccuracyTests.cs).
Documentation: this file and
[the progress ledger](RULE_HARDENING_PROGRESS.md). No WPF/UI, shared models,
capture parser, trust, profile, runner, workflow or other rule implementation
was modified. No new secret retention, packet capture, query logging or
unredacted evidence was added; blocked rules emit no event evidence.

The guard is scoped to the exact immutable R391–R400 IDs, preserving
unrelated detections. Existing runtime modes, confidence floors
(R102 80%, R118 86%, R163 84%, external R102 0.75), suppression,
approvals, privacy and frozen replay/holdout evidence remain unchanged.

## Authored xUnit scenario inventory — ZERO EXECUTED

[NetworkBatch391400AccuracyTests.cs](../Carthago.Tests/NetworkBatch391400AccuracyTests.cs)
contains **2 xUnit theory methods**, expanded into **120 concrete authored
invocations** (10 rules × 11 adversarial variations + 10 original-profile
invariant cases). Each of the ten rules has exactly these 12 cases:

| Case | Input / assertion |
| --- | --- |
| 1. plausible | Plausible family/overlay request with complete network identity; no match, exact rule-specific missing-producer reason |
| 2. descriptor-spoof | `Info` claims an authenticated callback or join; no match |
| 3. generic-path | Common `/api/v1/callback` and beacon words; no family attribution |
| 4. forged-audit | Synthetic `X-Audit-Result` and `X-Agent-Verified` headers; no match |
| 5. tls-only | TLS metadata without cleartext request; no match |
| 6. wrong-host | Host suffix spoofing; no match |
| 7. missing-source | Missing source address; no match |
| 8. malformed-target | Invalid percent-encoded path; no match |
| 9. privacy-token | Synthetic Authorization/query token; no event/evidence exposure |
| 10. benign-browser | Common browser request and URI; no false C2 attribution |
| 11. burst | Eight repeated generic requests; no fabricated threshold crossing or event |
| 12. profile-invariant | Original Alert mode, threshold and confidence floor preserved |

**120 TEST-AUTHORED, 0 TEST-EXECUTED.** The test file uses synthetic
traffic records only and asserts fail-closed behavior, not verified malware
detections. There is no sound positive family attribution possible with the
current evidence contract. No build, dotnet test, replay, holdout, CI,
benchmark, Windows runner or production capture was run. No compile,
pass, precision, recall, accuracy or certification claim is made.

## Static divergence review and outstanding quality GAs

- Pre-change: inspected live HEAD `1bc051104de3973e04bf2d734f69e92819f8c37e`, R381–R390 publication,
  the ten original rule classes, generic evidence collector, parser fields,
  existing test fixtures, profile/mode/threshold/cooldown and docs standard.
- Pre-publication: recheck current remote HEAD and all changed paths against
  concurrent UI-only work; publish a complete source/test/docs candidate only
  with a **non-forced expected-HEAD lease**. Reconcile only disjoint commits.
- Windows compilation and the 120 authored cases are unexecuted. Static source
  inspection is not a build or test pass.
- R391 needs trusted node/controller join state; R392 needs trusted server
  inventory and attributable User-Agent. R393–R400 need vetted, versioned
  family-specific signatures and realistic benign/malicious holdouts.
- Profile maturity labels and generic legacy indicator metadata must not be
  mistaken for field validation. Any future profile correction requires a
  separate compatibility review, not silent threshold relaxation.
- Independent replay expectations R343/R295/R275/R163 remain open; frozen
  R102 V1 **FAILED 4/6**, V2 **0/4 approved sources** unchanged.
  Historical full 4,940/4,940 test checkpoint predates these candidates.

**Next contiguous ten-rule GA: R401–R410**, only after coherent publication
and a new live HEAD review.

## References

- [ZeroTier controller and member authorization](https://docs.zerotier.com/controller/)
  — a local/controller state query distinguishes membership and authorization
  from ordinary UDP connectivity.
- [ZeroTier enterprise deployment and port usage](https://docs.zerotier.com/enterprise-deployment/)
  — UDP/9993 is connectivity, not evidence of a completed network join.
- [Cobalt Strike Malleable C2 profile language](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_profile-language.htm)
  — operators can configure URI and header behavior, invalidating generic
  path/word attribution.
- [Microsoft C# identifier conventions](https://learn.microsoft.com/en-us/dotnet/csharp/fundamentals/coding-style/identifier-names)
  — stable public rule IDs and contracts remain unchanged.
