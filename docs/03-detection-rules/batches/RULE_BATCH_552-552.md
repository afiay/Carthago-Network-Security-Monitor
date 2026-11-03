# CARTHAGO — GA R552: External NTP Mode-7 Monlist Private-Subnet Fanout

**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED  
**Branch:** `feature/carthago-reliability-hardening`  
**Live source base SHA:** `9b3691c9063bf74815b1fb7405e64f7f17a62e40` (2026-11-02)  
**Source, registry and authored-test commit SHA:** `95857da83ab80faec3f5659e6469859ca1d8701c` (unpublished source commit until the cohesive documentation descendant is atomically published)  
**Publication/documentation SHA:** the resulting Git commit containing this document, recorded in the publication result (a commit cannot embed its own SHA).  
**Next proposed cursor:** R553, subject to fresh live registry, producer and concurrency review.

## Rule matrix and research mapping

| Rule | Historical research | Falsifiable typed predicate and producer | Mode / severity / minimum confidence | Threshold / window / cooldown | Disposition |
| --- | --- | --- | --- | --- | --- |
| **R552** External NTP Mode-7 Monlist Private-Subnet Fanout | **P0051 NTP** (partial existing wire classifier, not a new decoder) | Existing `PacketHandler` → `OtProtocolLight.TryIdentifyUdp` → `TrafficRecord.ApplicationProtocol == "ntp.mode7.monlist"`; one **public unicast IPv4 source** sends client-to-server UDP/123 MON_GETLIST_1-shaped requests to **three distinct RFC1918 destination /24s** within five minutes, with coherent UDP/IPv4, source port >=1024, bounded payload length and unique packet IDs | **Candidate / Shadow / Medium / 84%** | 3 private /24s / 5m / 10m | **CONDITIONAL source-defined registered rule**; no new decoder or live sensor integration |

**Novelty and overlap:** Existing R242 counts repeated NTP monlist requests to a source/destination pair, while R546 correlates *internal-to-public* monlist target fanout. R552 instead correlates **public-to-private** requests crossing **three private /24 networks**, excluding multiple hosts in a single /24. It is not a generic UDP/123 scan and does not infer an NTP response, amplification, affected ntpd version, successful exploitation, authenticated source identity, or an external Internet path through NAT.

## Source reachability, privacy and invariants

- **Actual producer:** [PacketHandler](../../../Carthago/Services/PacketHandler.cs) recognizes UDP datagrams using the bounded [OtProtocolLight](../../../Carthago/Services/OtProtocolLight.cs) mode-7 request discriminator; [NetworkBatch241245Evidence](../../../Carthago/Engine/Rules/Expansion/NetworkBatch241245Evidence.cs) verifies the typed UDP operation. The detector uses only `Id`, `Source`, `Destination`, `IpVersion`, `IsUdp`, `IsTcp`, `IsQuic`, `Protocol`, `SourcePort`, `DestinationPort`, `ApplicationProtocol`, `L4Len`, absent contradictory HTTP/TLS/DNS fields, and `RuleEvaluationContext.TimestampUtc`. Neither port-service hints nor `Info` can establish the operation.
- **Visibility:** only when the Windows packet capture sees the original unencrypted IPv4 UDP request and the source/destination boundary *after any NAT*. ETW-only records, encrypted/tunneled traffic, incomplete datagrams, one-sided or missing capture, and unobserved internal networks cannot satisfy the predicate. The 8-byte mode-7 discriminator is a request **shape**, not full application validation. No NTP server response or version is available.
- **Provenance limit:** `TrafficRecord.ApplicationProtocol` remains publicly settable and source IP can be UDP-spoofed; an imported/synthetic record is not cryptographically authenticated as packet-captured. The authored raw-frame test demonstrates that the real producer *can* generate the expected typed evidence but does not establish unforgeable provenance. Retain **Shadow** and require trusted sensor origin, approved scanner/source roles and asset context before promotion.
- **False positives:** authorized external vulnerability scans, NTP inventory, managed-provider probes, routing/NAT, maintenance and spoofed-source traffic. No allowlist is asserted to be implemented; listed tuning knobs are future policy options.
- **Bounded state:** reuse the existing instance-owned [NetworkBatch226230Evidence.Window](../../../Carthago/Engine/Rules/Expansion/NetworkBatch226230Evidence.cs) with at most 4,096 source buckets, 512 packet IDs and 512 distinct targets per source; monotonic timestamps, duplicate-ID exclusion, five-minute expiry, lock-protected observations and fail-closed saturation. A bounded ten-minute per-source cooldown returns `SuppressedMatch` rather than a false no-match.
- **Privacy and lifecycle:** the new [R552 rule](../../../Carthago/Engine/Rules/Expansion/R552_ExternalNtpMonlistPrivateSubnetFanoutRule.cs) emits only fixed, non-secret aggregate evidence (`ntp.operation`, `matched_conditions`, `count`, `window_seconds`, destination port). It does not copy `Info`, payload, source identity or credentials into evidence. Normal [RuleRegistry](../../../Carthago/Engine/Rules/Catalog/RuleRegistry.cs) registration and `DetectionEvent` match lifecycle preserve JSONL journal-first persistence. No direct UI, sink, incident, or audit write; no changes to R102/R118/R163 confidence floors, mode semantics, pinned holdouts, shared capture or telemetry schemas.

## Threat research and exploitation classification

| Primary reference and date | Exact claim and relevance | Classification for this rule |
| --- | --- | --- |
| [NTP Project BUG 1532](https://www.ntp.org/support/securitynotice/ntpbug1532/), last updated **2026-09-03**; original fix **2010-04-24** | CVE-2013-5211 affects `ntpd` releases before **4.2.7p26** with unrestricted monlist. Vendor notes exploitation in **December 2013** using forged mode-7 requests. The R552 request shape cannot determine affected version, configuration or responses. | **CONFIRMED_EXPLOITED_KNOWN_VULNERABILITY — historical 2013 only**; no 2026 exploitation inference |
| [Cisco security advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-CVE-2013-5211), first published **2014-01-09** | Affected Cisco products may process mode-7 requests and amplify responses. R552 does not identify Cisco products or successful amplification. | Vendor context, **not candidate-specific proof** |
| [MITRE ATT&CK T1595](https://attack.mitre.org/techniques/T1595/), last modified **2025-10-24** | Active scanning can use native protocol requests. The observed public-to-private three-subnet pattern is compatible with reconnaissance but also with authorized scans. | Technique context only |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), checked **2026-11-02** | No candidate-specific KEV record or current exploitation evidence is asserted from this review. | **UNVERIFIED for current exploitation** |
| [FIRST EPSS](https://www.first.org/epss/), checked **2026-11-02** | EPSS estimates probability of future CVE exploitation, not observed exploitation; no numerical score was retrieved or assigned. | No EPSS-derived detection claim |

## Authored scenario matrix — not executed

[Advanced xUnit source](../../../Carthago.Tests/R552AdvancedAccuracyBatchTests.cs) contains **21 test methods**: **19 `[Fact]`** and **2 `[Theory]`** with **9 `[InlineData]`** cases, totaling **28 concrete invocations** if discovered and executed.

| Scenario family | Authored coverage |
| --- | --- |
| Positive and producer | NTP mode-7 parser classification; three different private /24s; actual IPv4/UDP frame → `PacketHandler.ParseFrame` → rule positive |
| Benign and cross-protocol negatives | Ordinary NTP sync, public or reserved targets, nonpublic sources, repeated same target or distinct hosts within one /24, source isolation |
| Malformed, spoofed and privacy | Truncated/response/incorrect-mode wire prefixes, Info-only false evidence, wrong port/transport, TLS/DNS/HTTP contradictions, missing/invalid payload length, IPv6, raw secret-marker redaction |
| Temporal, state and concurrency | Duplicate packet ID, out-of-order event time, five-minute expiry, ten-minute cooldown suppression, concurrent three-target evaluation |
| Policy and registry | Unique R552 registration, Candidate/Shadow profile, 84% minimum confidence, telemetry validation |

**Authored:** 21 xUnit methods / 28 parameterized invocations. **Executed:** 0. **Builds:** 0. **CI, replay, holdout, runner, capture, scan:** 0. No compilation, precision, recall, F1, or test-pass claim.

## Exact source changes and next GA

- `Carthago/Engine/Rules/Expansion/R552_ExternalNtpMonlistPrivateSubnetFanoutRule.cs` — new ordinary registered rule, not a standalone inspector.
- `Carthago.Tests/R552AdvancedAccuracyBatchTests.cs` — source-only advanced test scenarios.
- `Carthago/Engine/Rules/Catalog/RuleRegistry.cs` — one explicit R552 registration, no renumbering.
- `docs/RULE_BATCH_552-552.md` — this GA evidence and limitations.
- `docs/rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md` — additive detection-owned decision record.

**Next candidate cursor:** R553 **only if** the next live source/registry audit confirms it unused and a genuinely novel producer-backed predicate qualifies. DTLS appliance outcomes, encrypted web edge semantics, unauthenticated MQTT-origin flags, Windows lateral outcomes and non-IP Layer 2 capture remain blocked pending explicit source/telemetry integration authorization. Do not reopen the completed P0001–P0500 protocol GAs.
