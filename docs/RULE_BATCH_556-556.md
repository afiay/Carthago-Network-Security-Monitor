# CARTHAGO — GA R556: external SMB2 WRITE request private-subnet fanout

**Branch:** `feature/carthago-reliability-hardening`  
**Base HEAD:** `8dac306cc76696f7cb399fe6a4be3cb284376260` (2026-11-02).  
**Status:** **SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.** No restore, build, xUnit, replay, holdout, CI, runner, capture or packet scan was executed.

## Threat decision and deduplication

| Rule | P research and existing coverage | Novel observable predicate | Policy |
| --- | --- | --- | --- |
| **R556 — External SMB2 Write Request Private-Subnet Fanout** | **P0006 SMB** (PARTIAL_WIRE_IDENTIFICATION, bounded SMB2 WRITE request shape, not SMB authentication/session semantics). Existing R553 covers **private-to-private** SMB2 WRITE fanout, R249 SMB2 WRITE **private-to-public** and R076/R078 broader admin/lateral patterns; none requires **public-to-private** SMB2 WRITE requests across three internal /24s. P0113 named-pipe research is not claimed as supported. | One globally routable public IPv4 source sends existing PacketHandler-classified SMB2 WRITE requests on TCP/445 to **three distinct RFC1918 destination /24 networks** in **five minutes**, with unique packet IDs and coherent bounded typed metadata. | **High / Candidate / Shadow / minimum confidence 90% / threshold 3 / 5m window / 10m cooldown.** |

**Malicious hypothesis:** an external-origin client issuing SMB2 WRITE requests across segmented internal file servers may indicate unexpected cross-boundary file-placement activity. This is a **request-shape and target-fanout** detection only, not proof of successful authentication, an admin share, remote service execution, a completed write, malware deployment or exploitation. The existing classifier does not validate authenticated SMB session identity, server response status or file paths. Authorized remote backup gateways, managed external administration, NAT/VPN translation and segmented enterprise file services can resemble the predicate; external-to-private visibility depends on capture vantage point and routing. Encrypted SMB3 and fragmented/segmented traffic are outside this first-segment classifier. **No candidate-specific CVE/KEV exploitation is asserted and no EPSS value is assigned.**

## Provenance, runtime and safety

- **Producer:** `PacketHandler` TCP first-segment path → `NetworkBatch246250Wire.Smb2Write` → `TrafficRecord.ApplicationProtocol = smb2.write.request`; typed `Id`, `IpVersion`, `IsTcp`, `IsUdp`, `IsQuic`, `Protocol`, `Source`, `Destination`, `SourcePort`, `DestinationPort`, `L4Len`, `Length`. `ApplicationProtocol` is publicly settable: imported records can forge the label. **Live capture-origin provenance must be enforced upstream before Alert promotion.** No new producer or shared schema was changed.
- **Predicate:** source must be public IPv4 (explicitly exclude RFC1918, shared, loopback, documentation, benchmark, link-local and other reserved ranges), destinations RFC1918 in three different /24s, source TCP port >=1024, destination TCP/445, payload length 117–4096, coherent IPv4/TCP and no contradictory HTTP/DNS/TLS/QUIC metadata. No match from `Info`, ports alone, generic SMB, responses or truncated payloads.
- **State:** reuse instance-owned bounded `NetworkBatch226230Evidence.Window` (4096 source buckets with bounded per-source packet IDs/targets, monotonic timestamps) plus bounded per-source 10m cooldown; duplicate and out-of-order packets cannot inflate the threshold. Suppression is returned as `SuppressedMatch`.
- **Event:** only fixed protocol, cross-boundary, subnet-count, window and port markers are emitted. No SMB payload, share/file path, user, password, `Info` or raw command is copied. Existing RuleEngine owns journal-first persistence and Disabled/Shadow policy.
- **Invariant:** R102/R118/R163 confidence floors 80/86/84%, other modes, suppression, frozen V1 R102 holdout (historical 4/6), pending V2, UI and protocol ledger are unchanged.

## Source-only advanced xUnit coverage

**20 authored methods (18 Fact + 2 Theory), 30 concrete invocations (18 Fact + 12 InlineData); executed 0.** Scenarios cover bounded SMB2 WRITE wire-positive, CREATE/response/truncation negatives, three-private-/24 public-source positive, private/reserved/nonpublic source and destination negatives, same-subnet benign activity, Info/port-only spoofing, contradictory transport/application fields, malformed IDs/length, duplicate/out-of-order, distinct sources, window expiry, cooldown, concurrency, redaction, actual PacketHandler-produced positive and registry/Candidate/Shadow/90% invariants. **These assertions are not compiled or run.**

**Changed paths:** `Carthago/Engine/Rules/Expansion/R556_ExternalSmb2WriteTargetSubnetFanoutRule.cs`, `Carthago.Tests/R556AdvancedAccuracyBatchTests.cs`, `Carthago/Engine/Rules/Catalog/RuleRegistry.cs`, `docs/RULE_BATCH_556-556.md`, `docs/rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md`.

## Research, blocked higher-fidelity alternative and next GA

- [MITRE ATT&CK T1021.002 SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/) and [DET0530](https://attack.mitre.org/detectionstrategies/DET0530/) (updated 2026-05-12) identify lateral movement involving remote SMB shares, but **DET0530 requires additional authenticated share, service/process and outcome evidence not present here**. R556 is not claimed to implement DET0530.
- [Microsoft SMB feature descriptions](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-feature-descriptions) explain SMB encryption visibility and modern signing; [Microsoft SMB server hardening advisory](https://support.microsoft.com/en-us/servicing/os/windows/2025/09/support-for-audit-events-to-deploy-smb-server-hardening-smb-server-signing-smb-server-epa), originally 2025-09-09, describes audit support for signing/EPA. Neither establishes R556-specific exploitation.
- [FIRST EPSS](https://www.first.org/epss/) measures CVE exploitation likelihood, not observed SMB compromise; no candidate-specific score. [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) remains an advisory-priority source, not a substitute for packet evidence.

**BLOCKED higher-fidelity candidate:** authenticated admin-share WRITE followed by remote service creation cannot be safely inferred from `smb2.write.request`; requires a trusted Windows 5145/share-access and service/process outcome producer, identity/session join and owner-approved shared ingestion contract. Do not register that speculative rule. **Next proposed cursor R557** after fresh live registry/producer audit; no P0501, isolated inspector or test execution.
