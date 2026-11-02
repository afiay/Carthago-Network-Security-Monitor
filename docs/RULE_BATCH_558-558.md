# CARTHAGO — GA R558: internal NTP mode-7 monlist cross-subnet sweep

**Branch:** `feature/carthago-reliability-hardening`  
**Source audit base HEAD:** `8c053c93cbc23b13a522b2c329e3e57cf5635d3c` (2026-11-02).  
**Status:** **SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.** No restore, build, xUnit, replay, holdout, CI, runner, capture, benchmark or packet scan executed.

## Research mapping, novelty and malicious predicate

**R558 — Internal NTP Mode-7 Monlist Cross-Subnet Sweep** maps to historical **P0051 NTP** (PARTIAL bounded mode-7 recognition, not full NTP support). Existing **R242** detects monlist repetition; **R546** detects private-to-public monlist fanout; **R552** detects public-to-private fanout. None requires **one RFC1918 source sending parser-classified mode-7 MON_GETLIST_1 requests to three distinct other RFC1918 destination /24 networks in five minutes**. The source's own /24 is excluded. No new decoder, runtime, synthetic producer or P row was introduced.

**Malicious hypothesis:** a host probing legacy NTP control services across routed internal segments may be performing network-service discovery or seeking misconfigured NTP servers. This is a **request sweep**, not evidence of a server response, affected version, amplification, exploitation, authenticated sender or confirmed lateral movement. Approved vulnerability assessment, managed inventory, NTP maintenance and monitoring are realistic benign lookalikes. UDP source addresses can be spoofed; NAT or one-sided capture may obscure true origin.

**Policy:** Medium severity; Candidate maturity; **Shadow** default; **84% minimum confidence**; three remote RFC1918 /24s; 300-second window; 600-second cooldown. Require IPv4/UDP metadata, destination UDP/123, client source port >=1024, payload length 8–512, total packet length >= 28 + UDP payload length, unique nonempty packet IDs, monotonic timestamps, and disjoint source/destination /24. Fail closed for ordinary NTP sync, responses, port/Info-only claims, contradictory TLS/HTTP/DNS fields, malformed evidence, own-subnet and repeated-/24 probes.

## Producer, trust, privacy and runtime boundaries

- **Existing producer:** `PacketHandler.ParseFrame` -> `OtProtocolLight.TryIdentifyUdp` recognizes bounded NTP mode-7 request header bytes (mode 7, request, implementation 3, request code 42), then sets `TrafficRecord.ApplicationProtocol = "ntp.mode7.monlist"`; `NetworkBatch241245Evidence.NtpMonlist` validates typed UDP direction/ports. The rule reads `Id`, `Source`, `Destination`, `IpVersion`, `IsUdp`, `IsTcp`, `Protocol`, ports, `L4Len` and `Length`.
- **State:** existing instance-owned `NetworkBatch226230Evidence.Window`, bounded to 4096 source buckets and 512 packet IDs/target networks per source, duplicate-resistant and monotonic; saturation fails closed. Per-source cooldown state is bounded and expires.
- **Privacy/journal:** `DetectionEvent` structured evidence contains only fixed operation, aggregate count, window, conditions and destination-port markers. Do not persist raw `Info`, packet payload, hostnames, credentials, NTP data or secrets. `RuleEngine` retains journal-first persistence, Shadow/Disabled policy and suppression.
- **Provenance limitation:** `TrafficRecord.ApplicationProtocol` is publicly settable on imported records; imported traffic could impersonate the parser label. The source-only rule cannot authenticate capture origin. **No Alert promotion** without approved capture-origin assurance, scanner/maintenance allowlists, independent replay and field validation.
- **Visibility:** only IPv4 UDP packets visible to the local sensor; no authenticated NTP daemon version, response/amplification measurement, time-synchronization anomaly or host process audit. No shared `PacketHandler`, `TrafficRecord`, `TrafficCaptureService` or UI changes.

## Authored xUnit scenarios — not executed

**24 methods (22 Fact, 2 Theory); 32 concrete invocations (22 Fact + 10 InlineData); 0 executed.** Scenarios include actual bounded UDP classifier and `PacketHandler` parsed-frame positive; mode-7 request versus sync, response and truncation; public/reserved targets/sources; same-/24 exclusion; port/Info-only claims; invalid IP/UDP/payload/packet lengths; duplicate and empty packet IDs; source isolation; out-of-order and expired windows; cooldown suppression; concurrency; secret redaction; registry uniqueness and Candidate/Shadow/84% policy. These tests were authored, **not compiled or passed**.

**Exactly five detection-owned files changed:** `Carthago/Engine/Rules/Expansion/R558_InternalNtpMonlistCrossSubnetSweepRule.cs`, `Carthago.Tests/R558AdvancedAccuracyBatchTests.cs`, `Carthago/Engine/Rules/Catalog/RuleRegistry.cs`, `docs/RULE_BATCH_558-558.md`, `docs/rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md`. No UI, historical protocol ledger, frozen holdout, workflow, runner or shared sensor changes.

## Dated primary research, exclusions and next cursor

- [NTP Project BUG 1532 / CVE-2013-5211](https://www.ntp.org/support/securitynotice/ntpbug1532/) (updated **2026-09-03**) documents historical monlist amplification; reported exploitation in **December 2013** is not evidence of current R558 exploitation.
- [Cisco advisory CVE-2013-5211](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-CVE-2013-5211) (published **2014-01-09**) documents affected mode-7 behavior, not a version fingerprint detectable by R558.
- [MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/) and [DET0376](https://attack.mitre.org/detectionstrategies/DET0376/) (modified **2026-05-12**) describe network-service discovery and stronger process/connection correlation not provided by this packet-only rule.
- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [FIRST EPSS](https://www.first.org/epss/) are prioritization inputs. No R558-specific current KEV exploitation or FIRST EPSS score is asserted; EPSS estimates CVE exploitation likelihood, not evidence of this sweep.

**Blocked higher-fidelity candidate:** attributing monlist to an authenticated host/process, confirming a vulnerable `ntpd` version or actual amplification requires trusted host/asset evidence, validated response matching and owner-approved shared integration. Preserve R102/R118/R163 floors (80/86/84%), frozen R102 V1 holdout (historical 4/6), pending V2 and all rule-specific modes/windows/suppressions.

**Next proposed cursor R559**, only after a new live HEAD, registry, producer and duplicate-coverage audit. P0001–P0500 research remains finished; no P0501 or isolated protocol GA.
