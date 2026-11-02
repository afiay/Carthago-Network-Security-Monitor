# CARTHAGO — GA R550: BACnet cross-boundary discovery reply correlation

**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**.  
**Branch:** `feature/carthago-reliability-hardening` only.  
**Live source base (2026-11-02):** `f611cedba4b4d99c32976fb227383043f1b13878` (UI-73 documentation; detection-owned paths disjoint).  
**Source/test commits:** `a2f0da3b265f3f0f821dd3ff777b7a7e182b9015` (implementation, registry and tests), followed by `3bacd832f89ec33b22206bbadd003cd441636591` (authored-test source correction).  
**Source blob:** `de8ceb11a400607e0c5701129392125fc3036d3d`; **final authored-test blob:** `553993306d9ea9340b283bc2a03128e1a55eaec0`.  
**Publication SHA:** the verified live branch HEAD after the final non-forced expected-HEAD update; a commit cannot contain its own SHA.  
**Research crosswalk:** [P0046 BACnet](protocols/PROTOCOL_EXPANSION_PROGRESS.md), related P0382 BVLC framing; original P IDs are research row IDs, not new rules or independent decoder claims.

## One-rule decision matrix and deduplication

| Rule / disposition | Observable producer and novel predicate | Policy / limits | Existing overlap and benign alternatives |
| --- | --- | --- | --- |
| **R550 — BACnet Cross-Boundary Discovery Reply Correlation; AUTHORED** | `PacketHandler.ParseFrame` → `OtProtocolLight.TryIdentifyUdp` → typed `TrafficRecord.ApplicationProtocol` (`bacnet.whois` / `bacnet.iam`), `IpVersion`, `IsUdp`, both UDP/47808 ports, bounded `L4Len`, addresses and unique packet IDs. A public IPv4 source sends Who-Is-shaped datagrams to **two distinct RFC1918 targets**, and each target emits an I-Am-shaped datagram back to that same public source within **60 seconds**; both pairs complete within **five minutes**. | **CONDITIONAL** on bidirectional capture of both datagrams. High / Candidate / **Shadow** / 86% minimum confidence / two distinct paired targets / 5m window / 60s per-pair / 10m cooldown. 2048 source buckets, 64 targets and 256 packet IDs per source; monotonic, deduplicated, fail-closed saturation. | R241 recognizes BACnet discovery bursts; R545 recognizes public-to-private I-Am; R547 recognizes public-to-private Who-Is fanout. **None of those requires a reverse-direction, temporally paired I-Am-shaped observation from two distinct private endpoints.** Approved BBMD, foreign-device routing, commissioning and discovery can legitimately yield the same sequence. |

This is a new **two-direction temporal correlation predicate**, not another single-packet port label. The existing bounded classifier recognizes the BVLC length, NPDU and unconfirmed-service marker but **does not validate complete I-Am application parameters or authenticate device identity**. A minimum 21-byte I-Am-shaped datagram excludes header-only pseudo-replies; it is not a full BACnet semantic decoder. A reply after a request is **not cryptographic or causal proof** that a device answered that request. NAT, spoofed UDP source IPs, proxies, packet loss, visibility gaps and nonstandard BACnet ports limit precision/coverage. No BACnet/SC encrypted payload is decoded.

## Evidence, privacy and policy invariants

- Require coherent IPv4/UDP metadata, both ports 47808, parser-classified Who-Is or I-Am-shaped operations, no contradictory DNS/HTTP/TLS metadata, and strict RFC1918/public unicast direction. RFC5737 TEST-NET, benchmarking, loopback, link-local and multicast sources are excluded from public-origin claims.
- Packet IDs are deduplicated within each source bucket; unmatched replies, repeated replies from one target, reversed time, requests older than 60 seconds, completed pairs older than five minutes, and saturated state cannot manufacture threshold completion. An explicit suppressed result is returned during cooldown.
- The rule returns an ordinary `RuleEvaluationResult.Match` with structured, fixed, non-secret evidence. It does **not** copy `Info`, BACnet device identifiers, raw packet bytes, arbitrary headers or payloads, and it never directly sends UI notifications, external alerts or journal writes. The existing engine owns the mandatory journal-first `DetectionEvent` lifecycle.
- `TrafficRecord.ApplicationProtocol` is currently publicly settable; imported or fabricated records cannot be cryptographically attested. **Production-grade provenance and sensor trust remain unverified**, so the candidate stays Shadow. No shared model or capture schema was changed. Proposed approved-BBMD/engineering-host and maintenance-window tuning knobs are guidance, not implemented allowlists.
- R102/R118/R163 confidence floors 80%/86%/84%, all existing rule modes, suppression policies, pinned R102 V1 (historical 4/6) and pending V2 provenance remain untouched.

## Dated primary threat research and exploitation classification

- [ASHRAE BACnet Standard 135-2020 Addendum bx, 2024-09-30](https://bacnet.org/wp-content/uploads/sites/4/2024/10/135_2020_bx_20240930.pdf), Clause 16.10.2: Who-Is is normally broadcast and qualifying devices return I-Am; proxying can change which system emits I-Am. This justifies pairing *shapes* without assuming authenticated device replies.
- [MITRE ATT&CK ICS T0846, Remote System Discovery](https://attack.mitre.org/techniques/T0846/), **last modified 2026-10-13**, and [DET0739](https://attack.mitre.org/detectionstrategies/DET0739/): network discovery alone requires approved-role, target-scope and baseline context before operational alerting.
- [Siemens ProductCERT SSA-781903](https://cert-portal.siemens.com/productcert/html/ssa-781903.html), **2026-08-11**, reports CVE-2026-59693 (malformed BACnet denial of service) in specified Desigo DXR/PXC versions. This is **VENDOR_ADVISORY_NO_EXPLOIT_EVIDENCE** in the material reviewed, **not** a R550 signature: R550 does not inspect malformed exploit packets or firmware versions.
- [Siemens ProductCERT SSA-333035](https://cert-portal.siemens.com/productcert/html/ssa-333035.html), **2026-10-13**, describes availability risks in APOGEE/TALON/Desigo families; these do not prove R550 observes exploitation.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [FIRST EPSS](https://www.first.org/epss/) are separate exploit-status/risk sources. No BACnet discovery-pair-specific KEV confirmation, zero-day IOC, affected-device version or EPSS score is asserted. R550 generic behavior classification: **UNVERIFIED**.

## Authored advanced scenarios — NOT EXECUTED

[R550AdvancedAccuracyBatchTests.cs](../Carthago.Tests/R550AdvancedAccuracyBatchTests.cs) contains **20 xUnit methods / 28 concrete invocations** (18 Facts and 2 Theories with 5 InlineData each).

1. Raw IPv4/UDP frames passed through the actual `PacketHandler.ParseFrame` path for Who-Is and realistic-length I-Am-shaped classification, then two reverse-direction paired-target positive correlation with High severity/count/window.
2. Legitimate private commissioning, one-way requests, unsolicited I-Am and unrelated public-peer negatives.
3. Truncated/mismatched BVLC length, short I-Am envelope, Info-only claims, wrong transport, ports, IPv6, DNS and TLS contradictions, and RFC5737/benchmarking address negatives.
4. Duplicate packet IDs across targets, repeated replies to one target, out-of-order, >60-second reply, >5-minute expiry, separate source buckets, explicit cooldown suppression and concurrent reply evaluation.
5. Secret-free structured evidence, Candidate/Shadow/86% profile, registry uniqueness and config key.

**Tests executed: 0; builds/restores: 0; replays/holdouts/CI/Actions/runners/benchmarks/scans/captures: 0.** No compilation, precision, recall, F1, operational detection or CVE exploitation claim is made.

## Exact changed paths and next GA

- [R550 implementation](../Carthago/Engine/Rules/Expansion/R550_BacnetCrossBoundaryDiscoveryReplyRule.cs)
- [R550 advanced authored tests](../Carthago.Tests/R550AdvancedAccuracyBatchTests.cs)
- [RuleRegistry.cs](../Carthago/Engine/Rules/Catalog/RuleRegistry.cs): one explicit `R550` / `Rules.R550.Enabled` registration.
- This report: `docs/RULE_BATCH_550-550.md`.
- [Detection-owned protocol-informed threat backlog](rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md).

No historical protocol GA, UI folder/design ledger, shared `PacketHandler`/`TrafficRecord`, detection journal, workflow, security control or holdout was modified. Independent UI engineering remains active; older overlapping detection automations remain paused. The entire source candidate is published together through one expected-HEAD-protected, non-forced branch update or not published at all.

**Next proposed GA: R551**, subject to a fresh live registry, producer, duplicate-coverage and concurrency audit. Do not add a new rule solely to inflate the catalog.
