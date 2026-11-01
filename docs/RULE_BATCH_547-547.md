# GA R547 — external BACnet Who-Is target fanout

**Branch:** `feature/carthago-reliability-hardening`  
**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**.  
**Live source base HEAD:** `3fd5e0fade9792a0e294252edebdb117e85feead` (2026-11-01).  
**Publication:** One atomic expected-HEAD update containing this report, source, tests, registry and backlog. The final commit SHA is recorded in the publication response, not embedded in its own content.  
**Authored source blob:** `98bb98621aa1eb9f2cecc7439ac0ecfe9df9829d`; **authored test blob:** `0cb38662a0d4cdbd043619bb6f40cb3208545494`.  
**Next proposed cursor:** R548 after a fresh live registry audit; no quota-driven extra rules.

## Research, overlap and observable security behavior

| Rule | Historical P input and existing overlap | New exact positive predicate | Severity / policy | Boundaries |
| --- | --- | --- | --- | --- |
| **R547 — External BACnet Who-Is Target Fanout** | **P0046 BACnet**; P0382 BVLC as related framing; R241 counts 15 Who-Is/I-Am packets in 2m, R545 counts two inbound I-Am announcements for one pair, R223 addresses generic ICS internet exposure. | One **globally routed public IPv4 source** sends **three distinct wire-classified BACnet Who-Is UDP requests** to **three distinct RFC1918 IPv4 destinations** on both UDP ports 47808 within **5 minutes**, using unique packet IDs and coherent IPv4/UDP/payload-length metadata. | **High / Shadow**, Candidate, **80% confidence floor**, threshold 3 distinct private targets, window 300s, cooldown 600s. | Request fanout only. No proof of authenticated source, device presence, BACnet response, authorization, vulnerability, command, process change or exploitation. |

**Novelty:** R241's burst is packet-count based and combines Who-Is and I-Am; R545 examines the **I-Am** announcement direction and a fixed public/private endpoint pair. R547 examines the **Who-Is** request direction and **distinct-target** fanout from one public source. Three single requests to different private targets can match R547 without reaching R241's 15-packet threshold. This is a different, falsifiable reconnaissance predicate rather than a protocol label or a renamed prior rule.

**Trusted producer and reachable fields:** [PacketHandler](../Carthago/Services/PacketHandler.cs) calls [OtProtocolLight.TryIdentifyUdp](../Carthago/Services/OtProtocolLight.cs), which validates the BACnet/IP BVLC length and Who-Is operation bytes before assigning `TrafficRecord.ApplicationProtocol="bacnet.whois"`. The [typed record](../Carthago/Models/TrafficRecord.cs) supplies `Id`, `Source`, `Destination`, `Protocol`, `IsUdp`, `IsTcp`, `IsQuic`, `IpVersion`, `SourcePort`, `DestinationPort`, `L4Len`, and contradictory TLS/HTTP/DNS fields. [NetworkBatch241245Evidence.Bacnet](../Carthago/Engine/Rules/Expansion/NetworkBatch241245Evidence.cs) validates the UDP and operation contract. `ApplicationService` and `Info` are **not** authoritative. The sensor must see the relevant unencrypted IPv4 UDP datagrams; it cannot infer routed traffic outside its capture position.

**False positives and policy:** Approved BBMD/foreign-device routing, VPN/NAT, building commissioning, asset inventory and BMS discovery may generate legitimate cross-boundary traffic. UDP source IPs may be spoofed. The default **Shadow** policy is intentionally non-paging: MITRE ATT&CK ICS [T0846](https://attack.mitre.org/techniques/T0846/) and [DET0739](https://attack.mitre.org/detectionstrategies/DET0739/) (modified **2026-10-13**) require asset-role, authorized source and operational-baseline checks before promotion. ASHRAE's [2025 BACnet interpretation](https://www.ashrae.org/file%20library/technical%20resources/standards%20and%20guidelines/standards%20intepretations/ic-135-2024-8.pdf) provides routing context. **Threat classification: UNVERIFIED** for this particular fanout; no dated vendor or CISA KEV evidence establishes a BACnet Who-Is CVE exploitation signature. [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) returned HTTP 403 during this source review; no FIRST [EPSS](https://www.first.org/epss/) score is invented.

## Implementation and invariants

- New ordinary registered [R547 rule](../Carthago/Engine/Rules/Expansion/R547_ExternalBacnetWhoIsTargetFanoutRule.cs) derives from the existing `IotOtAdvancedPrecisionDetectionRuleBase` and uses the normal `RuleEvaluationResult` → `DetectionEvent` → engine journal-first pipeline. [RuleRegistry](../Carthago/Engine/Rules/Catalog/RuleRegistry.cs) explicitly registers `R547` with stable `Rules.R547.Enabled` configuration. No separate engine, direct alert or new protocol inspector.
- Existing [bounded window](../Carthago/Engine/Rules/Expansion/NetworkBatch226230Evidence.cs) caps 4,096 source buckets and 512 packet IDs/targets per bucket; rejects duplicate IDs, out-of-order timestamps and stale observations. An independently bounded 4,096-entry cooldown map fails closed on saturation. It returns `NoMatch`, `SuppressedMatch` or ordinary `Match`.
- Public IPv4 classification excludes RFC1918, documentation, benchmark, multicast, link-local and reserved examples. Destination must be RFC1918 IPv4. Both ports must be 47808 and payload length 8–1476; malformed and contradictory telemetry is excluded.
- Evidence includes only `bacnet.operation=whois`, fixed condition labels, aggregate count/window and UDP destination port. No raw `Info`, BACnet device IDs, credentials, payload or untrusted header strings are persisted. Endpoints remain unauthenticated packet header IPs. No R102/R118/R163 floors, policy modes, journal, holdout or shared capture contract changed.

## Authored scenarios, not executed

[Advanced xUnit source](../Carthago.Tests/R547AdvancedAccuracyBatchTests.cs): **19 xUnit methods / 25 concrete invocations** (17 `Fact` methods, two `Theory` methods with 3 and 5 rows). Source-only scenario classes:

1. Real-shaped Who-Is wire classification and malformed/truncated BVLC length rejection; three-target positive with severity/count/window assertions.
2. I-Am, generic BACnet, internal commissioning, one-target repeat, nonpublic source, multicast/public destination, wrong transport and port negatives.
3. Port/`Info` spoofing, missing length, IPv6, contradictory TLS/HTTP/DNS evidence fail-closed.
4. Duplicate packet IDs, out-of-order timestamps, source isolation, window expiry, cooldown suppression and concurrent observations.
5. Redaction of credentials/device markers; explicit registry uniqueness, Candidate/Shadow mode and 80% confidence floor.

**Tests authored:** 19 methods, 25 invocations. **Tests executed:** 0. **Builds/restores, replays, holdouts, CI, Actions, runners, scans and captures:** 0. No compilation, precision/recall/F1, runtime outcome or successful exploit claim. Execution remains prohibited until the owner says **“now it's test time.”**

## Publication scope and next dependency

Only five detection-owned paths are included: the R547 class, R547 tests, explicit registry registration, this batch report, and [protocol-informed detection backlog](rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md). Historical protocol research, UI, PacketHandler, TrafficRecord, capture, security pipelines and frozen holdouts are unchanged.

**Next GA:** Recheck the live rule registry for **R548** and choose another **distinct, actually observable** predicate. Do not repeat P0001–P0500 research GAs. If an owner-approved trusted BMS asset/gateway inventory later becomes available, evaluate whether it can safely tighten this Shadow candidate; do not fabricate authorization from IP addresses.
