# CARTHAGO — GA R549: Cross-subnet default Basic credential fanout

**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**.  
**Branch:** `feature/carthago-reliability-hardening` only.  
**Source base HEAD (2026-11-02):** `f5f4b706a61d681533b05bc87536f8dee84ac430` (GA UI-72 documentation, disjoint from detection-owned paths).  
**Source/test commit (unpublished until the final atomic update):** `310d2f53ba6986b8e7558265ed52ea8e9c90c34e`.  
**Source blob:** `abdb5b1c6c4f3e63329db200c6295b5ab2f4a88e`; **test blob:** `0cf3195810fc08026bc03872829bc8e6ad71548f`. The final publication commit contains this report and the updated backlog; the exact publication SHA is the verified branch HEAD after the atomic update.  
**Research crosswalk:** [completed P0001 HTTP/2, P0002 HTTP/3 and P0003 WebSocket research](protocols/PROTOCOL_EXPANSION_PROGRESS.md) provides the **edge visibility and encryption-boundary context only**. The original 500-row inventory has **no standalone HTTP/1.1 entry**. R549 uses Carthago's *existing cleartext HTTP/1.x producer* and does **not** claim to decode HTTP/2, HTTP/3 or WebSocket, nor invent a P ID.

## Detection and deduplication decision

| Rule | Producer and novel predicate | Policy / reachability | Existing overlap / realistic benign activity |
| --- | --- | --- | --- |
| **R549 — Cross-Subnet Default Basic Credential Fanout** | `PacketHandler.ParseFrame` → bounded `HttpLight.TryParseHttp` → `TrafficRecord.HttpBasicDefaultCredentialObserved` (internal-set capture flag, one complete Authorization header). One RFC1918 IPv4 source sends **three** HTTP/1.x GET/POST requests with a recognized known-default Basic value to anchored admin routes in **three distinct RFC1918 /24 destination networks** (none its own) in 5m. Source/destination/ports, TCP/HTTP, bounded L4 length, redacted headers and unique packet IDs must agree. | **CONDITIONAL** on seeing early **cleartext** TCP HTTP headers in the existing capture path; **High / Candidate / Shadow / 88% floor / 3 distinct /24s / 5m / 10m cooldown**. No shared sensor changes. | R118 detects a *single* default-credential attempt to a likely IoT device; R133 detects generic cleartext Basic; R237 detects IoT admin route context; R130/R169 require web login failure or identity context. R549 correlates **parser-confirmed known-default credentials across multiple private subnets** without inventing server responses. Legitimate cross-VLAN provisioning, factory resets, inventory or authorized scanners can match. |

## Evidence, trust and failure boundaries

- The capture-path flag is populated only after a complete HTTP header block and exactly one Authorization field; parser inspection of a known default Basic value occurs **before redaction**. An imported JSON record cannot set this internal-set flag. The rule also requires a redacted Authorization header, HTTP/1.x method, an anchored admin route, TCP cleartext service port, coherent IPv4 addresses and a 40–4096 byte L4 payload.
- The producer is **not** a complete TCP reassembler. Split/late headers, TLS-wrapped HTTP, HTTP/2 and HTTP/3 ciphertext, nonstandard ports, missing privileges and capture topology limit coverage. Neither the flag nor the correlation authenticates the operator or establishes password acceptance, login success, device identity, lateral movement or compromise.
- Only fixed boolean/condition strings and counts are added to structured evidence; no raw Authorization, Base64 credentials, URI query, request headers or `Info` are copied. Existing event metadata still carries source/destination and a bounded, checked HTTP Host; normal journal-first `DetectionEvent` lifecycle applies.
- Reuses the existing `NetworkBatch226230Evidence.Window` (4096 source buckets, 512 IDs and target prefixes per bucket, monotonic timestamps, duplicate ID rejection, fail-closed saturation) and a 4096-key bounded cooldown dictionary. Source-only review found no new direct UI alerts, external sinks, packet capture bridge, profile mutation or independent engine.
- Proposed `ApprovedProvisioningHosts` and `ApprovedMaintenanceWindows` are tuning guidance, **not newly implemented allowlists**. Shadow is required until owner-approved asset role, maintenance baseline, negative traffic and independent precision evidence exist.

## Dated primary threat research

- [MITRE ATT&CK T1078.001 — Default Accounts](https://attack.mitre.org/techniques/T1078/001/), **modified 2026-05-12**, documents abuse of preset credentials on network devices and applications. [DET0465 — Detection of Default Account Abuse Across Platforms](https://attack.mitre.org/detectionstrategies/DET0465/), **modified 2026-05-12**, emphasizes device authentication logs, user context and maintenance windows; this rule has *packet-attempt evidence only*, not authenticated outcomes.
- [CISA, Secure by Demand: OT Product Selection](https://www.cisa.gov/sites/default/files/2025-01/joint-guide-secure-by-demand-priority-considerations-for-ot-owners-and-operators-508c.pdf), **2025-01-13**, prioritizes eliminating default passwords and recognizes legitimate OT deployment concerns.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) live retrieval on **2026-11-02** returned HTTP 403. No R549-specific confirmed exploitation, CVE or IOC is asserted. [FIRST EPSS](https://www.first.org/epss/) predicts 30-day CVE exploitation likelihood; there is **no applicable CVE-specific score** for this generic request sequence. Classification: **UNVERIFIED**, not a zero-day or exploit detector.

## Authored scenarios — NOT EXECUTED

[R549AdvancedAccuracyBatchTests.cs](../Carthago.Tests/R549AdvancedAccuracyBatchTests.cs) contains **20 xUnit methods / 26 concrete invocations** (17 Facts, 3 Theories with 2, 3 and 4 InlineData rows).

1. Valid complete known-default Basic request, redaction, real raw IPv4/TCP `PacketHandler.ParseFrame` producer path, and three-subnet positive correlation with High severity/count/window.
2. Non-default/malformed Basic, duplicate Authorization, incomplete headers, ordinary paths, one-subnet and source-local-subnet negatives.
3. Public/non-RFC1918 endpoints, Info-only spoofing, imported JSON flag forgery, TLS/QUIC/DNS/UDP contradictions, invalid ports/length/Host fail closed.
4. Duplicate packet ID, out-of-order timestamp, source isolation, expired window, cooldown suppression and concurrent arrivals.
5. Secret-free structured and legacy event evidence, unique registry ID/config, Candidate/Shadow mode and 88% confidence floor.

**Tests executed: 0; builds/restores: 0; replays/holdouts/CI/Actions/runners/benchmarks/scans/captures: 0.** No compilation, accuracy, field precision, recall, F1, CVE exploitation or production delivery result is claimed. Owner approval `now it's test time` is still required.

## Changed paths, concurrency and next GA

- [R549 rule](../Carthago/Engine/Rules/Expansion/R549_CrossSubnetDefaultBasicCredentialFanoutRule.cs)
- [R549 authored tests](../Carthago.Tests/R549AdvancedAccuracyBatchTests.cs)
- [RuleRegistry](../Carthago/Engine/Rules/Catalog/RuleRegistry.cs) — one explicit `R549` registration, `Rules.R549.Enabled`.
- This report: `docs/RULE_BATCH_549-549.md`.
- [Detection-owned threat backlog](rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md).

The paused overlapping detection automations remain disabled. The independent UI automation owns disjoint paths and is unchanged. No historical protocol GA, UI resource, shared PacketHandler/TrafficRecord, journal, security control, workflow or frozen holdout is edited. R102/R118/R163 confidence floors **80%/86%/84%** and frozen R102 V1 **4/6** remain unchanged; V2 remains pending independent provenance.

**Next proposed GA: R550**, only after a fresh live registry and source/producer audit. Prioritize genuinely new reachable predicates; do not create R550 solely to increase the count.
