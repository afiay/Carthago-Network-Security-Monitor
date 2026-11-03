# CARTHAGO — GA R561: repeated Redis CONFIG SET error replies across connections

**Branch:** `feature/carthago-reliability-hardening` · **Audit HEAD:** `57e7d5aef88bfde97f1d82b63b399b1e7090b082` (2026-11-02).  
**Status:** **SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.** No restore, build, xUnit, replay, holdout, CI, runner, capture, scan or benchmark was executed. Publication is not production promotion.

## Threat predicate and research reconciliation

| Rule / historical input | Exact observable predicate | Policy / overlap |
| --- | --- | --- |
| **R561 — Repeated Rejected Redis CONFIG SET Requests**; **P0024 RESP** (research row, not a new decoder) | One **public IPv4 client** receives **three PacketHandler-correlated RESP2 error replies** from one **RFC1918 Redis server**, on **three distinct client TCP ephemeral ports**, within **five minutes**. Every reply must have the **internal-set `RedisRespConfigSetReplyErrorObserved` flag**, coherent IPv4/TCP/6379 reverse direction, `redis.resp2` classification, unique packet ID and bounded length. | **Medium / Candidate / Shadow / 86% minimum confidence / threshold 3 / window 300 s / cooldown 600 s**. **R437** identifies CONFIG SET but deliberately remains fail-closed for unauthorized configuration changes; **R438** is Redis replication, not rejected CONFIG SET attempts. R561 is a distinct repeated *failed-attempt* behavioral predicate, **not** an R437 authorization or success promotion. |

The source of the new flag is the existing `PacketHandler` RESP2 request/reply correlator introduced in the independent R437 integration stream: first complete CONFIG SET request after SYN, eligible SYN-ACK, contiguous first client payload, bounded first server RESP2 error reply within 30 seconds. It records a Boolean, not the parameter/value or error text. The new rule **does not** edit that producer, the existing R437 rule, shared telemetry or journal code. This is **CONDITIONAL** on that recent unverified producer and full bidirectional plaintext capture.

A Redis RESP2 error is not authenticated evidence of server identity, unauthorized client identity, an access-control violation, persistent configuration state or a CVE exploit. The command can fail for ordinary administrative mistakes. A configured `Approved.AdminHosts` entry suppresses that client; an empty allowlist is **not** interpreted as evidence of unauthorized status. NAT, Redis proxies, error-message spoofing, packet loss, split frames, TLS, RESP3, pipelining and late capture can affect attribution or hide events. Keep Shadow until exact-SHA compilation, producer/replay validation and environment approvals.

## Implementation, state and privacy

- `Carthago/Engine/Rules/Expansion/R561_RedisConfigSetRejectedReplyBurstRule.cs` — one ordinary `DatabaseServiceExposurePrecisionDetectionRuleBase` rule using `CreateEvidenceDrivenProfile`, `CreateDetectionEvent`, and the existing engine lifecycle. No direct UI, incident or journal writes.
- `Carthago/Engine/Rules/Catalog/RuleRegistry.cs` — exactly one new R561 registration after R560; no existing rule IDs or configurations changed.
- `Carthago.Tests/R561AdvancedAccuracyBatchTests.cs` — **16 xUnit methods, 18 concrete invocations authored; 0 executed**.
- `docs/RULE_BATCH_561-561.md` and `docs/rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md` — detection-owned documentation only.

Per-rule state is synchronized and bounded to **1,024 client/server pairs**, **32 distinct client ports** and **96 unique packet IDs per pair**; observations expire after five minutes, stale pair eviction after ten minutes, and saturation fails closed. Duplicate IDs and out-of-order timestamps cannot advance the count. Once the threshold is met, repeated matches within ten minutes return `SuppressedMatch`. The emitted event contains only fixed operation/reply labels, aggregate count and window; no RESP command arguments, Redis error text, credentials or raw `Info`.

## Authored scenario matrix — unexecuted

| Family | Methods / invocations | Intended assertions |
| --- | --- | --- |
| Producer and positive threshold | 3 / 3 | Real raw TCP SYN/SYN-ACK/request/reply classification, three connections produce one R561 candidate, one/two remain nonmatches |
| Benign and missing evidence | 3 / 3 | +OK and PING negatives; missing SYN-ACK and malformed error; separate clients and servers |
| State and ordering | 3 / 3 | Repeated ports/IDs, out-of-order and expired observations, cooldown suppression |
| Forgery and address validation | 2 / 4 | Contradictory metadata/Info-only; three parameterized nonpublic client addresses |
| Privacy, registry and concurrency | 5 / 5 | Redaction, Shadow/Candidate/86%/unique registry, explicit approved-admin policy, concurrent duplicate reply, JSON-import flag forgery |

**Totals: 16 xUnit methods / 18 concrete invocations; 0 executed.** These are source assertions, not passing tests. The new rule inherits existing config/precision validation and journal-first `DetectionEvent` lifecycle. No field precision, recall, exploit detection, production identity, F1, build or pass rate is asserted.

## Research and next GA

- [Redis CONFIG SET command](https://redis.io/docs/latest/commands/config-set/) — runtime configuration command; RESP2 returns `OK` or an error, but neither authenticates a packet capture.
- [Redis RESP protocol](https://redis.io/docs/latest/reference/protocol-spec/) — RESP2 error frames and request/reply framing, including pipelining limitations.
- [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/) — public-facing service exploitation context, last modified **2026-05-12**. R561 does **not** establish exploitation.
- [FIRST EPSS](https://www.first.org/epss/) and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — no R561-specific CVE/score or confirmed exploitation claim. EPSS is probability, not evidence of an observed exploit.

**Next proposed cursor: R562**, subject to live ID/producer/overlap audit. Prioritize a truly independent predicate, not another address-direction mirror. Higher-fidelity R437 configuration-change and R485 BACnet WriteProperty outcomes remain **BLOCKED** pending authenticated server/device/asset evidence and owner-approved shared contracts. Frozen V1, pending V2, R102/R118/R163 confidence floors, UI stream, historical P inventory and all existing rule modes remain unchanged.
