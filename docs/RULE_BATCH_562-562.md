# GA R562 — Redis CONFIG SET error-to-OK reply transition

**Branch:** feature/carthago-reliability-hardening · **Audit base HEAD:** 54a084bda5805ce1170a2570ba31852377f8767b (2026-11-02).  
**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**. No restore, build, xUnit, benchmark, replay, holdout, CI, runner, packet scan or capture executed. Publication is not production promotion. The publication SHA is the resulting protected branch update and cannot be embedded in its own commit.

## Research, novelty and exact predicate

| ID and P research | Observable rule-owned predicate | Overlap / policy |
| --- | --- | --- |
| **R562 — Redis CONFIG SET Error-to-OK Reply Transition**; historical **P0024 RESP** (research row, not a new protocol) | One globally routable public IPv4 client receives **two PacketHandler-correlated RESP2 error replies** from one RFC1918 Redis server, on two distinct ephemeral client TCP ports, **then** a correlated **+OK-shaped** reply on a third port, within **five minutes**. The +OK-shaped reply must follow the latest error within **120 seconds**. Each reply is anchored to the first complete CONFIG SET request on its own SYN/SYN-ACK-observed TCP connection. | **Medium / Candidate / Shadow / 88% confidence floor / 3 distinct connections / 300 s window / 120 s follow-up / 600 s cooldown**. **R561** detects three error replies without requiring a subsequent +OK shape; **R437** deliberately remains fail-closed even for an unapproved client's +OK because no authenticated server/audit outcome exists. R562 is an ordered *reply-shape transition* candidate, **not** a bypass of R437 authorization or an exploit detector. |

The existing producer is PacketHandler's bounded, SYN-anchored RESP2 request/reply correlation. Only internal-set TrafficRecord.RedisRespConfigSetReplyErrorObserved and RedisRespConfigSetReplyOkObserved, strict redis.resp2 application classification, coherent reverse TCP/6379, IPv4 endpoints, bounded payload length and packet IDs are eligible. Imported JSON cannot assert the internal-set flags. A +OK-shaped wire reply is **not** proof of authenticated Redis identity, a durable configuration change, unauthorized access or a specific CVE. TLS, RESP3, pipelined commands, fragmented/reordered TCP, capture starting mid-flow, NAT and proxying may conceal or distort observations. Positive eligibility is **CONDITIONAL** on the recently integrated and still-unverified live producer and complete bidirectional plaintext capture.

Benign lookalikes include administrators correcting invalid configuration parameters, automation retrying transient errors and connection-pool churn. Configured Approved.AdminHosts clients are excluded. An absent allowlist is **not** evidence of unauthorized access. Production promotion additionally requires attested capture origin, server/asset identity, authorization policy and replay/false-positive assessment; R437's fail-closed outcome gate is unchanged.

## Implementation, privacy, state and journal-first lifecycle

- Carthago/Engine/Rules/Expansion/R562_RedisConfigSetErrorToOkTransitionRule.cs: ordinary DatabaseServiceExposurePrecisionDetectionRuleBase / RuleEvaluationResult / CreateDetectionEvent path; no direct UI, incident, sink or journal writes.
- Carthago/Engine/Rules/Catalog/RuleRegistry.cs: exactly one R562 registration after R561; no historical ID renumbering.
- Carthago.Tests/R562AdvancedAccuracyBatchTests.cs: **20 xUnit methods / 22 concrete invocations authored; 0 executed**.
- docs/RULE_BATCH_562-562.md and docs/rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md: detection-owned evidence and cursor.

State is synchronized and bounded to **1,024 client/server pairs**, **32 error ports** and **96 unique packet IDs per pair**. A duplicate ID, repeated error port, success on an error port or out-of-order timestamp cannot advance the predicate. Observations expire after five minutes; stale pairs are evicted on capacity pressure after ten minutes; saturation fails closed. A second eligible +OK during cooldown yields SuppressedMatch with no duplicate event. The emitted structured evidence contains fixed labels, counts and windows only; no CONFIG parameters, values, credentials, Redis error text or raw Info are copied. The ordinary RuleEngine retains mandatory journal-first downstream handling.

## Advanced xUnit scenario matrix — source-authored only

| Family | Methods / invocations | Intent |
| --- | --- | --- |
| Producer and positive/negative sequence | 5 / 5 | Real PacketHandler reply flags, two-errors-then-OK positive, errors-only, OK-before-errors, one-error negative |
| Distinctness and source isolation | 2 / 2 | Repeated client ports and same-port OK cannot count; client/server pairs isolated |
| Missing, malformed and stale evidence | 5 / 5 | Missing SYN-ACK, malformed RESP, unrelated PING, duplicate IDs, out-of-order, window expiry, late OK |
| Cooldown and spoof/transport negatives | 3 / 5 | Suppressed repeat, contradictory protocol/TLS/UDP/Info, three nonpublic client address cases |
| Privacy, policy, concurrency and import | 5 / 5 | Secret redaction, Candidate/Shadow/88%/registry, explicit admin policy, concurrent duplicate, JSON import forgery |
| **Total** | **20 / 22** | **0 executed; no pass, build, precision, recall, F1 or exploitation claim** |

## Research, advisories and blocked higher-fidelity outcomes

- Redis CONFIG SET official command reference (retrieved 2026-11-02): https://redis.io/docs/latest/commands/config-set/ — CONFIG SET changes runtime parameters; a RESP2 simple OK is the documented reply when the command was processed properly, otherwise an error. Packet capture cannot attest the server.
- Redis RESP protocol specification (retrieved 2026-11-02): https://redis.io/docs/latest/reference/protocol-spec/ — RESP2 simple strings and errors.
- MITRE ATT&CK T1190, last modified **2026-05-12**: https://attack.mitre.org/techniques/T1190/ — general exposed-service context only; no R562-specific exploitation established. MITRE DET0080 describes multi-signal server-side corroboration absent here: https://attack.mitre.org/detectionstrategies/DET0080/ .
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog ; FIRST EPSS: https://www.first.org/epss/ . No R562-specific exploited CVE or EPSS score is asserted. EPSS is a forecast, not observation of exploitation.

**BLOCKED:** A rule asserting unauthorized Redis configuration modification requires authenticated Redis audit, verified server identity and approved client/asset context, which this packet-only producer cannot supply. Do not weaken R437 or manufacture that outcome.

**Next proposed cursor R563** only after fresh live registry/producer/dedup review. Prioritize independent observable behaviors over more Redis or subnet-fanout variants. Frozen V1, pending V2, R102/R118/R163 confidence floors, historical P inventory, shared capture/record producers, UI automation and existing rule modes remain unchanged.
