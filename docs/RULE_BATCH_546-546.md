# GA R546 — outbound NTP mode-7 monlist target fanout

**Branch:** feature/carthago-reliability-hardening  
**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**  
**Source base HEAD:** `881d67c7a1d17a1a3cecda3917923a86aad88bc8` (2026-11-01).  
**Publication:** the atomic commit containing this report; exact resulting SHA is reported after publication (a commit cannot contain its own hash).  
**Scope:** One evidence-reachable, distinct detection rule; no ten-rule quota, new protocol inspector, shared sensor edit, or P0501. **Next proposed R ID:** R547, contingent on live registry review.

## Evidence and rule decision

| Rule | Research mapping | Typed producer and novel positive predicate | Default policy | Limitation |
| --- | --- | --- | --- | --- |
| R546 Outbound NTP Mode-7 Monlist Target Fanout | **P0051 NTP** (partial live wire classifier); distinct from R242 | `PacketHandler` calls `OtProtocolLight.TryIdentifyUdp`, which validates a bounded mode-7 MON_GETLIST_1 request and sets `TrafficRecord.ApplicationProtocol=ntp.mode7.monlist`. Three **distinct globally routable IPv4 destination addresses**, each on UDP/123, from one RFC1918 IPv4 source in **five minutes**, with valid UDP/IPv4 and 8–512 byte L4 payload metadata. | Candidate; **Medium / Shadow**, enabled but non-paging; minimum confidence **80%**; threshold **3 distinct destinations**; 5m window; 10m cooldown; source-keyed bounded state. | A request is not a response, successful amplification, an exploitable NTP implementation, authenticated source, or evidence of current CVE exploitation. No IPv6, fragmented, encrypted, unobserved or non-IP traffic. |

**Overlap resolved:** [R242](../Carthago/Engine/Rules/Expansion/R242_NtpAmplificationCandidateRule.cs) counts **five mode-7 monlist requests to the same source+destination pair within two minutes**; it does not count unique destinations. R546 requires a single RFC1918 source to send probes to **three different public IPs on UDP/123**, even when each destination receives only one request. R001/R017 generic scans lack this parsed NTP operation and exact target-fanout predicate. No other existing R ID is renumbered.

**Risk and attribution:** The [NTP Project security notice](https://www.ntp.org/support/securitynotice/ntpbug1532/) (resolved 2010; notice updated 2026-09-03) documents CVE-2013-5211 and historical exploitation of unrestricted monlist amplification in December 2013. [CERT/CC VU#348126](https://kb.cert.org/vuls/id/348126) (released 2014-01-10; revised 2014-08-26) explains reflected-DoS mechanics. This rule detects **request fanout only**; no assertion that any destination runs NTP or is vulnerable or that exploitation occurred. The behavior aligns with [MITRE ATT&CK T1595 Active Scanning](https://attack.mitre.org/techniques/T1595/) (modified 2025-10-24). No current CISA KEV addition, 2026 exploitation, or EPSS score is asserted; [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [FIRST EPSS](https://www.first.org/epss/) are risk-research inputs, not proof.

**Benign lookalikes:** approved vulnerability scanning, network audits, NTP health checks and diagnostics; NAT/VPN paths may change attribution. UDP source addresses can be spoofed. Do not promote from Shadow without authenticated host identity, asset ownership, approved-scanner inventory and negative-capture evidence.

## Implementation, source contracts and invariants

- [R546 source](../Carthago/Engine/Rules/Expansion/R546_NtpMonlistOutboundTargetFanoutRule.cs) is a normal `IotOtAdvancedPrecisionDetectionRuleBase` rule; [registry](../Carthago/Engine/Rules/Catalog/RuleRegistry.cs) explicitly registers R546. Descriptor and config use `Rules.R546.Enabled`; no public schema migration.
- Existing [packet producer](../Carthago/Services/PacketHandler.cs) → [bounded NTP classifier](../Carthago/Services/OtProtocolLight.cs) → [typed record](../Carthago/Models/TrafficRecord.cs) → [operation guard](../Carthago/Engine/Rules/Expansion/NetworkBatch241245Evidence.cs) is reused unchanged. No isolated parser, synthetic sensor, server log or response is invented.
- [Bounded observation helper](../Carthago/Engine/Rules/Expansion/NetworkBatch226230Evidence.cs) maintains at most 4,096 source buckets, 512 packet IDs/targets per bucket, rejects duplicates and out-of-order timestamps, and expires window entries. A separate 4,096-entry cooldown map is bounded and fails closed when full.
- No `Info`, packet body, NTP peer-list, credential, token, user-agent or host-derived string is retained in evidence. Only parsed operation label, fixed condition codes, destination port and aggregate count/window are included. Source/destination IPs remain the existing DetectionEvent endpoints; they are not authenticated identities.
- The rule returns `NoMatch`, `SuppressedMatch` or an ordinary `DetectionEvent` through the engine; no direct journal/UI/incident/sink calls. Existing JSONL-first persistence, mode enforcement, precision floors and frozen holdouts remain untouched.

## Authored tests and validation boundary

[R546 advanced tests](../Carthago.Tests/R546AdvancedAccuracyBatchTests.cs): **18 xUnit methods / 23 concrete invocations** (16 `Fact` and 2 `Theory` methods with 4 and 3 rows). Scenario classes include parsed wire-positive and three-target match; legitimate normal synchronization, repeated one-target and nonpublic destination negatives; truncated, response, spoofed `Info`, transport/length contradictions; duplicate IDs, out-of-order, per-source isolation, expiry and cooldown; secret redaction and registry/Shadow policy.

**Tests authored:** 18 methods / 23 invocations. **Tests executed:** 0. **Builds, restore, replay, holdout, CI, Actions, runners and captures:** 0. No precision/recall/F1, alert delivery or compile-success claim. Windows execution and journal-first replay await the owner's exact **“now it's test time”** authorization.

## Outstanding dependencies and next GA

1. Validate source compilation, xUnit, NTP producer reachability, source-attribution false positives and journal-first Shadow behavior only when testing is authorized. Existing R242 must retain its own policy and semantics.
2. Owner-approved integration proposal would be required for authenticated endpoint/asset evidence or approved-scanner telemetry; neither is fabricated by this GA.
3. Continue the [deduplicated threat backlog](rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md), prioritizing **new** observable predicates. Next possible ID **R547**, re-evaluated from live HEAD; no automatic additional inspector or historical P-GA replay.

## External references

- NTP Project, NTP BUG 1532, updated 2026-09-03: https://www.ntp.org/support/securitynotice/ntpbug1532/
- CERT/CC VU#348126, released 2014-01-10 and revised 2014-08-26: https://kb.cert.org/vuls/id/348126
- MITRE ATT&CK T1595, modified 2025-10-24: https://attack.mitre.org/techniques/T1595/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FIRST EPSS: https://www.first.org/epss/
