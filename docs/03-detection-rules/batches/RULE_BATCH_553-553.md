# CARTHAGO — GA R553: Cross-Subnet SMB2 Write Request Fanout

**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED  
**Branch:** `feature/carthago-reliability-hardening`  
**Live source base SHA:** `63adc5f2eee48b8019f7ae5b713c6a4ee50f041c` (2026-11-02)  
**Source blob SHA:** `91e1a71ed68b92f24cd1ce0add5e13f07830bbcf`  
**Authored-test blob SHA:** `5ccb3c4ca236e67b47ec14a89ff02595fde5d29e`  
**Publication/source/test/documentation commit:** this document's containing commit; a Git commit cannot embed its own SHA.  
**Next proposed cursor:** R554, after fresh live registry and producer review.

## Rule matrix and historical research

| Rule | P inventory and deduplication | Observable predicate | Policy | Disposition |
| --- | --- | --- | --- | --- |
| **R553** Cross-Subnet SMB2 Write Request Fanout | **P0006 SMB** partial wire recognition; **P0113** is related named-pipe research but **not** detected. R076/R078 general SMB/lateral signals; R249 external SMB2 WRITE, R333/R334 enumeration | `PacketHandler` → `NetworkBatch246250Wire.Smb2Write` → `TrafficRecord.ApplicationProtocol == "smb2.write.request"`; one RFC1918 IPv4 source sends first-segment SMB2 WRITE request shapes on TCP/445 to **three distinct other RFC1918 /24 networks within five minutes**; unique packet IDs, bounded length, coherent TCP/IPv4, monotonic timestamps | High; Candidate; **Shadow**; minimum 88%; 3 distinct /24s; 5m window; 10m cooldown | **REGISTERED SOURCE CANDIDATE — UNVERIFIED** |

## Trusted producer and limitations

- Existing live packet entry point `Carthago/Services/PacketHandler.cs` sets `ApplicationProtocol` only when a bounded, captured client-to-server TCP segment matches `NetworkBatch246250Wire.Smb2Write`. It is a first-segment **request-shape** classifier, not a full SMB session decoder or a cryptographic origin attestation. `TrafficRecord.ApplicationProtocol` remains publicly settable; imported/synthetic records must not be treated as authenticated sensor evidence.
- Require TCP/445, client source port >=1024, IPv4, nonempty unique packet ID, `L4Len` 117–4096, packet length consistent with IPv4/TCP minimum headers, no contradictory DNS/HTTP/TLS/QUIC fields, and distinct remote private /24 networks. A port-only or raw `Info` claim cannot match.
- SMB 3 encryption, reassembled requests beyond the first segment, authenticated user/share identity, C$/ADMIN$ use, server acceptance, file names, payloads, process launches and endpoint outcomes are **NOT OBSERVABLE** from this predicate. SMB signing is not independently validated. No remote-execution or ransomware conclusion follows from a match.
- Authorized backup, software distribution, roaming profile, replication, IT maintenance, VPN and NAT environments can look identical. Shadow mode must remain until representative benign traffic and host/share audit corroboration are validated.
- State reuses `NetworkBatch226230Evidence.Window` (bounded 4096 source buckets, 512 IDs/targets per bucket, duplicate and out-of-order controls) and a bounded 4096-entry cooldown map. No raw `Info`, credentials, file/share paths, SMB payloads or sensitive strings are placed in event evidence.
- Standard `RuleRegistry`, `IdentityAccessPrecisionDetectionRuleBase`, `DetectionEvent` and journal-first RuleEngine lifecycle remain in control. No direct UI, alert sink, journal or shared capture edit.

## Changed files and authored scenarios

| Path | Change |
| --- | --- |
| [R553 rule](../../../Carthago/Engine/Rules/Expansion/R553_CrossSubnetSmb2WriteRequestFanoutRule.cs) | One ordinary, source-only registered rule |
| [R553 advanced tests](../../../Carthago.Tests/R553AdvancedAccuracyBatchTests.cs) | 20 xUnit methods; 18 Facts + 2 Theories with 9 InlineData cases = **27 concrete invocations** |
| [RuleRegistry](../../../Carthago/Engine/Rules/Catalog/RuleRegistry.cs) | Exactly one `R553` registration |
| [Detection backlog](../../rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md) | Evidence-backed R553 decision, rejected named-pipe claim, next cursor |
| This document | Threat provenance, boundaries, authored-vs-executed evidence |

Authored scenarios cover wire-positive SMB2 WRITE and CREATE/response/truncation negatives; three remote private /24 positive; nonprivate source/target and same-subnet negatives; Info spoofing, contradictory HTTP/DNS/TLS/QUIC, malformed length/ID; duplicate, out-of-order, per-source isolation, expiration, cooldown and concurrency; PacketHandler raw-frame producer; redaction and registry/Shadow/confidence invariants.

**Tests authored:** 20 methods / 27 concrete invocations. **Tests executed:** 0. **Builds executed:** 0. No replay, CI, holdout, benchmark, scan, runner or live capture. No compilation, test success, field precision, recall or operational readiness is claimed.

## Threat refresh and future evidence

- [MITRE ATT&CK T1021.002 — SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/), last modified **2026-05-12**, describes SMB-enabled lateral movement; R553 does **not** identify administrative shares.
- [MITRE DET0530 — multi-event SMB admin-share lateral movement](https://attack.mitre.org/detectionstrategies/DET0530/), last modified **2026-05-12**, requires authenticated logon, share and process evidence beyond this packet-only rule.
- [Microsoft SMB signing and encryption overview](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview) explains why encrypted SMB data cannot be passively parsed; [Microsoft Security event 5145](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145) is a possible *future* trusted share-access source, not present in R553.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) returned HTTP 403; no R553-specific exploited CVE was verified. [FIRST EPSS](https://www.first.org/epss/) estimates CVE exploitation likelihood, not the risk of this generic traffic pattern. **Threat classification: UNVERIFIED**; no zero-day or CVE signature claim.

## Outstanding GA

**Next proposed R554** only after a live uniqueness, sensor and overlap audit. SMB authenticated share/file-operation correlation requires an owner-approved host evidence contract and is **BLOCKED**, not a new rule. Preserve R102/R118/R163 floors (80/86/84%), frozen R102 V1 historical 4/6, V2 pending provenance, all modes and suppression. The historical P0001–P0500 protocol inventory and UI design stream remain unchanged.
