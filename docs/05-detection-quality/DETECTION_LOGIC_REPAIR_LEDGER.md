# Detection-logic repair — source implementation ledger

**Scope:** Core detection rules on `feature/carthago-reliability-hardening`.
**Status:** IN PROGRESS — source only; no Windows/Linux build, xUnit, replay, live capture, or production validation inferred.
**Initialized:** 2026-11-17 from source audit at `ff69e39129ded0dd02e9773f26fc9d457e2f72d9`.
**Owner request:** Fix detection predicates and missing trustworthy evidence producers; do not count rule qualification tests as the implementation backlog.

## Fixed implementation queue

187 source-confirmed incomplete/blocked IDs (not 983). Explicit ordered queue:

- `R270`, `R273`, `R274`
- `R276–R285` (10 IDs)
- `R287–R350` (64 IDs)
- `R431–R540` (110 IDs)

Rules `R271`, `R272`, `R275` and `R286` are **not** in this queue. An ID entering a scheduled batch is **reviewed/processed**, not automatically **implemented**. Keep an independent carryover list of producer blockers; after the cursor reaches R540 revisit carried-over IDs and previously unreviewed source gaps. Never report `NoMatch` as an implemented detector or decrement the outstanding count solely for documentation, tests, or a reason-code change.

**Repair-complete (per ID)** requires: trustworthy observable source/provenance (or independently verified appropriately scoped capture evidence), a meaningful reachable rule predicate, bounded correlation/reset/duplicate handling where relevant, privacy-appropriate evidence and no fabricated security outcomes, and engine-path connectivity. Authenticated external audit **requires a deployed, authorized source** and cannot be inferred from packet labels. Unit-test authoring and execution are tracked separately from this engineering gate. Preserve existing confidence floors and alert/shadow decisions.

## Batch 01 — R270, R273, R274, R276–R282

**State:** STARTED 2026-11-17. Ten IDs inspected and classified; none yet counted functionally repaired. Only the concrete R270 diagnostics code and regression guard below were changed during this first pass; do not mark the other nine as implemented.

| Rule | Required functional evidence/production integration | Current source state | Work/status |
| --- | --- | --- | --- |
| R270 Detection Pipeline Tampering | Trusted engine control-plane mutation event, actor/authorization/maintenance context and verified resulting state | Unconditional `NoMatch` | **PARTIAL:** changed generic `NO_MATCH` into typed `TRUSTED_PIPELINE_CONTROL_PLANE_AUDIT_UNAVAILABLE`; still producer-blocked |
| R273 Impossible Travel Authentication | Authenticated, same-account successful IdP sign-ins at distinct UTC times with independently sourced geolocation and VPN context | Unconditional `NoMatch` | PRODUCER BLOCKED — Entra/OIDC sign-in ingestion and account/session correlation missing |
| R274 MFA Push Fatigue | Authenticated per-account distinct MFA prompt IDs, delivery + decision/outcome, bounded time window | Unconditional `NoMatch` | PRODUCER BLOCKED — MFA provider audit source missing |
| R276 OAuth Consent Grant Abuse | Authenticated tenant/app/actor/scope **grant outcome**, not request text or callback URLs | Unconditional `NoMatch` | PRODUCER BLOCKED — provider grant audit source missing |
| R277 Legacy Protocol Authentication Attempt | Capture-origin decoded POP/IMAP/SMTP AUTH command with exchange/flow binding or trusted server authentication audit | Unconditional `NoMatch` | PRODUCER BLOCKED — native AUTH parser/audit producer not connected |
| R278 Password Spray Low and Slow | Trusted failed login outcomes, stable source/account IDs, distinct account/window correlation and normal administrative exclusions | Unconditional `NoMatch` | PRODUCER BLOCKED — account-linked sign-in failure source missing |
| R279 Credential Stuffing Rotating User Agent | Authenticated failed-login IDs and account + UA digests, source/destination/window, privacy-safe distinct counts | Unconditional `NoMatch`; isolated `CredentialStuffingAuditWindow` exists | PRODUCER BLOCKED — validate and bind signed audit intake to rule-engine context without trusting `TrafficRecord.Info` |
| R280 Session Token Replay Across Geographies | Accepted authenticated session events, protected same-session token digests, corroborated country/IP provenance and replay-safe window | Unconditional `NoMatch`; isolated `SessionReuseAuditWindow` exists | PRODUCER BLOCKED — signed intake cannot authorize detection until provider source, integrity and engine binding exist |
| R281 Suspicious Admin Console Login To Cloud | Authenticated privileged sign-in outcome, account, tenant and administrative endpoint evidence | Unconditional `NoMatch` | PRODUCER BLOCKED — cloud administrative audit source missing |
| R282 VPN Login Followed By Internal Scan | Authenticated VPN session/source identity joined to independently observed internal scan series within bounded window | Unconditional `NoMatch` | PRODUCER BLOCKED — VPN session audit and source/identity join missing |

**Source changes published this batch:**
- `Carthago/Engine/Rules/Expansion/R270_DetectionPipelineTamperingIndicatorRule.cs`: a precise `InsufficientEvidence` reason code for absent trusted control-plane producer; commit `f8acf50efe4c2792b22e5b05b429b5314b2c6f8a`.
- `Carthago.Tests/R270AdvancedAccuracyBatchTests.cs`: authored assertion for the typed gap reason; commit `b17c0b973ff7d59a2d57110c4a1f5e0f10ee7686` (test **not executed**).

**Results:** 10/187 IDs reviewed as the first batch. **0/187 functional repairs proven** by these changes. R270's gap is more diagnosable but remains fail-closed; nine additional IDs are still producer-blocked. Do not treat this as test qualification or operational promotion.

## Next scheduled batch — Batch 02

**Next ten not-yet-processed IDs:** `R283`, `R284`, `R285`, `R287`, `R288`, `R289`, `R290`, `R291`, `R292`, `R293`.

Each hourly run:
1. Read current branch HEAD and this ledger; avoid editing files currently being changed by other automated streams.
2. Process up to the next ten source IDs in queue order; inspect their actual rule implementation, required producer and engine selectability.
3. Implement **real** source/producer/predicate functionality where possible; write narrowly scoped source test guards and preserve safety contracts. If a trusted audit/physical producer is missing, document its exact integration blocker and continue instead of introducing speculative alerts.
4. Mark each ID **REPAIR COMPLETE** only for real functionality, not merely examination/reason-code updates. Maintain a carryover list for blocked IDs and revisit it after progressing through all 187.
5. Append an exact changed-file/commit record, tests authored versus executed and next cursor. Do not invent run results.

## Batch 02 — R283, R284, R285, R287–R293 (2026-11-17)

**Source snapshot:** `ea593727513faf71ce112999b29b2c0a98c712e8`. Ten IDs inspected, **zero functionally repaired**. All detector EvaluatePrecision methods remain unconditional NoMatch. No runtime promotion, alert, Windows test or capture performed.

| ID | Required producer and blocker | State |
| --- | --- | --- |
| R283 | Authenticated SAML validation audit plus decoded RelayState and IdP rejection outcome; HTTP parameter alone spoofable | PRODUCER-BLOCKED |
| R284 | OIDC code issuance, trusted recipient attribution, outbound leakage proof and intended callback allowlist; URL text insufficient | PRODUCER-BLOCKED |
| R285 | Signed SCIM principal/API response and returned object counts with authorized administrative baseline | PRODUCER-BLOCKED |
| R287 | KDC 4771 or equivalent authenticated preauth-failure events, source/account/realm correlation and dedup | PRODUCER-BLOCKED |
| R288 | Complete NTLMSSP type-3 wire capture and server-side negotiation/auth outcome; new strict legacy-shape inspector is NOT version or success proof | IN-PROGRESS, PRODUCER-BLOCKED |
| R289 | Verified Access-Reject request/response window exists but no engine capture binding or trusted account/NAS outcome | PRODUCER-BLOCKED |
| R290 | Validated Citrix exploit-specific byte signature plus target product/version or authenticated appliance audit | PRODUCER-BLOCKED |
| R291 | Validated Fortinet exploit-specific byte signature plus target version or authenticated appliance audit | PRODUCER-BLOCKED |
| R292 | Validated GlobalProtect exploit-specific byte signature plus affected PAN-OS target context or appliance audit | PRODUCER-BLOCKED |
| R293 | Authenticated Kubernetes API-server audit decision with anonymous principal and target identity, not HTTP path | PRODUCER-BLOCKED |

**Concrete source increment:** `Carthago/Services/ProtocolIntelligence/NtlmV1AuthenticateInspector.cs` strict complete-message NTLMSSP type-3 legacy response-shape inspector; rejects truncated/overlapping buffers, extended-session security, NTLM2-session LM-zero tail, empty responses and untrusted partial messages. Does not expose response bytes, infer successful authentication, or feed R288. `Carthago.Tests/ProtocolIntelligence/NtlmV1AuthenticateInspectorTests.cs` six regression tests **AUTHORED, UNEXECUTED**. This is a parser prerequisite, not a positive detector. Exact commit is the atomic publication containing this ledger (inspect git log); no functional rule counted complete.

**Cursor:** Batch 03 = R294,R295,R296,R297,R298,R299,R300,R301,R302,R303. Carryover remains all 20 Batch 01/02 IDs; revisit after ordered queue. Preserve R102/R118/R163 precision floors and frozen holdouts.
