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


## Batch 03 — R294–R303 (2026-11-17)

**Source snapshot:** `634ee8125c38e4d6d7ce25e936aef3832352dd18`. All ten detector classes inspected; all ten EvaluatePrecision implementations still return unconditional NoMatch. **Zero functional repairs**. No runtime producer promotion or tests executed.

| ID | Status | Required trustworthy integration |
| --- | --- | --- |
| R294 | IN-PROGRESS, PRODUCER-BLOCKED | Authenticated Kubernetes API-server audit of secrets get/list, response decision, verified cluster identity and authorization context; isolated signed terminal-audit admission added, not engine-connected |
| R295 | IN-PROGRESS, PRODUCER-BLOCKED | API-server pods/exec audit plus upgraded session/command outcome; isolated signed audit request admission added, no session proof |
| R296 | IN-PROGRESS, PRODUCER-BLOCKED | API-server pods/portforward audit, principal and session outcome plus approved-session baseline; isolated signed audit request admission added |
| R297 | PRODUCER-BLOCKED | Service-account token-read provenance joined to independent external delivery, not a TokenRequest or bearer header |
| R298 | PRODUCER-BLOCKED | Host-verified Docker/containerd socket exposure inventory and endpoint identity, not port 2375 |
| R299 | PRODUCER-BLOCKED | Trusted Docker Engine container-create result, engine identity and principal, not HTTP POST |
| R300 | PRODUCER-BLOCKED | Verified etcd endpoint identity, trust boundary and authenticated client outcome |
| R301 | PRODUCER-BLOCKED | Verified Kubelet read-only listener and sensitive response outcome, not path/port |
| R302 | PRODUCER-BLOCKED | Verified Kubelet exec operation and session outcome, not path/POST |
| R303 | PRODUCER-BLOCKED | Trusted registry response inventory, distinct manifest results and authorized-client baseline |

**Source increment:** `Carthago/Services/ProtocolIntelligence/KubernetesAuditAdmission.cs` bounded (4096 identities), length-delimited HMAC-SHA256 isolated admission of Kubernetes audit terminal responses with typed secrets-read, pod-exec-request and port-forward-request operations. A shared key is NOT proof of exporter identity. No runtime ingestion or R294–R296 detector connectivity; never treat audit allow as proof of command success, exfiltration or unauthorized activity. `Carthago.Tests/ProtocolIntelligence/KubernetesAuditAdmissionTests.cs` regression source authored, **UNEXECUTED**: signed terminal observations, denied outcome, invalid signature, nonterminal, replay, stale and malformed events. This is a prerequisite only, **not a functional detector repair**. Commit SHA: see atomic git commit containing this ledger. Carryover: all 30 processed IDs unresolved. **Next cursor:** R304–R313.

## Batch 04 — R304–R313 (2026-11-17)

**Inspected source snapshot:** `ad36d6f540ee3e0bcc2aaf67726a8df29d3e5bc5`. All ten EvaluatePrecision methods remain unconditional NoMatch. No rule is functionally repaired. No Windows or native test executed.

| ID | State | Exact producer / missing runtime trust |
| --- | --- | --- |
| R304 | IN-PROGRESS, PRODUCER-BLOCKED | Registry-exporter authenticated response and explicit anonymous principal, distinct completed pulls; isolated signed operation admission added but no trusted exporter binding, runtime connection or burst predicate |
| R305 | IN-PROGRESS, PRODUCER-BLOCKED | Registry push result plus trusted workstation asset classification, approval baseline and signed exporter identity; isolated admission only |
| R306 | IN-PROGRESS, PRODUCER-BLOCKED | Docker build endpoint identity, complete context upload outcome and verified archive content/size; isolated admission does not prove content |
| R307 | PRODUCER-BLOCKED | Authenticated Kubernetes Dashboard endpoint identity, external exposure and actual response, not path/port |
| R308 | PRODUCER-BLOCKED | Verified Helm Tiller listener identity, boundary/authorization inventory and reachable response, not TCP/44134 |
| R309 | PRODUCER-BLOCKED | Verified Envoy admin listener inventory, ingress exposure and admin response, not URL |
| R310 | PRODUCER-BLOCKED | Sidecar inventory, effective mesh mTLS policy, route and independently confirmed bypass decision |
| R311 | PRODUCER-BLOCKED | Cloud workload identity plus trusted metadata service token response, not request alone |
| R312 | PRODUCER-BLOCKED | Versioned Kubernetes NetworkPolicy, CNI enforcement decision and authorized pod identities |
| R313 | PRODUCER-BLOCKED | Host-verified workstation role, DNS MX resolution attribution, external SMTP session and approved relay policy |

**Actual increment:** `Carthago/Services/ProtocolIntelligence/RegistryOperationAuditAdmission.cs` adds length-delimited signed registry-operation response admission with bounded 4096-event replay identities, monotonic timestamp checks and explicit accepted/denied/authenticated/unauthenticated distinctions. It is an isolated contract; shared HMAC key is not exporter identity, authorization, user role or proof of image transfer. `Carthago.Tests/ProtocolIntelligence/RegistryOperationAuditAdmissionTests.cs` adds four test methods (one theory with three data cases) for accepted operations, denied outcomes, signature tampering/invalid semantics and replay/expiry. **AUTHORED, UNEXECUTED.** No runtime/engine integration and no detector positives. Commit SHA: inspect atomic commit containing this ledger.

**Carryover:** all 40 processed IDs unresolved. **Next cursor:** R314,R315,R316,R317,R318,R319,R320,R321,R322,R323. Do not promote any rule until verified producer identity and detector positive/benign negative exist.


## Batch 05 — R314–R323 (2026-11-17)

**Source snapshot:** `6b192443f1a020ea72f4c5e5759546f03edd3ec5`. Inspected all ten detector EvaluatePrecision implementations; each remains unconditional NoMatch. **Zero functional repairs**, ten unresolved producer dependencies. No runtime or detector alert promotion.

| ID | State | Required trusted producer / integration |
| --- | --- | --- |
| R314 | PRODUCER-BLOCKED | Authenticated SMTP server failure responses and account-linked AUTH exchange, deduplicated burst |
| R315 | PRODUCER-BLOCKED | Authenticated IMAP server failure outcomes and stable distinct-account correlation |
| R316 | IN-PROGRESS, PRODUCER-BLOCKED | Complete plaintext POP3 command capture, independent TLS/STLS state and TCP stream reassembly; isolated redacted command inspector added, not wired to capture or rule engine |
| R317 | PRODUCER-BLOCKED | Verified Exchange Autodiscover endpoint and server-side distinct-account failure outcomes |
| R318 | PRODUCER-BLOCKED | Authenticated EWS operation/result and mailbox authorization context |
| R319 | PRODUCER-BLOCKED | Verified OWA/ECP endpoint identity, admin authorization and response |
| R320 | PRODUCER-BLOCKED | Authenticated Microsoft Graph mail-export audit and delivered result evidence |
| R321 | PRODUCER-BLOCKED | Authenticated Gmail message-read audit and result counts |
| R322 | PRODUCER-BLOCKED | Trusted mailbox-rule mutation audit with accepted outcome |
| R323 | PRODUCER-BLOCKED | Authenticated attachment retrieval results, delivered bytes and actor context |

**Actual source increment:** `Carthago/Services/ProtocolIntelligence/Pop3CleartextCommandInspector.cs` strictly inspects complete attested plaintext USER/PASS command lines, rejects partial/encrypted/malformed/overlong input, and emits only redacted command kind. `Carthago.Tests/ProtocolIntelligence/Pop3CleartextCommandInspectorTests.cs` contains four test methods with parameterized cases. **AUTHORED, UNEXECUTED**. Not a detector positive; independent TLS state and capture provenance remain absent. Commit SHA is the atomic commit containing this ledger; verify git log. **Carryover:** all 50 inspected IDs unresolved. **Next cursor:** R324–R333. No Windows tests, GitHub Actions or native capture.


## Batch 06 — R324–R333 (2026-11-17)
**Inspected snapshot:** `20c92f06bcccdacfd33a861909a83ce805855844`. All ten EvaluatePrecision methods return unconditional NoMatch; **zero functional detector repairs**, no runtime promotion. Statuses below remain unresolved and carry over. 
| ID | State | Required producer / blocker |
| --- | --- | --- |
| R324 | PRODUCER-BLOCKED | Authenticated web-content response and validated phishing-kit signature plus destination ownership; login URI insufficient |
| R325 | PRODUCER-BLOCKED | Authenticated sender identity and protected-domain policy plus actual delivery/contact outcome; DNS alone insufficient |
| R326 | PRODUCER-BLOCKED | Trusted resolver query attribution, mail-policy baseline and approved source context; policy lookups alone not recon |
| R327 | PRODUCER-BLOCKED | Authenticated Slack workspace app-install audit and successful install decision |
| R328 | PRODUCER-BLOCKED | Authenticated Teams connector delivery audit, accepted message and authorization context |
| R329 | PRODUCER-BLOCKED | Authenticated SharePoint completed file-download audit, distinct files, user and authorization baseline |
| R330 | PRODUCER-BLOCKED | Authenticated OneDrive anonymous share permissions, completed file access and distinct link identity |
| R331 | PRODUCER-BLOCKED | Authenticated calendar invitation delivery and validated malicious link verdict |
| R332 | PRODUCER-BLOCKED | Authenticated mail archive export result plus independently confirmed delivered bytes |
| R333 | IN-PROGRESS, PRODUCER-BLOCKED | Strict complete SMB2 SESSION_SETUP server-declared null response inspector added; still needs authenticated server identity, correlated IPC$ tree connect and enumeration outcome, stream reassembly and engine integration |

**Actual source increment:** `Carthago/Services/ProtocolIntelligence/Smb2NullSessionResponseInspector.cs` and `Carthago.Tests/ProtocolIntelligence/Smb2NullSessionResponseInspectorTests.cs` (five regression methods **AUTHORED, UNEXECUTED**). Complete SMB2 null session response parsing is not proof of enumeration, server authenticity or a detector-positive; R333 remains NoMatch. No Windows runner, native capture, GitHub Actions or CI changes. **Carryover:** all 60 inspected IDs unresolved. **Next cursor:** R334–R343. Commit SHA: inspect atomic git commit containing this ledger.


## Batch 07 — R334–R343 (2026-11-17)
**Inspected source HEAD:** dc03381141a6d223c7bf9e5f3dc4bf48ebaf983c. All ten EvaluatePrecision methods are unconditional NoMatch; none is functionally repaired. Source increment for R339: strict complete-frame SMB2 NEGOTIATE response inspector, reports server-advertised signing enabled/required flags without inferring unsigned session, authenticated server, or sensitive host. Regression source covers positive wire flags and negative malformed/partial/contradictory evidence. **Tests authored, not executed.** Inspector not yet wired into capture or RuleEngine. No Windows runner or Actions used.

| ID | Status | Missing trusted integration |
| --- | --- | --- |
| R334 | PRODUCER-BLOCKED | SMB named-pipe opens, per-session server outcomes and bounded distinct operations |
| R335 | PRODUCER-BLOCKED | authenticated SAMR/LSARPC interface, operation and returned enumeration result |
| R336 | PRODUCER-BLOCKED | authenticated DRSUAPI request, DC identity, principal and replication outcome |
| R337 | PRODUCER-BLOCKED | KDC-issued S4U delegation result and approved service-delegation policy |
| R338 | PRODUCER-BLOCKED | trusted KDC ticket enctype plus supported encryption policy and downgrade baseline |
| R339 | IN-PROGRESS, PRODUCER-BLOCKED | verified SMB2 server identity, negotiated session signing, sensitive-host classification and asset policy |
| R340 | PRODUCER-BLOCKED | trusted winreg RPC bind, operation result, principal and host approval |
| R341 | PRODUCER-BLOCKED | authenticated remote Task Scheduler create result and principal |
| R342 | PRODUCER-BLOCKED | verified WAC gateway, external ingress and complete request/response |
| R343 | PRODUCER-BLOCKED | trusted WinRM command/process audit, authenticated actor and encoded-command execution outcome |

**Changed files:** `Carthago/Services/ProtocolIntelligence/Smb2SigningNegotiationInspector.cs`, `Carthago.Tests/ProtocolIntelligence/Smb2SigningNegotiationInspectorTests.cs`, this ledger. **Functional detector repairs: 0.** Carryover: all 70 inspected IDs unresolved. **Next cursor:** R344–R350, R431–R433. Commit SHA: inspect atomic commit containing this ledger.
