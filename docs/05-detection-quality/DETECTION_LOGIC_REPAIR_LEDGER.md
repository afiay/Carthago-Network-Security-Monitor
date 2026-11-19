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


## Batch 08 — R344–R350, R431–R433 (2026-11-17)
**Source review:** inspected all ten expansion rule classes on the active branch. No rule was promoted to functional detection; runtime/engine binding is absent for the newly authored protocol prerequisite. All ten remain carryover.

| ID | State | Missing trustworthy source |
| --- | --- | --- |
| R344 | PRODUCER-BLOCKED | Windows WMI event-subscription creation result, actor, target and remote execution attribution |
| R345 | PRODUCER-BLOCKED | Authenticated DCOM MMC20 method invocation/outcome and remote principal/host |
| R346 | PRODUCER-BLOCKED | SQL Server audit of successful xp_cmdshell invocation and principal/authorization context |
| R347 | PRODUCER-BLOCKED | SQL Server audit of completed linked-server enumeration and result set |
| R348 | PRODUCER-BLOCKED | Authenticated LDAP query/response with AdminSDHolder object identity and actor |
| R349 | PRODUCER-BLOCKED | Authenticated LDAP SPN search result, caller and bounded enumeration correlation |
| R350 | PRODUCER-BLOCKED | Authenticated LDAP policy query response and approved administrative baseline |
| R431 | PRODUCER-BLOCKED | Verified Airflow service identity, complete HTTP admin response and authorization context |
| R432 | PRODUCER-BLOCKED | Verified Consul/Nomad service identity, complete admin response and management approval |
| R433 | IN-PROGRESS, PRODUCER-BLOCKED | Strict PostgreSQL protocol-3 startup-frame inspector authored; requires trusted complete capture, verified server identity, authentication outcome, external-source classification and engine integration |

**Actual source changes:** `Carthago/Services/ProtocolIntelligence/PostgreSqlStartupInspector.cs` (commit `8de31bc53a4c64695001d7663bc7ea1caffeccb0`) and `Carthago.Tests/ProtocolIntelligence/PostgreSqlStartupInspectorTests.cs` (commit `0038a20a8791e70fb1a0b1d092f9ae85e536d6cc`). Four test methods **AUTHORED, UNEXECUTED**. Startup-frame evidence alone is not proof of login, outcome, authorization or attack. No detector alert enabled. No Windows tests, Actions, CI changes or native capture performed.

**Carryover:** 80 reviewed IDs remain unresolved. **Next cursor:** R434–R443. Continue source/producer integration rather than qualification counting.

## Batch 09 — R434–R443 (2026-11-17)

**Source starting HEAD:** `0dcff503b15dbc5dcd3a193a0e00c467b5168083` (read before this batch's writes; concurrent branch writers may advance HEAD). **Scope:** ten database-exposure rules. No rule promoted to functional detection. Existing rule predicates and precision/Shadow policy unchanged. All ten remain unresolved carryover.

| ID | Status | Required trusted integration |
| --- | --- | --- |
| R434 | PRODUCER-BLOCKED | Complete MySQL client handshake plus authenticated server login outcome, verified server identity and external-source classification |
| R435 | PRODUCER-BLOCKED | TDS login exchange and authenticated SQL Server login audit outcome, server identity and approved DBA context |
| R436 | PRODUCER-BLOCKED | Complete MongoDB hello/command response, verified service and external exposure inventory; port/banner alone insufficient |
| R437 | PRODUCER-BLOCKED | Authenticated Redis command audit, CONFIG SET accepted outcome, verified server and approved-admin policy; do not weaken existing Redis precision tests |
| R438 | PRODUCER-BLOCKED | Redis REPLICAOF/SLAVEOF accepted server outcome, approved replication topology and trusted audit |
| R439 | IN-PROGRESS, PRODUCER-BLOCKED | Bounded memcached ASCII STATS request/response inspector authored; still needs trusted bidirectional TCP reassembly/flow provenance, verified service identity, approved monitoring baseline, threshold correlation and RuleEngine binding |
| R440 | PRODUCER-BLOCKED | Verified Elasticsearch cluster and complete snapshot repository API response, authorization and source attribution |
| R441 | PRODUCER-BLOCKED | Complete Cassandra native protocol startup/query response, verified node identity and external-source policy |
| R442 | PRODUCER-BLOCKED | Oracle TNS listener response with verified endpoint and multiple distinct service enumeration outcomes |
| R443 | PRODUCER-BLOCKED | Verified CouchDB service, complete admin API response, authorization context and external-source classification |

**Actual changes:** `Carthago/Services/ProtocolIntelligence/MemcachedStatsExchangeInspector.cs` (commit `5c94cf28dea6aa072693201b20553b7ce17c7726`) and `Carthago.Tests/ProtocolIntelligence/MemcachedStatsExchangeInspectorTests.cs` (commit `63fb19aa957053aaf40f910e879ed6bbaaba2ce6`). Four test methods including parameterized negative cases **AUTHORED, UNEXECUTED**. Inspector validates complete bounded ASCII STATS exchange and returns a count only; boolean caller attestations do not establish runtime capture provenance, authenticated server identity, authorization or malicious intent. No detector alert enabled. No Windows tests, native capture, GitHub Actions or CI changes deliberately performed.

**Carryover:** all 90 reviewed IDs remain unresolved. **Next cursor:** R444–R453. Revisit blockers after ordered queue; never mark parser-only work complete.


## Batch 10 — R444–R453 (2026-11-17)

**Inspected source HEAD:** `9776f4fdefd3b2eda6d086c8c7eea405e555fe0b`. Ten rule EvaluatePrecision paths use `EvaluateSpec` and generic profiles; no rule-specific trusted producer-to-engine positive path established. **Zero functionally repaired.** Source-only work, no Windows tests, native capture or Actions. All ten remain unresolved carryover.

| ID | Status | Missing trustworthy source / integration |
| --- | --- | --- |
| R444 | PRODUCER-BLOCKED | InfluxDB verified endpoint and authenticated query response, source approval |
| R445 | PRODUCER-BLOCKED | ClickHouse complete HTTP SQL request/response, verified cluster and approved client |
| R446 | PRODUCER-BLOCKED | Neo4j browser endpoint identity and complete response plus authorized management baseline |
| R447 | PRODUCER-BLOCKED | RabbitMQ management API verified broker, authenticated response and admin policy |
| R448 | PRODUCER-BLOCKED | Kafka broker protocol handshake, endpoint identity, external ingress and policy |
| R449 | PRODUCER-BLOCKED | ZooKeeper four-letter request/response reassembly, server attribution and admin baseline |
| R450 | PRODUCER-BLOCKED | NATS broker INFO/CONNECT exchange, verified server identity and accepted session |
| R451 | IN-PROGRESS, PRODUCER-BLOCKED | MQTT complete same-flow plaintext CONNECT/CONNACK, verified broker identity, authorization policy and runtime capture binding |
| R452 | PRODUCER-BLOCKED | Trusted database query result sizes and completed export/delivery outcomes with actor authorization |
| R453 | PRODUCER-BLOCKED | DNS decoded mDNS questions, distinct service/window correlation and approved discovery baseline |

**Actual source increment:** `Carthago/Services/ProtocolIntelligence/MqttAnonymousConnectInspector.cs` and `Carthago.Tests/ProtocolIntelligence/MqttAnonymousConnectInspectorTests.cs` (five test methods **AUTHORED, UNEXECUTED**). MQTT 3.1.1 CONNECT/CONNACK parsing is isolated and explicitly requires independent same-flow plaintext completeness; caller booleans are not trusted runtime evidence. No rule predicate or alert enabled. **Carryover:** 100 reviewed IDs remain unresolved. **Next cursor:** R454–R463. Commit: see publication of this ledger.


## Continuation — R451 carryover hardening (2026-11-17)

**Work completed:** tightened the existing MQTT 3.1.1 CONNECT/CONNACK inspector against contradictory Session Present evidence (reserved CONNACK flags, resumed session with CleanSession=true, or rejected session with Session Present), and rejected malformed UTF-8 or NUL ClientId. This is protocol-evidence correctness, not a producer or detector completion. Source: `Carthago/Services/ProtocolIntelligence/MqttAnonymousConnectInspector.cs`; regression source: `Carthago.Tests/ProtocolIntelligence/MqttAnonymousConnectInspectorTests.cs`. Two additional xUnit test methods **AUTHORED, NOT EXECUTED**. Source commit `92152fe0f2834a4cdc8c6634db98aefcf8a75efb`; tests commit `76ce6b4f9ff1af3e25e29c5b6c4964e7ac3b75b4`.

**R451 status:** IN-PROGRESS, PRODUCER-BLOCKED. Still requires trusted complete same-flow TCP reassembly, verified broker identity, policy context, runtime RuleEngine binding and detector-level tests. No alert enabled. No Windows runner, Actions, invasive capture or CI changes.

**Ordered cursor unchanged:** R454–R463 are the next ten *unprocessed* IDs; this continuation did not inspect or falsely advance them. **Carryover:** all previously reviewed 100 IDs remain unresolved. Revisit blocked IDs without counting a parser as a functional repair.

## Batch 11 — R454–R463 (2026-11-17; user-directed continuation)

**Source starting HEAD:** `4ae75d09afe644c75c8aca0a4bfc6efbf57f0aa5`.
**Scope:** ten local-discovery/network rules. Compared their actual `EvaluatePrecision` sources, the `LocalDiscoveryEvidenceBoundary` gate, PacketHandler/PortablePacketProcessor ARP decoding and internal provenance fields, rule precision telemetry, engine selector, window/cooldown helpers, and existing ARP frame tests. No live capture, Windows build, xUnit execution, or GitHub Actions was run.

| Rule | Source-development state | Missing integration / exact behavior |
| --- | --- | --- |
| R454 SSDP M-SEARCH external answer | PRODUCER-BLOCKED | Decoded M-SEARCH request, correlated external-direction SSDP response, verified UDP datagram source/target and approved service-discovery topology; mere UDP/1900 and Info string insufficient |
| R455 AirPlay discovery from non-media host | PRODUCER-BLOCKED | Parsed AirPlay service queries plus authoritative, stable asset-role inventory proving the sender is not a media host |
| R456 Chromecast discovery burst | PRODUCER-BLOCKED | Parsed service-query identities, unique frame-level observations, per-host discovery baseline and meaningful burst discriminator |
| R457 Printer JetDirect external access | PRODUCER-BLOCKED | Verified printer identity, actual JetDirect/RAW/IPP exchange and authorized external-source policy; TCP port alone insufficient |
| R458 IPP printing from external host | PRODUCER-BLOCKED | Complete IPP operation and correlated response with verified print service, target identity and external-source authorization |
| R459 SMB browser election anomaly | PRODUCER-BLOCKED | Validated legacy browser-election datagram/NetBIOS message, source and election-state transition; SMB/NetBIOS ports insufficient |
| R460 NetBIOS name query sweep | **SOURCE IMPLEMENTED — CANDIDATE, UNVERIFIED** | Complete capture-decoded NBNS first-level name questions (UDP/137) produce only transient digests. Eight distinct names per RFC1918 source in 60 seconds, bounded monotonic dedup, Shadow-only and cooldown; unauthorized or malicious outcome not inferred |
| R461 DHCP starvation candidate | PRODUCER-BLOCKED | Complete DHCP DISCOVER/REQUEST client IDs, distinct clients per sender with lease-exhaustion context and approved network topology |
| R462 Rogue DHCP offer | PRODUCER-BLOCKED | Complete capture-decoded DHCP OFFER, verified/approved DHCP server inventory (with relay/failover distinction), valid transaction and origin; packet port and text insufficient |
| R463 Gratuitous ARP storm | **SOURCE IMPLEMENTED — CANDIDATE, UNVERIFIED** | New wire-derived Ethernet/IPv4 gratuitous-ARP broadcast observation from `PortablePacketProcessor.ParseArp` through internal `ArpSenderMacMatchesFrame`, source==target IP, RFC1918, per-host+MAC 16 distinct packet IDs within 60s, bounded monotonic window, ten-minute cooldown, Candidate/Shadow with unchanged 76% confidence floor; not an authenticated spoofing verdict or field-confirmed anomaly |

**R463 code changes published:**
- `Carthago/Engine/Rules/Expansion/R463_ARPGratuitousStormRule.cs` — real predicate and candidate-mode profile instead of generic `EvaluateSpec` fail-closed stub; commit `4a6d66c58600502d30ad6624949770cca4f20450`.
- `Carthago.Tests/R463CaptureBoundBurstTests.cs` — **nine authored, unexecuted** xUnit facts using real in-memory ARP Ethernet frame parsing plus benign, forged-label, MAC mismatch, wrong destination, duplicate packet ID, multi-identity separation, out-of-order, expiry, cooldown and selector guards; commit `423a63cdace19239087b83bb8e25d78be1f4eb08`.
- `Carthago/Engine/Rules/Expansion/LocalDiscoveryEvidenceBoundary.cs` — removed the superseded generic R463 missing-producer declaration; other R454–R462 guards unchanged; commit `4665b36128dda38f889a6a67d4e0d20473302fa5`.

**No false promotion:** R463 has a source-level reachable detector path using existing parsed Ethernet data, but Windows/CLI compilation, test execution, native capture, false-positive calibration, engine trace/journal and SOC rendering remain unverified. It is explicitly **Candidate/Shadow**, not a high-confidence attack alert or operationally accepted repair. Its 16/60s threshold is deliberately more conservative than the previous nonfunctional 4/5-minute descriptor; operator policy tuning and benign burst evaluation remain follow-ups. Do not count authored tests as executed or source candidate as operational acceptance.

**Status:** 110/187 queued IDs have now been source-reviewed. Of them **two** (R460, R463) have source-level reachable positive detector implementations; the other **108** remain incomplete producer-bound candidates. **77 IDs remain unreviewed in the ordered queue.** Conservatively, **187 operationally completed rules are not established**; if counting source-only functional implementations, the *known remaining implementation backlog* is **185**, pending R460/R463 compilation and runtime review. Preserve 109 producer blockers as carryover; future batches should prioritize producer-to-engine integration rather than mere parser-only standalones.


**R460 additional atomic source publication:** `2d488d070f6f31dfeb50acca38382ece446e7d1a` updates the actual `R460_NetBIOSNameQuerySweepRule` predicate, `Carthago.Core/PortablePacketProcessor.cs`, internal `TrafficRecord.NbnsQueryNameDigest`, `NbnsNameQueryInspector`, `Carthago.Core.csproj`/WPF compile-link split, and the shared local-discovery evidence boundary. Eight narrowly targeted regression facts in `Carthago.Tests/R460CaptureBoundNetbiosSweepTests.cs` are **AUTHORED, NOT EXECUTED**. The binary decoder is limited to complete single-question first-level NBNS IPv4 UDP/137 payloads: QR/opcode/TC, length, A–P encoding, NetBIOS name, QTYPE NB and IN class checks; it does not parse compressed name scopes, multi-question traffic, retransmitted fragments or arbitrary DNS, nor provide asset authorization. The only exported detection evidence is a bounded distinct-name count and wire-decoder provenance. Rule remains **Candidate/Shadow, original 76% minimum confidence preserved**. Source-level predicate/producer are integrated, but runtime throughput, source authorization, 8/60s benign baseline, build, replay and SOC display are unverified. Other nine Batch-11 IDs remain blocked. **Queue cursor remains R464–R473**.

**Next ten unprocessed IDs:** `R464`, `R465`, `R466`, `R467`, `R468`, `R469`, `R470`, `R471`, `R472`, `R473`. Carryover work for R454–R462, earlier 100 blocked rules, and R463 current-SHA verification is explicit and not silently closed.


## Batch 12 — R464–R473 (2026-11-17; source-only)

**Inspected:** the ten expansion rule classes and the prior batch ledger. Their generic precision descriptors are not trusted detector-positive proof. This batch does not claim an operationally completed rule. Earlier R460/R463 source candidates remain unverified and in carryover.

| Rule | State | Missing authenticated producer or engine integration |
| --- | --- | --- |
| R464 | PRODUCER-BLOCKED | Complete ARP observations, per-IP conflicting MAC identity correlation, authoritative DHCP/asset inventory and failover baseline |
| R465 | PRODUCER-BLOCKED | Verified IPv6 ICMPv6 router advertisements and prefix information, trusted router inventory and change baseline |
| R466 | PRODUCER-BLOCKED | Verified Wi-Fi controller endpoint, complete admin request/response, authenticated actor and approval policy |
| R467 | PRODUCER-BLOCKED | Decoded CAPWAP discovery/join transactions, authenticated controller identity and external-origin policy |
| R468 | PRODUCER-BLOCKED | OS Bluetooth PAN/gateway attribution and correlated outbound flow plus authorized device policy |
| R469 | PRODUCER-BLOCKED | Valid ADB transport/authentication handshake, verified device identity and allowed developer endpoints |
| R470 | PRODUCER-BLOCKED | Signed MDM enrollment outcomes, stable distinct device identities and approved enrollment window |
| R471 | PRODUCER-BLOCKED | Authenticated RDP virtual-channel clipboard/file-copy event with session and transfer outcome |
| R472 | PRODUCER-BLOCKED | Signed endpoint process/remote-support session event, verified tool identity and authorized session baseline |
| R473 | IN-PROGRESS, PRODUCER-BLOCKED | Complete Modbus/TCP request/response reassembly, trusted ICS asset and approved engineering-workstation policy, transaction correlation and RuleEngine integration |

**Source increment for R473:** `Carthago/Services/ProtocolIntelligence/ModbusDeviceIdentificationRequestInspector.cs` (commit `ec0526a6d003b1edca2881b6ba5666a8d419a5ca`) parses only complete MBAP-framed function 0x2B/MEI 0x0E Read Device Identification requests. No success, maliciousness or authorization is inferred. `Carthago.Tests/ProtocolIntelligence/ModbusDeviceIdentificationRequestInspectorTests.cs` (commit `fadbaf744a97293375cf778bfd273d96837e3619`) has four xUnit methods with malformed-frame cases **AUTHORED, NOT EXECUTED**. The parser is not wired to trusted capture or RuleEngine. **Functional detector repairs: 0.** No local Windows runner, CI, Actions or live invasive tests used. **Carryover:** all ten remain incomplete. **Next cursor:** R474–R483. Ledger publication commit is the commit containing this section.

## Batch 13 — R474–R483 (2026-11-17; user-directed continuation)

**Source review starting SHA:** `7f439be5a8c2647a2406e3ef72e2fba1016bdfba`. The ten exact detector classes and relevant capture producers/OT evidence gates were reviewed. No Windows/Linux build, native capture, xUnit or CI run in this environment. Do not count a reviewed ID or authored test as a repaired detector.

| Rule | Source state | Missing evidence / implementation note |
| --- | --- | --- |
| R474 Modbus Force Listen Only Mode Attempt | **SOURCE IMPLEMENTED — CANDIDATE/SHADOW, NOT BUILT** | Dedicated first-client-payload Modbus/TCP MBAP FC08 subfunction 0x0004 decoder, SYN/SYN-ACK/sequence/ACK/complete-IP/TLS guards inherited from the existing native Modbus pipeline, internal capture-derived observation, Shadow-only exact request-attempt detector with cooldown. Does not prove device impact, success or unauthorized engineering work |
| R475 Modbus Diagnostics Function Abuse | PRODUCER-BLOCKED | Needs protocol-validated diagnostics subfunctions, repeated distinct transaction correlation, request/response where applicable, controller role/allowlist and benign maintenance baseline; FC08 port/name or any diagnostics request is not automatically abuse |
| R476 Modbus Coil Write Burst | PRODUCER-BLOCKED | Need exact FC05/FC15 request identity/targets, safely bounded multiple-write correlation, dedup across TCP connections, controller and approved engineering policy; ports/flow bytes insufficient |
| R477 S7 Start/Stop CPU Command | PRODUCER-BLOCKED | Needs complete TPKT/COTP/S7Comm start-stop job decoding, controller/session identity and request outcome; TCP/102 alone insufficient |
| R478 S7 Upload/Download Block Transfer | PRODUCER-BLOCKED | Needs correlated complete S7 block upload/download transactions, controller identity, user authorization and execution direction |
| R479 S7 PLC Identification Probe | PRODUCER-BLOCKED | Needs actual protocol-validated S7 identification query/response, distinct targets and engineering baseline |
| R480 DNP3 Control Relay Output Block | PRODUCER-BLOCKED | Needs decoded CRC-validated DNP3 function and CROB objects, request/response and authorized master identity |
| R481 DNP3 Freeze Counter Command | PRODUCER-BLOCKED | Needs decoded DNP3 freeze application operation, target counter objects and approved-master context; shared `OtDeepOperationEvidenceBoundary` remains fail-closed |
| R482 IEC-104 External Control Command | PRODUCER-BLOCKED | Needs validated IEC104 ASDU control and cause-of-transmission plus external/authorized master policy; TCP/2404 or generic IEC label insufficient |
| R483 OPC UA Browse Node Burst | PRODUCER-BLOCKED | Needs decrypted authenticated OPC UA Browse services, bounded distinct nodes/session/window and calibrated benign browse baseline |

**R474 source-level engineering change (atomic publication):**
- `Carthago/Services/ProtocolIntelligence/ModbusForceListenOnlyModeInspector.cs` — strict complete 12-byte FC08/subfunction 0x0004 request, protocol ID zero, MBAP length six, nonzero valid unit and data field zero. No response/success semantics fabricated.
- `Carthago.Core/PortablePacketProcessor.cs` — integrates the inspector inside **existing** native Modbus initial-capture path with verified TCP SYN/SYN-ACK, matching sequence/ACK, both directions not TLS, nonfragmented exact first request, and no duplicate second payload; sets a typed `TrafficRecord.ModbusForceListenOnlyModeAttemptObserved` flag and exact application-protocol marker.
- `Carthago/Models/TrafficRecord.cs` — capture-owned internal setter on attempt flag; user-imported Info text cannot set the flag.
- `Carthago/Engine/Rules/Expansion/R474_ModbusForceListenOnlyModeAttemptRule.cs` — source-level reachable positive predicate and event with precise request-only evidence, same **86% minimum confidence**, Candidate/Shadow runtime policy; per-instance bounded cooldown.
- `Carthago/Engine/Rules/Execution/RuleCandidateSelector.cs` — considers typed Modbus attempt field when deciding OT selectability; no loose word-based override.
- `Carthago.Core/Carthago.Core.csproj` and `Carthago/Carthago.csproj` — compile parser once in Core and avoid duplicate host compilation.
- `Carthago.Tests/R474CaptureModbusForceListenOnlyTests.cs` — **8 authored xUnit methods** (6 facts + 2 parameterized theories), not executed. Includes full raw-frame TCP three-way handshake, malformed MBAP/function/subfunction, partial/coalesced requests, wrong ACK/port/flags, missing SYN/SYN-ACK, forged text, duplicate packet ID, cooldown, source isolation, engine selectability and telemetry gating.

**Verification status:** STATIC SOURCE REVIEW ONLY. Exact commit SHA is the single Git commit containing this Batch-13 section. R474 remains **SOURCE CANDIDATE UNVERIFIED** until native compile/replay and false-positive/operational review. No other batch rule is marked functionally repaired. Preserve all other control/provenance gates; do not change critical alert policy globally.

**Cumulative source inventory:** 130 / 187 IDs reviewed, **3 source-only reachable candidate detectors (R460, R463, R474)**, 127 reviewed producer-blocked, 57 not yet reviewed. Thus 184 of the 187 initially identified rules lack a source-connected candidate predicate; **0 of these three newly authored candidate source paths have been demonstrated operationally accepted in this ledger**. Carry over all 127 blocked IDs and source-build/run review of R460/R463/R474.

**Next ten unprocessed IDs:** `R484`, `R485`, `R486`, `R487`, `R488`, `R489`, `R490`, `R491`, `R492`, `R493`. The hourly automation must select from this cursor, avoid redoing this batch and revisit blocked items after ordered traversal.

## Batch 14 — R484–R493 (2026-11-17; source-only)

**Rule-class inspection:** R484–R493 fetched from the existing branch. R485 and R486 ALREADY have reachable capture-bound Candidate/Shadow predicates and must not be misclassified as generic EvaluateSpec stubs. Their build, runtime, provenance, policy, and benign validation are not established by this inspection. The remaining eight rules use generic EvaluateSpec without demonstrated producer-specific positive detection. No operational completion claimed.

| Rule | State | Concrete missing integration |
| --- | --- | --- |
| R484 OPC UA Write | PRODUCER-BLOCKED | Authenticated/decrypted OPC UA Write service request and correlated response, node identity and approved engineering actor |
| R485 BACnet WriteProperty | SOURCE CANDIDATE, UNVERIFIED | Existing typed BACnet capture flag and Shadow rule; verify native decode, boundary policy, controller identity and benign write maintenance baseline |
| R486 BACnet DeviceCommunicationControl | SOURCE CANDIDATE, UNVERIFIED | Existing typed BACnet capture flag and Shadow rule; verify native decode, controller identity, approved maintenance and device response |
| R487 Profinet DCP SetName | PRODUCER-BLOCKED | Validated Ethernet DCP Set NameOfStation operation, target identity, topology and approved engineering source |
| R488 EtherNet/IP ListIdentity burst | IN-PROGRESS, PRODUCER-BLOCKED | Isolated strict encapsulation request inspector authored; requires actual capture/reassembly integration, correlated replies, unique target/window dedup, approved scanner baseline and RuleEngine wiring |
| R489 EtherNet/IP ForwardOpen external | PRODUCER-BLOCKED | Decoded CIP ForwardOpen service with session/path, target/controller identity, source boundary and response outcome |
| R490 IEC61850 MMS Write | PRODUCER-BLOCKED | Complete decoded MMS Write operation and response, authenticated IED identity and maintenance authorization |
| R491 GOOSE multicast outside substation | PRODUCER-BLOCKED | Ethernet GOOSE APDU decode, trusted interface/VLAN/substation boundary topology and publisher identity |
| R492 Historian bulk query | PRODUCER-BLOCKED | Authenticated historian query audit, returned volume, stable workstation identity and authorized job baseline |
| R493 Browser password store upload | PRODUCER-BLOCKED | Endpoint file identity/read and verified outbound upload join, destination identity, outcome and privacy-safe provenance |

**Concrete source increment:** `Carthago/Services/ProtocolIntelligence/EtherNetIpListIdentityInspector.cs` adds strict complete 24-byte EtherNet/IP encapsulation ListIdentity request validation (command 0x0063, zero body length/session/status/options, opaque sender context). This deliberately does not establish an inventory response, burst, scan, unauthorized behavior or trusted capture. `Carthago.Tests/ProtocolIntelligence/EtherNetIpListIdentityInspectorTests.cs` adds three xUnit methods (including a five-case theory) for valid, incomplete, coalesced and invalid-header requests. Source commit `195afcf375fc7a9e02f0725e80e0dc67557d3669`; test commit `fa262a9792bec14b82e0e77c0e18c8c464af8ac6`. **Tests authored, NOT executed.** No Windows runner, build, live capture or CI. R488 remains fail-closed with no engine integration. No precision floors or frozen holdout changed.

**Next exact cursor:** R494–R503. Keep R484/R487–R493 and R488 producer work in carryover; R485/R486 remain source candidates pending build/runtime acceptance. Earlier R460/R463/R474 candidate statuses are unchanged. No rule was operationally promoted in this batch.


## Batch 15 — R494–R503 (2026-11-17; source-only)

**Ten exact expansion rule classes inspected on the existing branch.** All ten retain generic `EvaluateSpec(context, Spec)` and have no demonstrated trusted source-to-detector predicate. Their descriptive TextIndicators, ProcessIndicators, paths, and ports do not establish a sensitive-file transfer or authorization violation. **Functional detector completions: 0.**

| ID | State | Required trusted producer / blocker |
| --- | --- | --- |
| R494 | PRODUCER-BLOCKED | Endpoint-confirmed SSH private key file identity/read, process identity, destination and completed upload join; never inspect/store secret bytes |
| R495 | PRODUCER-BLOCKED | Endpoint-confirmed KeePass database file identity/read and correlated completed external transfer with backup policy |
| R496 | PRODUCER-BLOCKED | Endpoint-confirmed VPN configuration file identity/read, trusted external transfer outcome and authorized configuration distribution policy |
| R497 | PRODUCER-BLOCKED | Endpoint-confirmed browser cookie database file identity/read and completed outbound transfer; privacy-safe metadata only |
| R498 | PRODUCER-BLOCKED | Trusted clipboard sync operation with byte count, actor/session identity, remote sync endpoint and approved policy |
| R499 | PRODUCER-BLOCKED | Authenticated remote-desktop virtual-channel file-transfer outcomes, session identity, distinct transfer count and authorized remote-support baseline |
| R500 | PRODUCER-BLOCKED | Endpoint archive creation with file identity followed by correlated authenticated cloud upload outcome and backup baseline |
| R501 | IN-PROGRESS, PRODUCER-BLOCKED | Strict bounded multipart filename entropy prerequisite authored; still requires trusted HTTP body provenance, authenticated upload outcome, real multipart body completion/closing-boundary validation, deduplicated per-session threshold, authorization baseline and RuleEngine wiring |
| R502 | PRODUCER-BLOCKED | Trusted decrypted complete HTTP POST body with verified data URI/base64 payload length, transfer outcome and destination authorization |
| R503 | PRODUCER-BLOCKED | Authenticated HTTP POST request/response and verified paste-service identity, transferred byte count, distinct completed requests and allowlist |

**Concrete source changes:** `Carthago/Services/ProtocolIntelligence/MultipartFilenameEntropyInspector.cs` (commit `6615915ef886c35bdbc49420d4a7a2a1b364c099`) adds a bounded, strict first-part multipart header filename entropy prerequisite, gated on explicitly complete plaintext body input. It does **not** verify upload success, trust the caller, validate the full multipart body, retain content, or emit alerts. `Carthago.Tests/ProtocolIntelligence/MultipartFilenameEntropyInspectorTests.cs` (commit `af439d2d2f8ba1a01dd311f7594d9b480beadc13`) authors three xUnit methods including a theory; **tests NOT executed**. The parser is isolated and has no RuleEngine integration. No local Windows runner, dotnet build, native capture, GitHub Actions, precision floor or holdout changes.

**Carryover:** all ten remain incomplete. Existing R460/R463/R474/R485/R486 source candidates remain unverified; all previous producer-blocked IDs remain in carryover. **Next exact ten:** R504–R513. Ledger publication SHA is the commit containing this section.


## Batch 16 — R504–R513 (2026-11-17; source-only)

**Scope:** inspected all ten exact expansion classes at the live branch. All retain generic `EvaluateSpec(context, Spec)` with no demonstrated trusted producer-specific positive predicate. TextIndicators, host, process and path labels are not evidence of a completed unauthorized upload or SSH dynamic tunnel. **Functional detector completions: 0.**

| ID | State | Required trusted producer / blocker |
| --- | --- | --- |
| R504 | PRODUCER-BLOCKED | Authenticated GitHub Gist creation audit/API response, confirmed secret-classification event, actor and authorization policy; hostname or URL alone insufficient |
| R505 | PRODUCER-BLOCKED | Authenticated Discord attachment upload outcome, byte count, stable actor/session, deduplicated burst window and approved use policy |
| R506 | PRODUCER-BLOCKED | Authenticated Telegram sendDocument API outcome, verified bot/account, file metadata and burst threshold; encrypted traffic alone insufficient |
| R507 | PRODUCER-BLOCKED | Authenticated MEGA upload completion or signed endpoint transfer event, bytes, actor and approved sync policy |
| R508 | PRODUCER-BLOCKED | OS-attested rclone process identity plus verified outbound transfer completion, destination classification and backup authorization; user-agent string spoofable |
| R509 | PRODUCER-BLOCKED | Trusted rsync process/command direction and completed external push, endpoint identity and backup authorization |
| R510 | PRODUCER-BLOCKED | Authenticated S3-compatible PutObject/multipart completion, verified destination identity, asset inventory and approved bucket policy |
| R511 | PRODUCER-BLOCKED | Endpoint/database export completion joined by file identity to authenticated HTTP upload outcome and actor/authorization |
| R512 | PRODUCER-BLOCKED | Verified sensitive-file classification, authenticated mail attachment send/delivery and recipient classification/approved business workflow |
| R513 | IN-PROGRESS, PRODUCER-BLOCKED | Strict SOCKS5 exchange prerequisite added; needs trusted bidirectional stream reassembly, OS-attested SSH process and dynamic-forward listener mapping, remote endpoint, authorized tunnel policy and RuleEngine wiring |

**R513 source increment:** `Carthago/Services/ProtocolIntelligence/Socks5ConnectExchangeInspector.cs` (commit `6d818afe6e5727c2f490d61999383d4403fb2dae`) strictly parses bounded complete plaintext same-session SOCKS5 no-auth greeting, method selection, CONNECT request and reply, including IPv4/IPv6/domain framing. It returns only server acceptance and address type, not SSH tunnel attribution or unauthorized behavior. `Carthago.Tests/ProtocolIntelligence/Socks5ConnectExchangeInspectorTests.cs` (commit `9c73fb954cba424743136de0e47f7c5b1f0b6937`) authors four xUnit methods for valid/rejected, partial, malformed and untrusted exchanges. **Tests authored, NOT executed.** No local Windows runner, build, native capture, CI, Actions or invasive tests. No engine alerts enabled, precision floors or holdout modified. All ten IDs retained in carryover. Earlier source candidates remain unverified.

**Next exact cursor:** R514–R523. This batch is a parser prerequisite, not ten implemented detectors. Ledger publication SHA is the commit containing this section.


## Batch 17 — R514–R523 (2026-11-17; source-only)

**Ten exact rule classes inspected:** R514 Chisel handshake; R515 FRP handshake; R516 Cloudflared handshake; R517 ngrok handshake; R518 reverse SSH tunnel; R519 DNS-over-QUIC resolver; R520 MASQUE CONNECT-UDP; R521 HTTP CONNECT non-proxy port; R522 WebSocket to IP literal; R523 domain-fronting Host/SNI mismatch. All remain incomplete. **Functional detector completions: 0.** No Windows runner, dotnet build, xUnit execution, native capture, CI or live network test.

| ID | Status | Exact missing trusted source / blocker |
| --- | --- | --- |
| R514 | PRODUCER-BLOCKED | Authenticated Chisel agent/process identity, decoded completed tunnel establishment and approved tunnel policy; string or port hints insufficient |
| R515 | PRODUCER-BLOCKED | Authenticated frpc/frps session control and remote proxy registration, host identity and approved tunnel inventory |
| R516 | PRODUCER-BLOCKED | Existing process-name/SNI prefilter is not authenticated connector identity; needs OS-attested process and verified Cloudflare Tunnel session/control-plane audit and authorization |
| R517 | PRODUCER-BLOCKED | Verified ngrok agent identity and authenticated tunnel session/API registration plus approved developer tunnel baseline |
| R518 | PRODUCER-BLOCKED | OS-attested SSH process command/socket forwarding mapping and remote listener establishment with authorization |
| R519 | PRODUCER-BLOCKED | Validated QUIC/DoQ protocol and resolver identity, authenticated DNS query evidence and approved resolver inventory |
| R520 | PRODUCER-BLOCKED | Decrypted HTTP/3 extended CONNECT-UDP request/response, capsule/session correlation and approved MASQUE proxy identity |
| R521 | IN-PROGRESS, PRODUCER-BLOCKED | Strict HTTP/1.1 CONNECT framing prerequisite authored; still needs trusted stream reassembly, proxy response status, policy-defined approved proxy ports, endpoint identity, correlation and RuleEngine integration |
| R522 | PRODUCER-BLOCKED | Complete WebSocket upgrade response with verified IP-literal authority and bidirectional tunnel behavior, trusted capture and approved application baseline |
| R523 | PRODUCER-BLOCKED | Same-session authenticated TLS SNI and decrypted HTTP Host provenance, proxy/CDN exception policy and verified mismatch outcome; separate flow labels are not proof |

**Source increment:** `Carthago/Services/ProtocolIntelligence/HttpConnectRequestInspector.cs` (commit `35139e16318c21a56cdca76b93cddc3b030ea19d`) parses bounded complete HTTP/1.1 CONNECT request framing, strict authority/port, matching single Host header, and rejects ambiguous request bodies/partial plaintext. This is a prerequisite only; caller-provided completeness is NOT authenticated provenance. `Carthago.Tests/ProtocolIntelligence/HttpConnectRequestInspectorTests.cs` (commit `bf46c57ba7ed355af8bf2d7adcb4f47a6a327aec`) authors three xUnit methods including a five-case theory. **Tests authored, not executed.** No engine alerts enabled. Preserve R102/R118/R163 floors and frozen holdout.

**Carryover:** all ten IDs unresolved, along with previous producer-blocked rules and unverified source candidates. **Next exact ten:** R524–R533. Ledger publication SHA is the commit containing this section.


## Batch 18 — R524–R533 (2026-11-17; source-only)

**Source inspection:** all ten expansion rule classes inspected on the existing branch. R524–R528 retain generic EvasionTunnel EvaluateSpec descriptions without demonstrated protocol-specific positive evidence. R529–R530 already have guarded health-source candidates; R531–R533 have guarded platform-health candidates, but their source boundary intentionally fails closed. No RuleEngine alert promoted. **Functional detector completions: 0.**

| ID | Status | Exact trusted producer / remaining integration |
| --- | --- | --- |
| R524 | PRODUCER-BLOCKED | Verified TLS ClientHello ECH extension from a complete capture, approved ECH provider inventory, independently authenticated provider/endpoint identity and policy decision |
| R525 | PRODUCER-BLOCKED | QUIC packet-number-space and connection-ID lifecycle with validated NEW_CONNECTION_ID/RETIRE_CONNECTION_ID frames, stable connection identity, migration exclusions and bounded distinct rotation rate |
| R526 | PRODUCER-BLOCKED | Capture-origin per-flow packet-length/time series, calibrated benign application baseline and independent beacon correlation; equal-sized packets alone are not malicious |
| R527 | PRODUCER-BLOCKED | Trusted long-lived flow/session continuity and monotonic timestamps, multi-interval recurrence, known scheduler/maintenance baseline and bounded gaps |
| R528 | PRODUCER-BLOCKED | Decrypted complete HTTP requests with source/session identity, privacy-safe distinct User-Agent counts and benign browser/automation baseline |
| R529 | SOURCE CANDIDATE, PRODUCER-BLOCKED | Authenticated sensor registry, expected heartbeat schedule, grace/maintenance state and verified missing-heartbeat decision; mutable record text cannot establish absence |
| R530 | SOURCE CANDIDATE, PRODUCER-BLOCKED | Sensor-clock monotonic/wall-clock measurements, trusted clock reference, multiple samples and drift decision with sleep/NTP recovery exclusions |
| R531 | IN-PROGRESS, PRODUCER-BLOCKED | New local OS volume-capacity probe prerequisite exists; still requires configured journal path ownership, periodic trusted sampling, policy thresholds, maintenance handling and typed RuleEngine health-event path. The existing textual rule remains fail-closed |
| R532 | SOURCE CANDIDATE, PRODUCER-BLOCKED | Authenticated per-sink outbox retry outcomes, queue depth, rate denominator, bounded window and maintenance policy; generic network retries insufficient |
| R533 | SOURCE CANDIDATE, PRODUCER-BLOCKED | Trusted per-rule match counters, comparable exposure-normalized baseline, replay/load-test exclusion, calibrated anomaly decision and engine integration |

**Concrete source increment:** `Carthago/Services/ProtocolIntelligence/JournalVolumeCapacityProbe.cs` (commit `e46cba5b1afc7990e7dc6c112f463715725dc6f4`) reads OS-reported available/total bytes only for an existing local directory and rejects invalid capacity/threshold data; it provides an explicit both-limits predicate. It does not authenticate caller-selected paths, infer journal ownership, or emit a detection. `Carthago.Tests/ProtocolIntelligence/JournalVolumeCapacityProbeTests.cs` (commit `2a3d4626cc26d9b2fba8f9199f1a9b77eb7d91df`) authors three methods including a five-case theory. **Tests authored, NOT executed.** No local Windows runner, build, live capture, GitHub Actions, force push, precision-floor or frozen-holdout changes.

**Carryover:** all ten IDs remain incomplete. Existing previous producer-blocked IDs and source candidates remain unresolved. **Next exact cursor:** R534–R540 (final seven IDs); then revisit the carryover queue. The ledger publication commit is the commit containing this section.


## Batch 19 — R534–R540 (2026-11-17; source-only)

**Exact ordered cursor:** final seven IDs R534, R535, R536, R537, R538, R539, R540. All seven rule classes and `PlatformHealthProducerEvidenceBoundary` inspected on the existing branch. They already contain guarded `EvaluatePrecision` candidates, but the boundary explicitly returns missing-producer reasons before mutable `TrafficRecord` text can create an alert. None is operationally complete. **Functional completions: 0.**

| Rule | Status | Missing authenticated integration |
| --- | --- | --- |
| R534 | SOURCE CANDIDATE, PRODUCER-BLOCKED | Expected eligible traffic and per-rule match baseline, enablement/suppression/maintenance state, authenticated health decision |
| R535 | SOURCE CANDIDATE, PRODUCER-BLOCKED | Comparable typed per-field coverage samples with expected population, parser/version/source scope and trusted producer |
| R536 | IN-PROGRESS, PRODUCER-BLOCKED | Typed bounded parser failure-rate comparison added; requires authenticated per-parser monotonic counters, stable epoch, expected exposure baseline, replay exclusions, periodic sampling and RuleEngine health-event integration |
| R537 | SOURCE CANDIDATE, PRODUCER-BLOCKED | Eligible public-IP GeoIP lookup attempts and explicit failure outcomes, provider enablement and authenticated bounded windows |
| R538 | SOURCE CANDIDATE, PRODUCER-BLOCKED | Authenticated eligible reputation lookup attempts/outcomes and provider-specific rate baseline with disabled/rate-limit exclusions |
| R539 | SOURCE CANDIDATE, PRODUCER-BLOCKED | Typed baseline persistence attempt/failure outcome from owned store with read-only/maintenance policy |
| R540 | SOURCE CANDIDATE, PRODUCER-BLOCKED | Typed analyst-feedback persistence attempt/failure outcome from owned store with cancellation/validation exclusion |

**Engineering increment:** `Carthago/Services/Diagnostics/ParserFailureRateWindow.cs` (source commit `c5d751e6da08ffd09a061ebd4bd6212b9ed534c3`) adds a pure typed comparison of cumulative per-parser counters across baseline and current UTC windows. It requires stable parser/epoch, monotonic plausible counters, nonoverlapping windows, denominators and both absolute and relative increases. It does **not** authenticate its caller or enable alerts. `Carthago.Tests/ParserFailureRateWindowTests.cs` (test commit `cccdc9683c79321574d7b24ab0381fda6f3d11ee`) authors four xUnit tests for rate increase, resets, invalid counters and benign rate. **Tests authored: 4. Tests executed: 0.** No local Windows runner, dotnet build, native capture, GitHub Actions, force push, floor or holdout changes. The R536 producer boundary remains fail-closed.

**Next cursor:** ordered queue exhausted; do not mark it implemented. Revisit the unresolved per-ID carryover queue starting with previously authored typed protocol/health prerequisites, prioritizing real trusted producer-to-RuleEngine wiring. All seven remain unresolved. Ledger publication SHA is the commit containing this section.


## Carryover integration pass 01 — R536 counter-continuity hardening (2026-11-17)

**State:** IN-PROGRESS, PRODUCER-BLOCKED. Ordered 187-ID inspection cursor is exhausted; no ID was promoted to functional. This pass revisited R536, not a new ten-ID batch. The source-only increment closes a concrete counter-integrity gap: two individually monotonic windows previously could compare despite a reset/rollback or impossible cumulative failure increment *between* the windows. The comparator now requires cumulative attempts and failures to be nondecreasing across the gap and gap failures not to exceed gap attempts. Same-epoch claims alone are insufficient. This preserves fail-closed behavior and avoids artificial parser-failure spikes.

**Changed files:** `Carthago/Services/Diagnostics/ParserFailureRateWindow.cs` (commit `5fec1658bad8a5417ce6e286439fe642a8d8cec7`); `Carthago.Tests/ParserFailureRateWindowTests.cs` (commit `f596ef231a75245675df7787546d88b35409f5bf`). **Tests authored:** 2 additional xUnit methods (counter rollback and impossible gap). **Tests executed:** 0. No Windows runner, build, native capture, invasive tests, GitHub Actions or holdout/precision-floor changes. Sequential commits, not atomic.

**Remaining R536 blockers:** trusted owned per-parser counter producer, immutable parser/epoch identity, sample provenance, replay/maintenance exclusion, scheduler, policy thresholds and typed RuleEngine health-event integration. Counter comparison is not an authenticated detector. **Functional completions this pass: 0.** Continue unresolved carryover with producer-to-engine wiring, prioritizing locally owned health counters over unauthenticated external audit feeds. No next ordered ID cursor; all reviewed IDs remain unresolved pending verification.


## Carryover integration pass 02 — R531 redirected-path guard (2026-11-17)

**Status:** IN-PROGRESS, PRODUCER-BLOCKED; **functional completions: 0**. The 187-ID ordered review cursor is exhausted, not implemented. This run revisited R531 and hardened the OS-backed journal capacity prerequisite: `JournalVolumeCapacityProbe.TryRead` now rejects any symbolic-link/junction (reparse-point) directory in the resolved path ancestry. Otherwise a caller-supplied redirected directory could report capacity from a different volume than the expected journal storage. This check is a safety prerequisite, **not** proof that the directory is the configured journal owner; it does not produce an alert.

**Changed files / publication:** `Carthago/Services/ProtocolIntelligence/JournalVolumeCapacityProbe.cs` commit `35d1380367316a2f63bb74371e41724a516a0056`; `Carthago.Tests/ProtocolIntelligence/JournalVolumeCapacityProbeTests.cs` commit `e3ad17485de370e70bb39e4cf81f5be13d8ab915`. **Tests authored:** one symlink-path regression method, conditionally bypassing unsupported symlink creation. **Tests executed:** 0. No local Windows build/runner, CI, native capture or live invasive tests. Sequential SHA-guarded file writes, not atomic. No change to R102/R118/R163 floors, frozen holdout, or RuleEngine alert gates.

**Remaining producer/engine blocker:** obtain the actual configured journal directory from the owned journal service (not user traffic), bind it to a trusted periodic capacity sampler with stable storage identity and maintenance state, and feed typed verified health events to R531 through RuleEngine. The existing mutable-text rule must remain fail-closed. **Next:** continue carryover integration, prioritizing real producer-to-engine wiring for R531 and R536; do not advance a fictitious ten-ID cursor or mark producer-blocked IDs complete.

## Carryover — R531 configured journal capacity ownership (2026-11-17)

**Source snapshot before change:** `ad5f55eb5d225d77292a3aaa469256344500f12e`.
**Status:** R531 IN-PROGRESS / PRODUCER-BLOCKED; **zero functional detector completions**.

The actual `DetectionJournal` now exposes `TryReadConfiguredVolumeCapacity`, reading OS-reported volume capacity through `JournalVolumeCapacityProbe` using the instance's `DetectionJournalOptions.DirectoryPath`, not an arbitrary packet-provided path. It does not create a missing directory or publish a health event. This is a concrete journal-owner-to-probe connection, **not** R531 RuleEngine integration.

**Changed source:** `Carthago/Services/Journaling/DetectionJournal.cs` (commit `859549924422c50c28295f8f9620da8cd12e5a34`).
**Tests authored:** `Carthago.Tests/DetectionJournalCapacityOwnershipTests.cs` (two xUnit tests; commit `3a2f6d06379f8c040a75ad2571a23985f1703038`).
**Tests executed:** none; no Windows runner, compilation, native capture or CI.
**Outstanding R531 blockers:** owned periodic sampling lifecycle; explicit minimum-byte and percent policy; maintenance exclusions; typed trusted health-event transport; RuleEngine dispatch and benign/positive integration tests. Do not infer successful journal writes from free space. **R536** still needs authenticated parser attempt/failure counters and a runtime connection.

**Next cursor:** ordered queue exhausted at R540; continue unresolved carryover IDs without treating review or partial prerequisites as completion.

## Carryover — R531 owned threshold evaluation (2026-11-17)

**Status:** IN-PROGRESS / PRODUCER-BLOCKED; **functional detector completions: 0**. The ordered R270–R540 inspection queue was already exhausted. This pass adds a fail-closed policy evaluation to the actual `DetectionJournal` owner: `TryEvaluateConfiguredVolumeCapacity` validates explicit byte and percent thresholds, samples its configured directory via the existing OS-backed probe, and only returns a low-space *prerequisite* when both limits are breached. Invalid policy or unavailable capacity returns unknown (false method result), never a low-space finding. This does not publish events or enable R531 alerts.

**Source change:** `Carthago/Services/Journaling/DetectionJournal.cs` commit `6613f0676039f4faa7836b41628c6f36f512882b`.
**Tests authored:** 3 xUnit methods in `Carthago.Tests/DetectionJournalCapacityOwnershipTests.cs` commit `3f8b140d3bb4cf94f73b3e81d68166a6e5bb3c48`, covering invalid thresholds, missing owned directory and non-mutating evaluation of an existing directory. **Tests executed: 0**; no Windows runner, build, native capture, GitHub Actions or invasive test. Commits are sequential SHA-guarded content updates, not atomic.
**Outstanding:** configured production policy and periodic sampling ownership, maintenance exclusion, trusted typed health-event delivery, RuleEngine dispatch and positive/benign integration verification. R536 still needs authenticated parser counters and integration. No R102/R118/R163 precision-floor, holdout or alert-gate changes.
**Next:** unresolved carryover producer-to-RuleEngine integration; no new ordered cursor and no blocked ID marked complete.

## Carryover — R531 owned consecutive-sample gate (2026-11-18)

**Status:** IN-PROGRESS / PRODUCER-BLOCKED; **functional detector completions: 0**. Ordered 187-ID review queue remains exhausted. Added `Carthago/Services/Journaling/JournalCapacitySamplingGate.cs` (commit `3bc47e569bdabf87a1fbc0b73bb055b95c5e0dc3`) as a stateful owner-bound sampling prerequisite around `DetectionJournal.TryEvaluateConfiguredVolumeCapacity`. The gate requires valid policy, UTC timestamps, minimum interval and two consecutive low readings; it resets on maintenance, invalid clocks or failed OS capacity samples. It neither accepts packet-derived data nor emits a detection or bypasses `PlatformHealthProducerEvidenceBoundary`. Caller-supplied maintenance and clock inputs still require trusted scheduling/ownership.

**Regression source authored:** `Carthago.Tests/JournalCapacitySamplingGateTests.cs` (commit `a5a8fb5a2ca796442e0b9125b2fbb37a5bc7ff1d`), two xUnit methods for separated samples, maintenance/invalid-clock fail-closed and missing owned directories. **Tests executed: 0.** No local Windows runner, dotnet build, native capture, GitHub Actions, force push or invasive test. Source compilation and behavior remain unverified.

**Remaining R531 blockers:** actual owned periodic scheduler and monotonic clock provenance; configured production threshold and maintenance policy; typed trusted health-event delivery and R531 RuleEngine integration; positive/benign runtime tests. R536 requires authenticated parser counters and engine integration. All previously producer-blocked IDs remain in carryover; none is counted implemented. **Next:** prioritize real R531 producer dispatch, then R536 parser counter ownership. No next ordered ID cursor.

## Carryover — R531 stale-sample continuity guard (2026-11-18)

**Status:** IN-PROGRESS / PRODUCER-BLOCKED; **functional detector completions: 0**. The ordered 187-ID review cursor remains exhausted. The owner-bound `JournalCapacitySamplingGate` previously allowed an arbitrarily old first low-capacity reading to confirm a later low reading. It now expires the first sample when elapsed time exceeds a configurable maximum interval (default three times the minimum interval); an expired low sample starts a new two-sample sequence. Explicit maximum intervals shorter than the minimum are rejected. Default interval calculation saturates safely at `TimeSpan.MaxValue`.

**Production file:** `Carthago/Services/Journaling/JournalCapacitySamplingGate.cs` (commits `0199622af7c7f476574b8d2545e146e7671ca96e`, `cb4d5c0b2f4bf21323c491d0254b54061ed657dc`). **Tests authored:** two xUnit methods in `Carthago.Tests/JournalCapacitySamplingGateTests.cs` (commit `cb2111a3c3a1cbba320d0a0af92593c072875611`). **Tests executed:** 0. No Windows runner, build, live capture, CI, invasive tests, force push, or changes to R102/R118/R163 floors and frozen holdout. Sequential SHA-guarded writes, not atomic.

**Remaining:** no owned periodic scheduler or trusted clock/maintenance context, no production threshold configuration, no typed health-event dispatch or R531 RuleEngine predicate integration. R536 still lacks owned parser counters and RuleEngine wiring. No detector promoted and no carryover rule marked complete. **Next:** prioritize authenticated local health producer dispatch and runtime integration rather than further isolated sampling helpers.


## Carryover — R531 concurrent sampling serialization (2026-11-18)

**Source snapshot:** branch HEAD `524b80f8903ef154f5731dbccd8327b45679b5a6` at start of pass. **State:** IN-PROGRESS / PRODUCER-BLOCKED; **functional completions: 0**. Ordered 187-ID review cursor remains exhausted; no rule promoted.

**Actual source change:** `Carthago/Services/Journaling/JournalCapacitySamplingGate.cs` now serializes sampling and reset state under a private lock. Concurrent GUI/CLI/service callers cannot race on `_previousUtc` and `_consecutiveLow` to fabricate a two-sample confirmation. Commit `8c4fe08a336440fd79d82901f949ae38852364c1`.

**Regression test source:** `Carthago.Tests/JournalCapacitySamplingGateTests.cs` adds a parallel same-timestamp sampling test that requires zero confirmations and a later distinct sample for confirmation. Commits `098d711f7621f2ef754598fe9ad2028030215be2`, `628ec7c22f6fdac2022597a58f7c8605744570b1`. **Tests authored: 1. Tests executed: 0.** No local Windows runner or build; compilation unverified. No CI, live invasive tests, force push, precision floor or frozen holdout changes.

**Remaining R531:** trusted owned periodic scheduler and clock/maintenance provenance, production threshold policy, typed health-event transport, R531 RuleEngine integration and positive/benign runtime verification. **R536:** trusted parser-counter producer and RuleEngine integration. All blocked IDs remain carryover; no new ordered cursor. Next engineering pass must prioritize actual producer-to-engine integration, not further isolated helpers.


## Carryover R531 — bounded low-space episode confirmation (2026-11-18)

**Status:** IN-PROGRESS / PRODUCER-BLOCKED, not functional detector completion. Ordered queue cursor remains exhausted; do not count this as an additional reviewed rule or advance the cursor. R536 remains producer-blocked.

**Production change:** `Carthago/Services/Journaling/JournalCapacitySamplingGate.cs` now emits the two-reading low-space confirmation once per sustained episode instead of on every later low sample; recovery, stale/unknown sampling, maintenance and explicit reset re-arm it. This reduces duplicate downstream notifications if a trusted dispatcher is connected. Commit `a6cf232ace96c8a0bf571f06021511b67818b849`.

**Test authored:** `Carthago.Tests/JournalCapacitySamplingGateTests.cs`, `SustainedLowSpaceConfirmsOnceUntilGateIsReset`, commit `17d4c9e560fc87b43395c90d2988f5e896f4f124`. **Tests executed: none.** No Windows runner/build, live capture, replay or qualification performed; compilation unverified.

**Unresolved integration:** R531 still requires a lifecycle-owned periodic scheduler, trusted clock and maintenance context, configured production thresholds, typed authenticated local-health admission, and actual RuleEngine predicate/event integration. R536 requires owned parser-counter producer, trusted attribution and engine binding. Packet text and journal write failures are not substitutes for OS-backed low-space evidence. **Functional repairs this run: zero.** Next cursor: carryover R531/R536 and remaining blocked IDs; no new ordered IDs.


## Carryover R531 — duplicate scheduler-tick suppression (2026-11-18)

**Status:** IN-PROGRESS / PRODUCER-BLOCKED; **functional detector completions: 0**. Ordered review cursor exhausted; no new ten-ID batch and no carryover item marked implemented.

**Actual production fix:** `JournalCapacitySamplingGate.TrySample` previously called `ResetCore` when an otherwise valid scheduler tick repeated the last accepted UTC timestamp. That reset cleared the one-shot low-space episode flag, allowing a later pair of low readings to emit a duplicate confirmation without recovery. Identical timestamps now return no sample without modifying the existing confirmation state; strictly backward clocks still reset fail-closed, and maintenance still resets. Commit `4e9201822d3de40f00acea1f6f06fcd904c7b124`.

**Regression authored:** `Carthago.Tests/JournalCapacitySamplingGateTests.cs` adds `DuplicateTickDoesNotRearmConfirmedLowSpaceEpisode`, commit `1a28f82e5da8300978f6cb47ba2662208baa9b38`. **Tests executed: 0.** No local Windows runner or build, native capture, GitHub Actions, invasive tests or force push. Compilation unverified. No change to R102/R118/R163 floors or frozen holdout.

**Outstanding R531:** production-owned scheduler, trusted clock/maintenance context, threshold policy, typed authenticated health-event delivery and actual RuleEngine admission. **R536:** owned parser counters and engine binding. **Next cursor:** unresolved carryover R531/R536 and remaining blocked IDs; no new ordered IDs. This is a sampling integrity fix, not a functional detector completion.


## Carryover engineering increment — 2026-11-18 (R531)
- **Status:** IN-PROGRESS / PRODUCER-BLOCKED; **functional detector repairs: 0**. The fixed 187-ID review cursor remains exhausted; this work revisits R531 and does not claim a new ten-ID batch.
- **Production source:** `Carthago/Services/Journaling/JournalCapacitySamplingGate.cs` now accepts an optional capacity-reader delegate for deterministic testing; default production behavior remains OS capacity sampling via its owned `DetectionJournal`. Rejects impossible samples (negative free, zero total, free greater than total), resetting confirmation state. This is **not** a trusted event admission mechanism; external delegates must not be accepted as authenticated health telemetry.
- **Tests authored:** `Carthago.Tests/JournalCapacitySamplingGateTests.cs` adds deterministic low/healthy/recovery episode coverage and invalid-capacity fail-closed coverage, avoiding host-disk-dependent early returns. **Tests executed: none; compilation unverified** (no Windows runner).
- **Commits:** production `eb13b62bbe3279028758114238d605cfa156a418`; tests `02b923f0aa534bc85234ca9e01efc4e476867214`; ledger commit is the commit containing this entry.
- **Still required R531:** lifecycle-owned periodic sampling, configured policy/maintenance ownership, authenticated typed local-health event and RuleEngine admission; do not infer detection from a test-injected capacity delegate or packet text.
- **Still required R536:** owned parser counters with trusted provenance, runtime producer and RuleEngine connectivity.
- **Next cursor:** ordered 187-ID review exhausted; revisit producer-blocked carryover, beginning with R531 and R536. No blocked ID counted complete.


## Carryover R531 — capacity classification integrity (2026-11-18)

**Status:** IN-PROGRESS / PRODUCER-BLOCKED; **functional detector completions: 0**. The ordered 187-ID review cursor is exhausted, not the implementation backlog. No new ordered ten-ID batch was selected; revisit R531/R536 and remaining producer-blocked IDs.

**Source change:** `Carthago/Services/Journaling/JournalCapacitySamplingGate.cs` now independently recomputes the configured two-threshold low-space classification from the sampled available/total bytes, and resets fail-closed if a capacity reader's claimed Low flag disagrees. This prevents a contradictory reading from advancing a two-sample confirmation episode. The default production reader remains the OS-backed journal-volume probe; no packet-derived telemetry or detector promotion. Commit `d7668595818e40cff9026d5bd12f08631774637f`.

**Regression authored:** `Carthago.Tests/JournalCapacitySamplingGateTests.cs`, `ContradictoryLowFlagCannotConfirmOrPreservePendingEpisode` covers contradiction, reset and fresh two-reading confirmation. Commit `7d01501d8be3e56728878b11bde2bfe197cfd4e1`. **Tests executed: none.** No Windows runner/build available in this execution; compilation unverified. Ledger commit: the commit containing this entry.

**Still missing:** R531 lifecycle-owned scheduler, trusted maintenance/clock policy, production threshold configuration, typed authenticated local-health event admission and RuleEngine integration. R536 requires owned parser-failure numerator/denominator metrics, stable parser attribution, bounded rate baseline and RuleEngine connectivity. Neither is functionally complete. No precision floors or frozen holdout modified.

**Next cursor:** carryover R531/R536 and other producer-blocked IDs; no new ordered IDs. 


## Carryover R531 — journal probe IO/access failure boundary (2026-11-18)

**Status:** IN-PROGRESS / PRODUCER-BLOCKED. Functional detector completions: **0**. The ordered 187-ID inspection cursor is exhausted; this is a carryover repair, not a new ten-ID batch.

**Production source:** `Carthago/Services/Journaling/JournalCapacitySamplingGate.cs` now treats IO, unauthorized access and security exceptions from the capacity probe as unknown capacity and resets pending confirmation rather than allowing the exception to escape the sampling gate or retaining stale evidence. This does not treat a failed journal probe as proof of low disk. Production commit `e90013c3bd0ec9452e91295a556769540f47a1f1`.

**Regression source authored:** `Carthago.Tests/JournalCapacitySamplingGateTests.cs` adds `JournalProbeIOExceptionResetsPendingLowSpaceEpisode`, requiring a fresh pair of readings after an IO failure. Test-source commit `caebb690c9924be31f2090e737c7bf326dddd342`. **Tests executed: 0; compilation unverified.** No local Windows runner, GitHub Actions or live invasive tests used.

**Unresolved:** R531 still requires lifecycle-owned periodic sampling, authenticated maintenance/clock context, configured thresholds, typed health-event admission and RuleEngine integration. R536 still requires owned parser numerator/denominator counters, trusted parser attribution and engine admission. Neither is functionally complete. No precision floors or frozen holdout modified.

**Next cursor:** carryover R531/R536 and other producer-blocked IDs; no new ordered IDs. Ledger update commit is the commit containing this entry.


## Carryover R531 — lifecycle-bound capacity polling prerequisite (2026-11-19)

**Status:** IN-PROGRESS / PRODUCER-BLOCKED; **functional detectors completed: 0**. Ordered 187-ID review cursor remains exhausted; no blocked ID promoted and no new ten-ID batch claimed.

**Source authored:** `Carthago/Services/Journaling/JournalCapacityMonitor.cs` (commit `f49fc110c971d032a971d222c91497f7aa1c8b52`). Internal `PeriodicTimer` polling loop binds a journal-owned OS capacity reader through the existing two-reading gate, accepts application-owned cancellation, and resets pending evidence if the maintenance-policy provider fails. This is a **non-wired prerequisite**: it has no startup registration, no trusted policy provider, no authenticated event admission and no RuleEngine dispatch. Its callback must not be treated as a detection or trusted provenance by itself.

**Tests authored: 0; tests executed: 0.** No local Windows runner, build, GitHub Actions or invasive tests; compilation unverified. Existing R102/R118/R163 floors and frozen holdout not modified.

**Required before R531 functional:** production lifecycle ownership, configured byte/percent/interval policy, trusted maintenance context, provenance-protected typed health event, dedicated RuleEngine admission and positive/benign-negative regression tests. **R536:** parser attempt/failure counters and trusted engine integration remain missing. **Next cursor:** R531/R536 and remaining producer-blocked carryover, no new ordered IDs. Ledger commit is the commit containing this entry.


## Carryover R531 — monitor shutdown and failed-handoff safety (2026-11-19)

- **Status:** IN-PROGRESS / PRODUCER-BLOCKED. Functional detectors completed: **0**. The fixed ordered inspection cursor is exhausted; this is carryover, not a new ten-ID batch.
- **Production source changed:** `Carthago/Services/Journaling/JournalCapacityMonitor.cs` in commit `c4bb5b1ac1a027d8d9f454d1ad7f8639abff5a20`. The polling loop now treats application cancellation as normal shutdown and clears the gate in `finally`. A failed confirmation handoff resets the gate and rethrows instead of retaining an acknowledged low-space episode. This is lifecycle integrity only; the callback is not authenticated RuleEngine admission.
- **Tests authored: 0. Tests executed: 0.** No local Windows runner/build; compilation unverified. No GitHub Actions, invasive tests, force pushes, precision-floor changes or frozen holdout changes.
- **Still missing R531:** actual startup ownership, production policy and trusted maintenance context, provenance-protected typed health event and RuleEngine evaluation, plus positive and benign-negative tests. **R536:** owned parser attempt/failure counters and typed engine admission. Other producer-blocked IDs remain carryover; do not mark any implemented.
- **Next cursor:** unresolved carryover R531/R536 and other blocked IDs; no new ordered IDs. Ledger commit is the commit containing this entry.


## Carryover R531 — monitor lifecycle contract regression (2026-11-19)

**Status:** IN-PROGRESS / PRODUCER-BLOCKED; functional detectors completed: **0**. The ordered 187-ID inspection cursor remains exhausted; unresolved producer carryover is not complete. This run adds a narrowly scoped monitor contract test but **does not** establish startup registration, typed health-event admission, or an R531 detector-positive.

**Changed test source:** `Carthago.Tests/JournalCapacityMonitorTests.cs`, commit `6c3b859e154a73f6bd0f35b8de6752c13005a04b`. Two xUnit facts authored: already-cancelled owner token must terminate without sampling/delivery; invalid cadence and missing maintenance/delivery callbacks must fail construction. **Tests authored: 2; tests executed: 0.** No Windows runner or local build available; compile and execution unverified. No GitHub Actions, live invasive tests, force pushes or precision-floor/holdout changes.

**No production source change in this run.** R531 still requires application lifecycle wiring, owned policy/maintenance provenance, configured thresholds and dedicated typed RuleEngine health-event evaluation. R536 still requires trusted parser-attempt/failure counters, parser identity and engine integration. No blocked ID promoted. **Next cursor:** R531/R536 and remaining producer-blocked carryover; no new ordered IDs.
