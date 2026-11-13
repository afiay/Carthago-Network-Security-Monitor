# Active sensors — AS-01 through AS-10

Status: source candidate; Windows build, tests and live smoke pending.

## Existing capability
LocalLanDiscovery and NpcapArpDiscovery already implement bounded local IPv4 ARP and ICMP discovery. SensorIdentity/SensorRegistry are fleet identity and heartbeat primitives, not active scanning.

## AS-01
Select a LAN host filter using Scan LAN or Add IP, stop monitoring, then right-click the capture-source selector (or Shift+F10) and choose Check TCP exposure. The owned dialog shows target and adapter and requires an explicit Run authorized check action. Close cancels outstanding work. One local IPv4 peer, 12 fixed TCP ports, sequential attempts, 750 ms per-port budget; no application payload, credentials, DNS resolution or public targets. Source socket binds to the selected local IP; this is not a guarantee of physical interface routing on every multihomed Windows system.

Open means a TCP handshake completed. Refused means the connection was explicitly refused, not proof of a particular host configuration. Timeout, unreachable and other errors are distinct and inconclusive. No application protocol or vulnerability is inferred. Results remain in the dialog and are not injected as TrafficRecord/DetectionEvent or automatically persisted. Remote observers may see the connections; use only authorized hosts.

## Verification
PowerShell from repository root:

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~TcpExposureSensorTests|FullyQualifiedName~LocalLanDiscoveryTests|FullyQualifiedName~LanCaptureDiscoveryTests"
```

Expected checks include scope rejection, fixed port list, distinct outcome classification, timeout, cancellation, and source address propagation. No live probe is executed by these unit tests. On Windows, manually select an authorized LAN lab host with a known listening service and a refused port; verify result statuses, UI cancel, and that active capture prevents the check.

## Next
Later: durable exposure snapshots and change detection with explicit baseline approval, active-origin evidence isolation, and opt-in scheduling. Do not promote detection rules on these observations until producer and replay contracts are tested.

## AS-02 — DNS integrity

Select an authorized LAN resolver using Scan LAN or Add IP, stop monitoring, then use the capture-source context menu: Check DNS integrity. Enter an ASCII/punycode hostname and optionally up to 16 independently verified IPv4 addresses. One source-bound UDP IN/A query to port 53, random transaction ID, two-second timeout, no retries, no search suffix or implicit hostname. Connected UDP filters source endpoints; transaction ID, question, type/class and response flags must match. Existing strict DnsAddressObservationInspector validates full framing and CNAME-linked answer ownership. Distinguish exact set match/difference, observation without baseline, NXDOMAIN, NODATA, DNS errors, truncation, invalid response and transport failure. A difference is not poisoning proof; CDN/split-horizon may legitimately vary. No DNSSEC validation, EDNS extended RCODE interpretation, TCP fallback, AAAA, persistence, scheduled querying or detection promotion yet. A resolver may forward the name externally.

Windows verification pending:

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~DnsIntegritySensorTests|FullyQualifiedName~DnsWireNameCodecTests|FullyQualifiedName~DnsAddressEnrichmentTests|FullyQualifiedName~TcpExposureSensorTests"
```

Unit tests use synthetic responses; manual lab check should include known A answers, NXDOMAIN, timeout and cancellation.

## AS-03 — TLS inspection

Select a LAN host with Scan LAN/Add IP, stop monitoring, and choose Inspect TLS certificate from the capture-source context menu. Select direct TLS port 443, 8443, 5986, 636 or 8883, enter the expected DNS identity and optionally an independently verified 64-hex SHA-256 leaf fingerprint. One source-bound TCP/TLS handshake, five-second overall cancellation budget, no DNS resolution, application data, client credentials, or trust-store changes. OS-selected protocols; negotiated protocol/cipher reported only after successful authenticated handshake. Strict platform hostname/chain validation; certificate callback records leaf metadata even when rejecting, never accepts policy errors or treats a fingerprint match as a trust override. Chain policy disables certificate downloads and revocation checks (revocation status unknown). No claim of exhaustive TLS version support, STARTTLS, IP SAN identity, revocation or persistent fingerprint history.

Windows validation pending:

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~TlsInspectionSensorTests|FullyQualifiedName~TlsIdentityEnrichmentTests|FullyQualifiedName~DnsIntegritySensorTests|FullyQualifiedName~TcpExposureSensorTests"
```

Tests include local scope/port/name validation, fingerprint and validity evidence, strict rejection, cancellation, and isolated loopback TLS rejection/timeout. Manual Windows smoke: approved trusted TLS endpoint and self-signed/mismatched certificate; verify no trust override, no application payload, and no protocol/cipher claims on rejected handshakes. No detector promotion or persistence.

## AS-04 — HTTP/HTTPS health

Select an authorized LAN host, stop monitoring, and choose Check HTTP/HTTPS health from the capture-source context menu. Supply the expected ASCII/punycode DNS hostname for Host/SNI; select 80/8080 (HTTP) or 443/8443 (HTTPS). One source-bound TCP connection, one HEAD / HTTP/1.1 request, five-second overall cancellation budget, no DNS resolution, proxy, redirects, cookies, credentials or intentional body reads. HTTPS requires the same strict platform trust as AS-03 before writing the request; no certificate downloads or revocation checking. HTTP/1.0 and HTTP/1.1 final status codes 200–599 are supported; interim 1xx, HTTP/2, malformed, incomplete, oversized (16 KiB) or excessive (>128) headers are inconclusive. Selected security headers are recorded as observed values (including duplicates), not evaluated as secure; report-only CSP is separate. Redirects 301/302/303/307/308 are classified by URI origin only, never followed; destination text, cookies and unselected headers are not retained in observations. Origin equivalence is not a DNS/route authorization check. No body download, application login, persisted baseline, detection promotion or vulnerability finding. A HEAD rejection may reflect method policy rather than service unavailability.

Windows verification pending:

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~HttpHealthSensorTests|FullyQualifiedName~TlsInspectionSensorTests|FullyQualifiedName~DnsIntegritySensorTests|FullyQualifiedName~TcpExposureSensorTests"
```

Unit and isolated loopback tests cover scope, request construction, response framing, selected headers, redirect classification, header budget, timeout and cancellation. Manual Windows smoke: trusted HTTPS endpoint, invalid certificate (no HTTP request), HTTP redirect and HEAD rejection. No test execution claimed.

## AS-05 — Gateway integrity

Select an active Wi-Fi/Ethernet Npcap adapter (or its LAN host filter), stop monitoring, and choose Check gateway integrity. Select a configured IPv4 gateway/source pair in the existing private local /24 intersection; no arbitrary targets or IPv6. Revalidate adapter/address/gateway at execution. Optionally enter an independently verified expected unicast MAC; no automatic baseline acceptance. Read scoped Windows neighbor cache before the probe (missing/error means not established), then send two directed-target Ethernet broadcast ARP requests and collect replies for 350 + 850 ms. Only replies matching gateway IP, local IP, local Ethernet/ARP destination MAC, and consistent unicast Ethernet/ARP source MAC count; one VLAN tag supported. Retain up to 16 distinct claims and overflow indication. No reply, single observation, baseline match/difference and conflicting claims are distinct; cache mismatch separately reported. ARP has no transaction ID or authentication, so these are claims in a probe window, not cryptographic proof of gateway identity or causality. No auto-blocking, persistent baseline, traffic injection or detector promotion. The modal dialog waits for capture cleanup before releasing the main window on cancellation.

Windows validation pending:

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~GatewayIntegritySensorTests|FullyQualifiedName~NpcapArpDiscoveryTests|FullyQualifiedName~WindowsLanArpResolverTests|FullyQualifiedName~LocalLanDiscoveryTests"
```

Synthetic frame tests cover strict source/destination matching, VLAN, unrelated frames, cache-only evidence, duplicate versus competing claims, baseline and overflow. Live Npcap smoke required: authorized gateway, selected adapter, cancellation/cleanup, and isolated lab conflicting claims. No execution claimed.

## AS-06 — SNMPv3 infrastructure

Select an authorized LAN SNMP agent, stop monitoring, choose Check SNMPv3 infrastructure, supply a read-only USM user and SHA-256/AES-128 passphrases. Source-bound connected UDP port 161, one engine discovery and one authPriv GET, five-second overall cancellation budget, bounded 8192-byte datagrams. No v1/v2c fallback, SET, walk, retries, credential storage or diagnostic logging. Carthago does not persist credentials, but managed strings and SharpSnmpLib's internal key cache can retain secret material in process memory; no zeroization guarantee. Discovery reports are unauthenticated and never supply inventory. Require an actual encrypted scoped PDU (not just flags), USM security model and matching message/request IDs, engine/user/context, authPriv flags, SHA-256 digest and AES salt lengths, library hash validation and engine boots/time window before projecting exact requested OIDs in order. Reports, error responses, missing/wrong-type values and transport failures are separate from complete observations. sysUpTime is agent uptime in centiseconds, not proof of device reboot. Initial scope: five fixed scalar objects (sysDescr, sysObjectID, sysUpTime, sysName, ifNumber). Interface tables, counters, vendor health, time resynchronization, persistent baselines and scheduling deferred.

Windows verification pending:

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~SnmpInfrastructureSensorTests|FullyQualifiedName~SharpSnmpClientAdapterTests|FullyQualifiedName~SnmpClientAdapterTests"
```

Unit tests cover input scope, credentials, exact OID projection and types, library-generated authPriv wire messages, tampered digest, wrong engine/user/context/request IDs and plaintext downgrade. Before qualification, run an authorized SNMPv3 SHA-256/AES lab agent and verify correct credentials, wrong authentication/privacy, wrong engine/context, tampered digest, downgrade, timeout and cancellation on real wire. No runtime verification claimed.

## AS-07 — Active evidence history

Each of the six manual dialogs has an unchecked opt-in Save completed observation to local active history checkbox. Only completed observations (including inconclusive probe outcomes) are eligible; cancelled or thrown requests are not saved. One row per inspection, including the complete fixed-port TCP batch. Separate per-user %LOCALAPPDATA%/Carthago/active-evidence.db LiteDB, collection active_observations; version, ActiveProbe origin, GUID observation and adapter identity, source/target, probe key, UTC ticks, status and typed projected JSON. No TrafficRecord, rule, passive baseline or detection insertion. No credentials, packet bytes, raw HTTP header values, TLS subject/issuer/SAN or SNMP free text stored; SHA-256 hashes of selected HTTP values and SNMP name/description support comparison (not anonymization). DNS query name, local IP/MAC and certificate fingerprint remain sensitive local metadata. No automatic trust or baseline approval. Insert and retention in one transaction; duplicate IDs rejected, max 5,000 rows and 30 days, prune on save/read, 16 KiB payload, up to 200 results per exact sensor/target query. Database file size may not shrink immediately after pruning. Per-operation handles and in-process gate; storage errors displayed separately from probe outcomes. History menu displays projected JSON; no background scheduling, multi-process writer coordination beyond LiteDB locking, encryption at rest or export yet.

Windows verification pending:

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~ActiveEvidenceStoreTests|FullyQualifiedName~LocalStoreLifecycleTests"
```

Tests cover persistence, duplicate IDs, retention, filters, invalid rows, storage failure and all six projections. Manual smoke: opt in/out, reopen history, confirm failure is not reported as saved, verify no secrets or passive detection events. No runtime verification claimed.

## AS-08 — Session-scoped active sensor manager

Select one authorized LAN host, stop monitoring and finish discovery, then open Active sensor manager (session) from the capture-source context menu. Explicitly approve up to 16 distinct TCP/DNS/TLS/HTTP profiles for that target, with adapter GUID/source/mask, endpoint, 5 min–24 h interval and optional history. Start is explicit; first due checks start immediately, one at a time, with a one-second tick between checks. No stored profiles, auto-start, background service, credentials or arbitrary target expansion. Revalidate current adapter/source/mask/local scope on every run; scope change blocks profile until removed and reapproved. Subsequent checks run after completion, no catch-up bursts. Nonresponsive results back off by 2^failures (max factor 32, cap 24 h); responsive results reset failures, not a claim of security or application health. Store completed evidence only when opted in; storage failure separate from probe outcome. Cancel/stop waits for in-flight probe cleanup before dialog closes. Modal manager keeps this window's manual capture controls unavailable; other capture processes may observe active traffic. Gateway and SNMP remain manual-only pending exclusive Npcap ownership and credential lifecycle. No persistent scheduling or detection promotion.

Windows verification pending:

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~ActiveSensorManagerTests|FullyQualifiedName~ActiveEvidenceStoreTests|FullyQualifiedName~TcpExposureSensorTests|FullyQualifiedName~DnsIntegritySensorTests|FullyQualifiedName~TlsInspectionSensorTests|FullyQualifiedName~HttpHealthSensorTests"
```

Deterministic clock/transport tests cover explicit start, scope revalidation, single in-flight execution, duplicate/capacity bounds, interval/backoff, cancellation and history opt-in. Manual Windows smoke: approved host, start/stop, close during probe, scope change and persisted history. No runtime verification claimed.

## AS-09 — Approved active exposure comparisons

From Active sensor history select a retained observation and explicitly approve it as the comparison reference for its exact sensor/adapter/source/target/probe key. One approval per scope, max 128; references only, no duplicate payload and no automatic advancement. Approval requires usable evidence and cannot convert rejected TLS, conflicting gateway claims or inconclusive probes into references. Replacement requires confirmation. Compare a newer selected row to the approved retained observation; expired/evicted references are unavailable. No implicit baseline, no network action. Compare only definite TCP Open/Refused transitions, positive DNS A sets, observed TLS certificate fingerprint/validity/policy, final HTTP status and headers on successful responses, direct gateway MAC claims, and authenticated SNMP inventory fields. Missing/timeout/malformed evidence is not a negative finding; SNMP uptime is not reboot evidence. Changes are investigation observations, not attacks. No detection event or automatic blocking. History retention remains 30 days/5000 rows; approval metadata is local and bounded, not an authenticated trust store.

Windows verification pending:

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~ActiveChangeDetectorTests|FullyQualifiedName~ActiveEvidenceStoreTests|FullyQualifiedName~ActiveSensorManagerTests"
```

Tests cover explicit approval/replacement/expiry, exact scope, chronology, positive and inconclusive comparisons across six sensors. No test execution claimed.

## AS-10 — Qualified active finding pipeline

Every explicitly saved manual or scheduled observation is evaluated inside the same LiteDB transaction. A retained, explicitly approved reference for the exact sensor/adapter/source/target/probe scope must predate both confirmations; the two newest distinct observations after approval must contain the same AS-09 change (kind, field, before and after), at least one minute apart and within 24 hours. An intervening inconclusive, recovery or different result breaks confirmation; old or future observations cannot qualify. Separate ASD001–ASD011 identifiers (not registered R-series rules), Info/Low/Medium severity, Medium confidence in the observed change only. Deterministic SHA-256 identity over baseline/scope/change deduplicates while retained, even across process restart. New approved baseline or distinct transition has a new identity. Max 1000 findings / 30 days; evidence IDs, projected before/after, timestamps and scope retained; referenced observations can expire or be evicted independently. No packet/flow IDs, no attacker attribution, no passive-rule invocation, external delivery, automatic blocking or incident correlation. Project qualified persisted findings to the existing DetectionEvent contract for the separate Active sensor history inbox; Show qualified active findings applies sensor/target filters. No historical backfill; approve first, then save two new observations. Storage failure rolls back the observation and findings together. Runtime qualification and central incident integration remain separate gates.

Windows verification pending:

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~ActiveFindingQualificationTests|FullyQualifiedName~ActiveChangeDetectorTests|FullyQualifiedName~ActiveEvidenceStoreTests|FullyQualifiedName~ActiveSensorManagerTests"
```

Test positive repeat confirmation, distinct IDs, scope, timing, intervening recovery, no approval, retention, replay/deduplication, and DetectionEvent provenance. No runtime execution claimed.

## AS-Q01 / AS-Q02 — Local qualification gate

Run from the clean feature branch on Windows:

```powershell
.\verify-active-sensors.ps1
```

The script builds the actual Release test project (including its WPF app reference), then runs exactly the ten active sensor suites with --no-build/--no-restore. Fresh per-run TRX, build/test logs and qualification.json are written under ignored build-verify/active-sensors/<run-id>. Source SHA and clean-worktree checks prevent attributing stale results to a changed checkout. The gate checks suite-level minimum case counts (234 total as of AS-Q02), nonzero execution, no skipped/failed cases, TRX counters, exit codes and unchanged source. A pass means synthetic and isolated loopback qualification only; no live LAN probes are executed by this script.

AS-Q02 source review fixes manual TCP/DNS/TLS/HTTP/SNMP dialogs to hold their modal owner until cancelled work and any already-started storage operation finish. New saves are suppressed after a close request; an already-started transaction may finish. TCP now creates a per-run token rather than disposing it as the dialog closes. SNMP discovery requires a bound noAuthNoPriv report with usable nonnegative engine boots/time, empty user/auth/privacy parameters, consistent context engine, correct counter OID/type and zero error index. These are source changes with ten additional discovery tests; no Windows build or execution is claimed.

Live smoke gate: run only on explicitly authorized lab hosts. Record adapter/target and expected versus actual for TCP listening/refused/timeout, DNS known A/NXDOMAIN/timeout, trusted and untrusted TLS, HTTP 200/redirect/error, gateway direct claim and cancellation, and a real SHA-256/AES-128 SNMPv3 agent with valid/invalid credentials. Save two distinct matching changes after baseline approval and verify one active finding, no passive attack attribution. Close each dialog mid-probe and confirm owner stays blocked until cleanup. No production qualification until these checks are recorded.

## AS-Q03 — Live observation chronology and evidence integrity

Live persistence now rejects future timestamps (including the former five-minute tolerance), unknown/numeric status values and duplicate JSON property names at any depth. Exact sensor/adapter/source/target/probe scope must advance strictly in observation time; older or equal-timestamp arrivals cannot retroactively contradict already-confirmed findings. Independent scopes may still arrive in a different order. This is a deliberate live-ingestion policy, not a historical import facility. The store checks the LiteDB commit result before reporting success. Added five evidence-store cases and one finding regression case; qualification minimum is now 240 authored cases. Windows build/test execution remains pending.

## AS-Q04 — Isolated wire-to-finding laboratory

The qualification gate now includes ActiveSensorPipelineLabTests (5 cases; 245 total authored minimum across 11 suites). These tests use ephemeral loopback TCP/UDP listeners, the real sensor transport/parser, evidence projections, temporary LiteDB stores, an explicit approved baseline, deterministic test clock and the actual active finding qualification path. DNS uses an internal endpoint transport seam while the public sensor continues to require the selected LAN scope and fixed UDP 53. TCP uses the production connect-only transport for one mapped logical port; other port outcomes are synthetic. HTTP uses the existing internal endpoint seam. Test-only logical LAN identities and timestamps map these isolated exchanges to the normal storage scope; no production authorization bypass, real LAN scanning, fixed service port binding or trust-store modification is introduced.

Coverage: unchanged DNS answers produce no finding; changed answers traversing the scheduler produce exactly one ASD003 after two confirmations; real HTTP header removal produces ASD008; a malformed response interrupts confirmation; the TCP peer observes EOF without application bytes. All tests use bounded cancellation and dispose temporary listeners/databases. The script still reports liveNetworkValidated=false: these cases do not validate physical adapter binding, Npcap, actual SNMP agents, the Windows WPF UI or real infrastructure. No Windows execution is claimed.

## AS-Q05 — Persistence and lifecycle stress qualification

ActiveSensorLifecycleStressTests adds seven cases (252 authored minimum across 12 suites). Concurrent independent-scope saves and duplicate-ID races use separate store instances over one temporary database; all accepted observations must survive reopening. A test-only internal beforeObservationCommit callback injects an exception after observation and finding insertion, proving rollback of both and a successful retry. Finding indexes are prepared before the observation transaction; finding retention is transactional. Small-capacity pressure verifies that evicted references cannot qualify new findings. A corrupt temporary database must remain unavailable without being silently replaced. Scheduler tests cancel during scope resolution and during an already-started synchronous persistence operation; no new probe starts after cancellation, cleanup waits for the in-flight write, and the completed transaction is reported accurately. No arbitrary cancellation of a LiteDB commit is attempted. The scheduler rechecks cancellation after scope resolution and immediately before persistence.

These tests are authored, not executed. In-process serialization is not cross-process coordination; power-loss recovery, real disk exhaustion, Windows UI lifecycle and physical network qualification remain separate gates.

## AS-Q06 — Read-only incident investigation context

The Incident Command Center now exposes Load active sensor context inside the selected case. It searches retained qualified ASD findings whose **inspected target** equals one of the incident's recorded canonical local IPv4 source/destination addresses, within the recorded first/last observed time interval. No DNS resolution, text/hostname inference, probe-source matching, cross-network identity assumption or automatic association. Demo cases, missing endpoints and ambiguous/missing/reversed times are ineligible. Filters run before the cap; at most 50 newest results, each with finding/baseline/observation IDs, adapter, probe source and before/after. Selection changes and page unload invalidate pending results; no new network probes. This is read-only contextual retrieval, not a write to incident membership, timeline, risk, attack story, passive journal or external sinks. Local store retention limits apply, and two endpoint queries are not a cross-query atomic snapshot. Tests cover context bounds, probe-source exclusion, demo/time rejection, cap ordering and no incident mutation. Eight new cases; 260 authored minimum across 13 suites. Windows runtime verification pending.

## AS-Q07A — Persistent configuration, session authorization

The active sensor manager can save selected session profiles into a separate local LiteDB file (%LOCALAPPDATA%/Carthago/active-sensor-profiles.db), list saved configurations, reapprove one for the current selected live scope, and delete saved configurations. Maximum 64 configurations globally, 16 approved profiles per session. Stable configuration key covers adapter GUID, source, mask, target, sensor, hostname and port; saving the same key updates interval/history preference. Schema/version, canonical IPv4, contiguous mask, local scope, supported sensor/port, canonical hostname and whole-minute interval are validated on save and read. Invalid/corrupt storage fails closed. The key is an identity, not an authentication signature. No credentials, runtime status, execution authorization or auto-start state are persisted. Saved configurations are inactive on load, and explicit reapproval plus Start is required; current adapter/source/mask/target must match exactly, and every scheduled probe revalidates scope. Deletion removes only the stored configuration, not an independently approved session profile. The UI does bounded local database operations synchronously while stopped. This is a single-process storage policy; unattended service ownership, cross-process coordination and secure SNMP credential storage remain separate work.

Ten authored cases cover reopen and no execution on load, fresh session ID, four scope mismatches, invalid/manual-only profiles, identity/update/delete, capacity, corruption and tampered record identity. Qualification minimum 270 across 14 suites; Windows execution pending.

## AS-Q07B — Machine-wide scheduler ownership

Scheduled active monitoring now uses Global\\Carthago.ActiveScheduler.Reservation.v1 via the existing Windows named-object reservation implementation in Carthago.Contracts. The reservation is distinct from the passive capture reservation; it uses named mutex object existence, not thread-affine mutex ownership. The scheduler acquires before any probe, holds ownership across delays/probes/synchronous storage, and releases after the loop exits and outstanding work finishes. Acquisition failure refuses execution with a visible reason; no session-local fallback or automatic takeover. The OS closes the handle on process termination (the object disappears when its last handle closes). Concurrent RunAsync on the same manager, profile edits while the loop owns its state, and standalone ticks during the loop are rejected. Standalone ticks are restricted to injected-probe tests; production uses the reserved loop. The five new Windows cases cover native contention, cross-thread release, concurrent contenders, failed startup/retry, cancellation cleanup and pre-cancel/empty-loop gates. Existing shutdown stress test uses a random isolated reservation name. Minimum 275 authored tests across 15 suites.

This is cooperative exclusion for scheduled probes, not a security boundary against other processes, nor a guarantee of cross-process database coordination, manual probe exclusion or Npcap capture coordination. No actual separate-process crash test or Windows execution is claimed. Durable grants and service ownership remain separate.

## AS-Q07C — Durable execution authorization

A separate active_execution_grants collection in the saved-profile database stores a unique grant ID, configuration digest, issue/expiry UTC ticks and nullable revocation time. Maximum lifetime 24h. Grant issuance requires explicit operator confirmation and exact current saved configuration/live scope. A grant binds all execution parameters (stable profile identity plus schema, interval and history preference); edits and deletion invalidate it atomically, even when changed back. Reissue creates a new grant ID and cannot revive a previously loaded grant-bound session. Grant reads fail closed for missing, revoked, expired, future-issued, malformed or unavailable data. Grant-bound profiles check authorization after live scope resolution, after probe completion and before persistence. Revocation does not interrupt an already-started socket operation or database commit by itself; the desktop revoke action also requests scheduler cancellation. A separate session-only approval is unaffected. Loading a grant still requires explicit Start, and no startup task or service is installed. Current grant records are bounded by saved profiles; replacement/deletion does not preserve an immutable audit history. The digest is not a signature or a boundary against local database tampering; Windows user-file permissions and cooperative same-process locking remain the trust model. Cross-process transactional revocation and service-account access require later qualification. Nine new authored cases; 284 across 16 suites; Windows execution pending.

## AS-Q07D — Explicit foreground active worker

The existing Windows console host carthago-monitor now accepts active status [--json] and active run --profile ID [--profile ID ...]. Status is configuration-only, does not resolve adapters, acquire reservations or probe, and does not claim scheduler health. Run accepts 1–16 distinct exact configuration IDs; all must have a current durable grant and exactly matching live adapter/source/mask/target before execution. It reuses ActiveSensorManager.AddAuthorized, the machine-wide scheduler reservation and the normal evidence store. Ctrl+C cancels and awaits cleanup; the loop exits when all selected profiles are blocked or the latest selected grant expires. No renewal, automatic discovery, automatic startup, new credentials or service installation. Exit codes: 0 status/expiry stop, 2 syntax, 3 invalid/unavailable/blocked/ownership failure, 130 operator cancellation. Same Windows user and local app-data store as desktop; the monitor still references the Windows desktop assembly/runtime, but no WPF window is initialized. This is not a service-account deployment or passive/active capture coordinator. Seven authored tests; 291 minimum across 17 suites. The qualification script also builds Carthago.Monitor explicitly. Windows runtime execution pending.

## AS-Q07E1 — Current-user SNMP credential vault

Manual SNMPv3 inspection can explicitly save/replace/delete credentials in %LOCALAPPDATA%/Carthago/snmp-credentials.db and opt in to use a stored credential for a manual GET. Windows DPAPI CurrentUser encrypts username/auth/privacy together; the payload binds exact adapter GUID/source/mask/target/UDP161 scope and a fresh generation through DPAPI optional entropy. Metadata exposes only scope hash/generation/version and ciphertext; no credentials in normal profiles, evidence, CLI, logs or status. Maximum 64 records. A stale generation cannot load a replacement; copied ciphertext fails scope/generation binding. Clear temporary plaintext byte buffers; immutable managed strings and SharpSnmpLib internals cannot guarantee zeroization. The vault is not protection against same-user code execution, database rollback, memory inspection or forensic recovery of old ciphertext. Deletion is logical, not secure erasure. No grant or scheduled SNMP profile is enabled in this stage, so there is no existing SNMP grant to invalidate; later scheduling must bind the credential generation and recheck it before transport. Same-user Windows runtime qualification pending. Seven authored cases; 298 minimum across 18 suites.

## AS-Q07E2 — Credential-bound scheduled SNMPv3

SNMP profiles are canonical (UDP161, empty hostname), saved without credentials and cannot be added by session-only approval. The desktop Add action saves configuration only; Grant requires an explicitly confirmed current credential generation and successful DPAPI decryption. Grants store the generation (non-SNMP grants retain null); every validity check compares it with the exact scoped vault record. The scheduler decrypts only the grant-bound generation, rechecks permission immediately before transport, invokes the existing read-only authPriv sensor, and rechecks before persistence. The headless worker uses the same profile/grant/manager path; status contains no secret or generation. Rotation/deletion invalidates the old grant without requiring cross-database transactional deletion; issuing a fresh grant is explicit. A credential rotation or revocation after transport starts cannot undo that operation. Corrupt ciphertext blocks before transport even if metadata still exists. No auto-start, service account or Npcap changes. Seven authored tests; 305 minimum across 19 suites. Windows runtime and real-agent interoperability pending.
