# Active sensors — AS-01 through AS-09

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
