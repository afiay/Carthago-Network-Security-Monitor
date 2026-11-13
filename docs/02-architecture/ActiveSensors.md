# Active sensors — AS-01 through AS-04

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
