# Active sensors — AS-01 TCP exposure

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
AS-02: scoped DNS integrity with expected-answer evidence and timeout handling.
AS-03: TLS certificate identity/validity from approved endpoints (no global trust bypass).
AS-04: HTTP health without redirects outside scope. Later: durable exposure snapshots and change detection with explicit baseline approval, active-origin evidence isolation, and opt-in scheduling. Do not promote detection rules on these observations until producer and replay contracts are tested.
