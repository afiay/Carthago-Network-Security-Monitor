# R983 — private FINS/TCP node negotiation with public client
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow; tests authored, zero executed.

Owner workbook R2782 / AN2253 T0883: https://attack.mitre.org/detectionstrategies/DET0796#AN2253

Original workbook directly inspected: native-protocol connection accepted from external address, explicitly Omron FINS, and approved communications/asset-role policy gates. Narrow protocol-reachability projection only. Complete IPv4 TCP/9600 SYN and matching SYN-ACK, first client PSH/ACK FINS command 0 (20 bytes, length 12, error 0, requested node 0–254), first server PSH/ACK command 1 (24 bytes, length 16, error 0, assigned client and server nodes 1–254 distinct, requested explicit node matches). Exact connection/sequence/opposite ACK and 30 seconds inclusive. No raw payload retained; one pending requested node and time in bounded flow. No authentication, FINS memory access, policy violation or OT asset inventory claim. Narrow standalone plaintext packets, no general stream reassembly. Legitimate remote engineering may match.

SYN/SYN-ACK verification is local to FINS; earlier rules' TCP semantics unchanged. Reset pending state on SYN reuse, FIN/RST, TLS, invalid sequence and replay. R684 TCP OPC UA exchange and R973 OPC UA HEL/ACK are separate protocol predicates. No existing exact FINS node negotiation in registry.

40 authored xUnit cases (3 positive, 19 malformed/other response, 14 session and 4 facts for timeout/one-shot, scope/forgery, state, registry). Includes incorrect SYN-ACK acknowledgement. Windows compilation and execution, independent wire captures and approval/asset policy remain pending.

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R983FinsNodeNegotiationQualityTests|FullyQualifiedName~R973OpcUaHelloAckQualityTests|FullyQualifiedName~R978ModbusBulkFileReadQualityTests"
```
Next R984 subject to live registry.
