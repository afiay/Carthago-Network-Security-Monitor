# R987 — public EtherNet/IP CIP Identity Reset
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow; tests authored, zero executed.

Owner workbook R2697 / AN1933 T0816: https://attack.mitre.org/detectionstrategies/DET0801#AN1933
Workbook inspected directly: restart/reset command from unapproved engineering workstation, change control and corroborating device/process-state effect. Not the SIPROTEC exploit precedent; this is a distinct CIP request projection.

Requires R986's verified TCP handshake and successful RegisterSession request/response (28 bytes each). Exactly the next client payload within 30 seconds, 47-byte SendRRData 006F, encapsulation length 23, matching nonzero handle, status/options/interface zero, timeout 0–30, two CPF items (null address, unconnected data B2 length 7), CIP service 05, two-word path 20 01 24 01, explicit reset type 0. No raw session handle or context emitted; bounded transient handle/time only. Exact contiguous sequence/ACK and full standalone payload; no general reassembly. State consumed once, reset on SYN reuse, FIN/RST, TLS, invalid sequence, replay, intervening payload. Registration alone is R986 not R987; existing R986 behavior preserved. R489 ForwardOpen and R980 DNP3 restart distinct. No accepted reset, actual power cycle, device role, authorization or outage inferred. Legitimate recovery and commissioning may match. Independent captures, device model, approval and operational state required for promotion.

43 authored xUnit cases (3 positives, 21 malformed/ordinary CIP, 15 session controls, 4 facts: registration/timeout, scope/forgery, cooldown and registry). Windows compilation/execution pending.

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R987EtherNetIpIdentityResetQualityTests|FullyQualifiedName~R986EtherNetIpRegisterSessionQualityTests|FullyQualifiedName~R983FinsNodeNegotiationQualityTests"
```
Next R988 subject to live registry.
