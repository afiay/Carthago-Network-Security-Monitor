# R974 — Modbus oversized FC03 read with matching exception
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow; source and tests authored only.

Owner workbook R2790 / AN2288: https://attack.mitre.org/detectionstrategies/DET0767#AN2288
Protocol: Modbus Application Protocol Specification V1.1b3, sections 6.3 and 7: https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf

Exact complete IPv4 TCP/502, observed SYN/SYN-ACK, first client function 03 request (12-byte MBAP/PDU, protocol ID 0, unit 1–247, quantity 126–65535), first server exception response (9 bytes, 0x83/0x03), matching transaction and unit, same flow, sequence/ACK contiguous and <=30 seconds. No raw data, register address or quantity retained; pending transaction/unit/time only. One-shot correlation, reset on SYN/reuse, FIN/RST, TLS, gaps, retransmission, additional client payload and expiry. Narrow PSH/ACK and standalone frames only. No proof of exploitation, authorization, device identity or impact; misconfigured clients and legitimate robustness tests may match.

Dedup: R240 and R968 concern write operations; R653 and R871 concern non-write host/payload fanout. R974 is a specific rejected oversized read transaction; no predicate changed. Not a claim that a rejected read indicates compromise.

39 authored xUnit cases: three positive boundaries, 20 benign/malformed exchanges, 12 correlation/reset controls, four facts for timeout/one-shot, scope/forgery/contradictions, cooldown/isolation and registry. Synthetic only; Windows execution and independent capture validation pending.

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R974ModbusOversizedReadQualityTests|FullyQualifiedName~R968ModbusSameRegisterQualityTests|FullyQualifiedName~R973OpcUaHelloAckQualityTests"
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release
```

Next R975 subject to live registry. Existing qualification obligations unchanged.
