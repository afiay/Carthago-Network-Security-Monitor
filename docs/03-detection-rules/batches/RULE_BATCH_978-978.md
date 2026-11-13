# R978 — Modbus FC20 bulk file-record response
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow; source and tests authored only.

Owner workbook R2797 / AN2244 T0893: https://attack.mitre.org/detectionstrategies/DET0749#AN2244
Protocol: Modbus Application Protocol Specification V1.1b3 section 6.14: https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf

Workbook inspected directly: bulk retrieval of configuration, program or data-record objects from unauthorized sources outside established operational profile; approved backups/polling/inventory suppressed. This candidate only observes one bounded wire exchange, NOT those policy gates or content identity.

Exact complete IPv4 TCP/502 first SYN-anchored FC20 single subrequest, MBAP protocol ID 0, unit 1–247, request byte count 7/reference 6, file nonzero, record 0–9999, quantity 100–120, range within 10000. First server response exact length 11+2*quantity, FC20, matching transaction/unit, byte count 2*quantity+2, subresponse length 2*quantity+1, reference 6. Same flow, exact TCP sequence/opposite ACK, <=30 seconds. No file number, record address or returned data retained; pending transaction/unit/quantity/time only. Reset on SYN/reuse, FIN/RST, TLS, gap, retransmission, additional payload and expiry. PSH/ACK standalone plaintext frames; no reassembly. Legitimate approved maintenance can match; no authorized-source or operational deviation claim. Quantity 100–120 is a narrow engineering threshold, not protocol-wide or validated anomaly.

Dedup: R974 rejected FC03 oversized read; R968 FC06 write burst; R653/R871 fanout; no prior exact FC20 single-subrequest/response in live registry. Existing predicates unchanged. Overlap with other broad observations is not independent incidents.

45 authored xUnit cases: three capture positives, 26 benign/malformed cases, 12 session cases, four facts (timeout/one-shot, scope/forgery/contradictions, state, registry). Synthetic only; Windows compilation/execution and independent capture/authorization baseline pending.

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R978ModbusBulkFileReadQualityTests|FullyQualifiedName~R974ModbusOversizedReadQualityTests|FullyQualifiedName~R968ModbusSameRegisterQualityTests"
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release
```

Next R979 subject to live registry. Prior qualification obligations unchanged.
