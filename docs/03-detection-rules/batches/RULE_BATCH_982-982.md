# R982 — public Modbus FC22 all-zero mask write request
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow; source and tests authored only.

Owner workbook R2714 / AN1908 T0836: https://attack.mitre.org/detectionstrategies/DET0776#AN1908
Protocol: Modbus Application Protocol Specification V1.1b3 section 6.16: https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf

Workbook inspected directly: parameter/setpoint write outside safe operating range or unauthorized write source, corroborated by historian drift and operational context. This candidate only observes a narrow request. No unsafe register meaning, accepted write or drift inferred.

Exact 14-byte complete IPv4 TCP/502 first SYN-anchored client payload, PSH/ACK, complete IP, contiguous normalization, non-TLS, MBAP protocol 0 length 8 unit 1–247, FC22, AND mask 0 and OR mask 0. Result formula (current AND AND_mask) OR (OR_mask AND NOT AND_mask) yields zero independent of current. No register, transaction, unit or raw payload retained. Other mask combinations, other functions, fragmented/coalesced/midstream/response requests excluded; no server acknowledgment required or inferred. Authorized reset and initialization may match. Public-to-private scope; no approved source or safe range inferred.

Dedup: R240 generic write observations may overlap; R968 FC06 same-point five-connection burst; R974 rejected FC03 read; R978 FC20 file read. Exact FC22 mask predicate distinct. Existing rule behavior unchanged. No independent incident claim on overlaps. Promotion requires device register mapping, independent capture controls, authorization and operational evidence.

23 authored cases: three positive boundaries, 15 negative frames, five facts for TCP/session/scope, datagram integrity, forgery/contradictions, state and registry. Synthetic only; Windows compilation/execution pending.

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R982ModbusClearMaskWriteQualityTests|FullyQualifiedName~R968ModbusSameRegisterQualityTests|FullyQualifiedName~R974ModbusOversizedReadQualityTests|FullyQualifiedName~R978ModbusBulkFileReadQualityTests"
```

Next R983 subject to live registry.
