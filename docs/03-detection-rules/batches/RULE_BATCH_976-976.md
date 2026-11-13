# R976 — public SNMP connection-table GETNEXT
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow; source and tests authored only.

Owner workbook R2791 / AN2184 T0840: https://attack.mitre.org/detectionstrategies/DET0770#AN2184
Protocol: RFC 1213 MIB-II https://www.rfc-editor.org/rfc/rfc1213.html ; RFC 3416 GETNEXT https://www.rfc-editor.org/rfc/rfc3416.html#section-4.2.2

Exact complete IPv4 UDP/161 SNMPv1/v2c GETNEXT (A1) with exactly two distinct legacy MIB-II table roots tcpConnTable (1.3.6.1.2.1.6.13) and udpTable (1.3.6.1.2.1.7.5), in either order, empty NULL values, canonical request ID, zero error/index, 20–4096 bytes. No raw community, OID or ID retained. This is an initial table-root request, not a completed walk, returned data, asset identity or NMS authorization. Modern TCP/UDP-MIB tables and other walk roots excluded. Workbook explicitly requires unauthorized source role plus operational deviation and suppression of approved polling/commissioning; this rule does NOT satisfy those gates, stays Shadow, and is not a validated T0840 analytic. Legitimate inventory and diagnostics can match.

Dedup: R771 rate, R773 fanout, R804 SNMP/SSH, R966/R969 SET, R971 GETBULK, R972 system fingerprint GET. R976 GETNEXT exact connection table roots; one event does not meet R771 burst. Potential overlap on repeated requests, not independent incidents. Existing predicates unchanged.

30 authored cases: four raw capture positives, 22 benign/malformed/operation controls, four facts for scope, forgery/contradictions, state and registry. Paired GETBULK positive R971 / negative R976. Synthetic only. Independent captures, NMS allowlist and baseline required before promotion.

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R976SnmpConnectionTableQualityTests|FullyQualifiedName~R971SnmpHighDemandGetBulkQualityTests|FullyQualifiedName~R972SnmpSystemFingerprintQualityTests"
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release
```

Next R977 subject to live registry. Prior qualification obligations and frozen holdouts unchanged.
