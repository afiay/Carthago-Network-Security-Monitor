# R971 — public SNMP high-demand GETBULK request
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow; source and test authoring only.

Owner workbook R2744 / AN1249 (T1602.001): https://attack.mitre.org/detectionstrategies/DET0453#AN1249
Protocol: RFC 3416 section 4.2.3 https://www.rfc-editor.org/rfc/rfc3416.html#section-4.2.3

Narrow complete IPv4 UDP/161 SNMPv2c GETBULK (A5); canonical BER, one to eight valid OID/empty-NULL bindings, zero non-repeaters, max-repetitions 64–1024 inclusive, packet 20–4096 bytes. Bounded requested output of 64–8192 variable bindings, not returned data. No community, OID, request ID or response retained. Reject other PDU types and versions, normal lower-demand polling, out-of-subset counts, noncanonical/negative numbers, malformed BER/OID/value, wrong direction and incomplete datagrams. Candidate threshold is engineering heuristic; legitimate inventory/diagnostics may match. No inferred successful MIB dump, unauthorized NMS, response size or device impact.

Dedup: R771 (same workbook row) detects 12 UDP/161 observations in ten seconds without decoding; R971 matches one exact high-demand request without burst. The predicates can overlap for a burst of high-demand requests; do not count as independent incidents. R966 and R969 decode SET operations, not GETBULK. Existing R771 unchanged. R971 provides a distinct operation-level observation, not a second claim of the same completed MIB dump.

31 authored xUnit cases: four raw capture boundary positives; 23 negative PDU/value/count/BER cases; scope/datagram integrity, forgery/contradictions, state and registry. Explicit R771/R966/R969 negatives on one positive R971 frame. Synthetic only; independent benign and attack captures, policy baseline and overlap evaluation before promotion.

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R971SnmpHighDemandGetBulkQualityTests|FullyQualifiedName~R966SnmpEnterpriseSetQualityTests|FullyQualifiedName~R969SnmpUpsRebootQualityTests"
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release
```

Next ID R972 subject to live registry. Prior qualification obligations and frozen holdouts unchanged.
