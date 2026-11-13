# R972 — public SNMP system fingerprint GET
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow; source and tests authored only.

Owner workbook R2771 / AN2186, remote system information discovery: https://attack.mitre.org/detectionstrategies/DET0787#AN2186
Protocol references: RFC 3418 system group https://www.rfc-editor.org/rfc/rfc3418.html ; RFC 3416 GET https://www.rfc-editor.org/rfc/rfc3416.html#section-4.2.1

Narrow projection: complete IPv4 UDP/161 SNMPv1/v2c GET (A0), exactly three distinct RFC3418 system scalar OIDs sysDescr.0 (1.3.6.1.2.1.1.1.0), sysObjectID.0 (1.3.6.1.2.1.1.2.0), sysName.0 (1.3.6.1.2.1.1.5.0), in any order, each empty NULL, canonical request ID, zero error/index; 20–4096 byte bound. No raw community, OID, request ID or returned data retained. Reject single/two-object polling, duplicates, extra scalars, wrong instance, other PDU/version, malformed/incomplete BER and contradictory/wrong-scope capture. Legitimate inventory/diagnostics can issue the same request. No enrolled OT asset, NMS authorization, returned fingerprint or compromise inferred.

Dedup: R771 packet-count burst, R773 target fanout, R804 SNMP/SSH sequence, R966/R969 SET, R971 GETBULK. R972 exact GET operation independent of rate. A burst of these requests may overlap R771; not independent incidents. No predicate changed in earlier rules.

32 authored xUnit cases: six raw capture permutations with both versions, 22 benign/malformed/PDU controls, scope/integrity, forgery/contradictions, state and registry. Explicit paired GETBULK positive R971 / negative R972 and R966/R969 negatives on R972 positives. Synthetic fixtures only. Independent positive/benign captures, approved source/asset inventory and overlap evaluation required before promotion.

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R972SnmpSystemFingerprintQualityTests|FullyQualifiedName~R971SnmpHighDemandGetBulkQualityTests|FullyQualifiedName~R966SnmpEnterpriseSetQualityTests|FullyQualifiedName~R969SnmpUpsRebootQualityTests"
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release
```

Next ID R973 subject to live registry. Prior qualification obligations and frozen holdouts unchanged.
