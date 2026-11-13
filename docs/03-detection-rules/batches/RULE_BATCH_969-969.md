# CARTHAGO R969 — external SNMP UPS reboot-duration SET
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow, no execution or production promotion.

Original owner workbook R2768, Detection of Device Restart/Shutdown — Network Devices (AN2187), T0816.
Source: https://attack.mitre.org/detectionstrategies/DET0801#AN2187
Protocol reference: RFC 1628 UPS-MIB, upsRebootWithDuration.0 (1.3.6.1.2.1.33.1.8.4.0), https://www.rfc-editor.org/rfc/rfc1628.html

Narrow projection: complete public IPv4 to private UDP/161 SNMPv1/v2c SET, strict definite-length BER and exactly one scalar binding to upsRebootWithDuration.0, canonical nonnegative Integer32 duration. Shared bounded BER structural parser retains separate enterprise and exact reboot predicates. Existing R966 enterprise SET behavior unchanged; UPS scalar is under mib-2, not the enterprise subtree. Reject reads, responses, other UPS control OIDs, missing/wrong scalar instance, invalid durations, mixed/multi-binding, unsupported SNMPv3, fragmented/incomplete UDP. Community, OID and duration are not retained as raw observation data. No enrolled UPS identity, approved NMS, power-state effect, success or authorization inferred; a legitimate maintenance request may match.

Dedup: R966 enterprise SET and R771 port-161 burst differ; R969 exact single power-control scalar and valid duration. R966 positive and R969 negative on enterprise SET, inverse on UPS reboot request. Targeted comparison, not exhaustive semantic-equivalence proof.

29 authored xUnit cases: four capture positives (versions and duration boundaries), 21 negative controls (read/response, adjacent OID, enterprise, malformed value/BER, missing instance and count), scope/completeness, forged/contradictory evidence, cooldown/peer/instance isolation and registry. Prior R966 parser/capture regressions included in focused command. Tests synthetic; independent reviewed benign/attack capture and operational context still needed.

Windows pending:
```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R966SnmpEnterpriseSetQualityTests|FullyQualifiedName~R967Dnp3UnsolicitedBinaryEventQualityTests|FullyQualifiedName~R968ModbusSameRegisterQualityTests|FullyQualifiedName~R969SnmpUpsRebootQualityTests"
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release
```

Next ID R970 subject to live registry. Prior thresholds, holdouts and qualification obligations unchanged.
