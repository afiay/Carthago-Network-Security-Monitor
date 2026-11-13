# R975 — public BACnet ReinitializeDevice coldstart/warmstart
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow; source and tests authored only.

Owner workbook R2697 / AN1933 (T0816): https://attack.mitre.org/detectionstrategies/DET0801#AN1933
Protocol: ANSI/ASHRAE Standard 135, ReinitializeDevice confirmed service 20. This is a BACnet restart-command projection, not a detector for the workbook's SIPROTEC exploit precedent.

Exact 12-byte BACnet/IP IPv4 UDP/47808 Original-Unicast BVLC, local NPDU with expecting-reply bit and valid priority, unsegmented ConfirmedRequest with valid max APDU/segments, service 20, context [0] enumerated coldstart (0) or warmstart (1), no password. No raw invoke ID, password or payload retained. Capture requires complete IP and UDP lengths. Both service-port and ephemeral source ports supported. Public-to-private scope at rule. Other operations including backup/restore/activate, segmented/routed/broadcast and password-bearing commands are intentionally excluded. No device identity, engineering-source authorization, maintenance context, accepted command or actual restart inferred. Legitimate maintenance may match.

Dedup: R485 WriteProperty service 15, R486 DCC service 17, R969 SNMP UPS reboot; R975 service 20 is distinct. Existing rules unchanged. Explicit paired DCC positive/negative regression. Candidate remains shadow until approved-source/asset policy and independent capture validation.

37 authored xUnit cases: 4 capture positives, 28 malformed/other operations, 5 facts for scope, DCC separation, forged/contradictory fields, state and registry. Synthetic only; Windows execution pending.

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R975BacnetReinitializeDeviceQualityTests|FullyQualifiedName~R974ModbusOversizedReadQualityTests|FullyQualifiedName~R973OpcUaHelloAckQualityTests"
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release
```

Next R976 subject to live registry. Prior qualification obligations and frozen holdouts unchanged.
