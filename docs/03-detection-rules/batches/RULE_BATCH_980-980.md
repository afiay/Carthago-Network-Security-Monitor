# R980 — public DNP3 cold/warm restart request
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow; source and tests authored only.

Owner workbook R2697 / AN1933 T0816: https://attack.mitre.org/detectionstrategies/DET0801#AN1933
Workbook directly inspected: embedded ICS restart/reset command, unapproved engineering source and potential multi-device/outage correlation. This is a narrow DNP3 request projection, not the workbook's SIPROTEC exploit or a completed restart.

Exact 15-byte complete IPv4 UDP/20000-to-20000 DNP3 frame, start 05 64, link length 8, control C4 (master unconfirmed user data), distinct nonreserved source/destination link addresses below FFF0, valid CRC-16/DNP over eight header bytes and three data bytes. Transport FIR/FIN, application FIR/FIN without CON/UNS, cold restart 0D or warm restart 0E, no objects. CRC is not origin authentication. No link address, sequence or payload retained. No fragmented, confirmed-link, object-bearing, TCP or other port traffic; narrow standalone datagram only. Public-to-private rule scope. Authorized maintenance may match; no source approval, device identity, device acceptance, outage or actual restart inferred.

Dedup: R967 unsolicited binary input event (outstation direction, different function); R975 BACnet restart; R969 SNMP UPS reboot. Broad R224 DNP3 segment and R875 TCP shape unchanged; possible overlap is not independent incidents. Shared CRC primitive reused without modifying R967. Independent MSB-first CRC fixture with known vector.

36 authored xUnit cases: four raw positives, 26 negative frames, six facts for CRC vector, scope, adjacent rule separation, forgery/contradictions, state and registry. Synthetic only; Windows compilation and execution, approved source inventory and independent captures pending.

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R980Dnp3RestartQualityTests|FullyQualifiedName~R967Dnp3UnsolicitedBinaryEventQualityTests|FullyQualifiedName~R975BacnetReinitializeDeviceQualityTests"
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release
```

Next R981 subject to live registry. Prior qualification obligations unchanged.
