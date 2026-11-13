# R977 — public BACnet Device Object_List ReadProperty
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow; source and tests authored only.

Owner workbook R2690 / AN1920 T0861: https://attack.mitre.org/detectionstrategies/DET0788#AN1920
Workbook predicate inspected directly: systematic full tag/object namespace enumeration, unapproved source, operational deviation; approved inventory and polling suppression. This candidate does NOT establish those gates.

ANSI/ASHRAE Standard 135 BACnet/IP: exact 17-byte IPv4 UDP/47808 Original-Unicast BVLC, local NPDU expecting reply, unsegmented ConfirmedRequest service 12, context [0] Device object identifier (type 8, concrete instance 0–4194302), context [1] property 76 Object_List, no array index or trailing parameters. Request for entire array; no response or completed enumeration inferred. Index zero (array size), individual elements, other properties/objects, ReadPropertyMultiple, segmented/routed/broadcast/incomplete data excluded. No object identifier, invoke ID or payload retained. Public-to-private at detector. Authorized BMS inventory and commissioning may match; no authorization or operational baseline inferred.

Dedup: R485 WriteProperty service 15, R486 DCC service 17, R975 restart service 20, R121/R241 discovery. Distinct exact property-read operation. Existing predicates unchanged. Explicit paired restart positive R975 / negative R977. Do not promote before independent benign/attack captures, NMS/engineering role inventory and baseline validation.

37 authored xUnit cases: four capture positives, 28 malformed/benign/other operation controls, five facts for scope, adjacent rule, forgery/contradictions, state and registry. Synthetic only; Windows execution pending.

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R977BacnetObjectListReadQualityTests|FullyQualifiedName~R975BacnetReinitializeDeviceQualityTests"
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release
```

Next R978 subject to live registry. Prior qualification obligations unchanged.
