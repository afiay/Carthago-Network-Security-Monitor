# R979 — BACnet Event_Enable all-transition disable request
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow; source and tests authored only.

Owner workbook R2711 / AN1861 T0878: https://attack.mitre.org/detectionstrategies/DET0728#AN1861
Workbook directly inspected: alarm/historian state changes correlated with configuration writes; authorization, maintenance/change control and corroborating operational effect required. This candidate supplies only a narrow request-side signal.

ANSI/ASHRAE Standard 135 BACnet/IP: exact 22-byte IPv4 UDP/47808 Original-Unicast BVLC, local NPDU expecting reply, unsegmented ConfirmedRequest WriteProperty (15), context [0] concrete Analog Input (0) or Binary Input (3) object, context [1] Event_Enable (35), opening context [3], application bit-string tag 0x82, five unused bits, all three transitions zero (0x00), closing context [3]. No priority, array index or trailing fields. No raw object identifier, invoke ID or payload retained. All three notification transitions disabled in the requested value; no observed alarm state, command acceptance or actual suppression claimed. Partial disable, other objects, other encoding, routed/broadcast/segmented/incomplete messages excluded. Authorized maintenance can match; no authorization or change-control baseline inferred.

Dedup: R485 generic WriteProperty parser intentionally excludes bit strings; R979 exact Event_Enable bit-string operation. R486 DCC, R975 restart, R977 Object_List distinct. Existing predicates unchanged. Scalar WriteProperty capture explicitly separated. No independent incident claim for broad BACnet overlaps. Promotion requires independent attack/benign capture and workbook operational fidelity gates.

42 authored xUnit cases: four capture positives, 33 malformed/benign controls, five facts for scope, scalar-write separation, forged/contradictory fields, state and registry. Synthetic only; Windows execution pending.

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R979BacnetEventDisableQualityTests|FullyQualifiedName~R977BacnetObjectListReadQualityTests|FullyQualifiedName~R975BacnetReinitializeDeviceQualityTests"
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release
```

Next R980 subject to live registry. Prior qualification obligations unchanged.
