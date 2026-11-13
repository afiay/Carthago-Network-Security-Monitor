# R981 — public DNP3 Disable Unsolicited all event classes
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow; source and tests authored only.

Owner workbook R2717 / AN2216 T1691.002: https://attack.mitre.org/detectionstrategies/DET0789#AN2216
Workbook inspected directly: cessation of expected unsolicited reports/status updates while direct polling remains reachable, without maintenance/alarm context. This is only a request-side projection, NOT that outcome analytic.

Exact complete 24-byte IPv4 UDP/20000-to-20000 DNP3 frame, link length 17, control C4, distinct nonreserved peers, CRC-16/DNP of eight header bytes and 12 data bytes, transport/application FIR/FIN, function 15 hex, exactly group 60 variations 2, 3, 4 qualifier 06 in any order. All event classes, no other selector. No link addresses, sequences or payload retained. No confirmed-link, TCP, fragmented or coalesced frames. CRC is not authentication. Approved startup and commissioning can legitimately issue this request; no approval, accepted command, reporting loss or continued polling inferred.

Dedup: R967 unsolicited event response, R980 restart, R486 BACnet communication disable, R979 BACnet notification setting. Existing predicates unchanged; broad DNP3 observations can overlap. Independent captures and source/maintenance/reporting baseline required for promotion.

36 authored xUnit cases: six capture permutations, 25 negative cases, five facts for scope, adjacent response, forged evidence, state and registry. Synthetic only; Windows execution pending.

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R981Dnp3DisableUnsolicitedQualityTests|FullyQualifiedName~R980Dnp3RestartQualityTests|FullyQualifiedName~R967Dnp3UnsolicitedBinaryEventQualityTests"
```

Next R982 subject to live registry.
