# R970 — IEC104 STARTDT then OFF execute
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow; source and test authoring only.

Owner workbook R2708 AN2212: https://attack.mitre.org/detectionstrategies/DET0794#AN2212 . This is a deliberately narrow wire projection of the Industroyer2 precedent, not the full unauthorized-command analytic. No asset/safety-critical point inventory, approved source, operator acknowledgement, maintenance status or process effect is available.

Exact complete IPv4 TCP/2404, observed SYN/SYN-ACK, first client STARTDT act (68 04 07 00 00 00), first server STARTDT con (68 04 0B 00 00 00), then first I-format type 46 C_DC_NA_1 activation, one nonsequence object, zero send/receive counters, originator zero, valid station/IOA, DCO OFF execute (1), no qualifier or select bit. All same flow, complete normalized bytes, TCP sequence and opposite ACK boundaries, <=30 seconds from STARTDT act. One shot; no raw command, station or IOA retained. Existing bounded flow table, reset on SYN, FIN/RST, TLS, invalid/gapped/retransmitted segment or expiry. Public-to-private direction required at detector. Scope excludes later I-frames, split/coalesced APDUs and IEC104 encrypted traffic. Legitimate power-system switching/recovery can match.

R482 broad generic external IEC104 command remains unchanged and producer-gated. R970 differs by exact STARTDT sequence and type 46 OFF execute; no claim of full R482 qualification. Future shared producer work must assess event overlap before promotion. Screening is not exhaustive semantic equivalence proof.

36 authored xUnit cases: one raw sequence positive, 19 command/framing controls, 12 session/timing controls, exact 30-second boundary/one-shot, scope/forgery/contradictions, cooldown/peer/instance, registry. Synthetic only; independent capture and operator-policy validation pending.

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R970Iec104StartupOffQualityTests|FullyQualifiedName~R968ModbusSameRegisterQualityTests|FullyQualifiedName~R969SnmpUpsRebootQualityTests"
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release
```

Next ID R971, subject to live registry. Prior qualification obligations and holdouts unchanged.
