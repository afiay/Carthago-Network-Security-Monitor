# R984 — FINS/UDP sixteen-word Data Memory clear request
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow; authored tests, zero executed.

Owner workbook R2714 / AN1908 T0836: https://attack.mitre.org/detectionstrategies/DET0776#AN1908
Original workbook inspected: parameter/setpoint write outside documented safe range or from unauthorized source, correlated with historian drift. This is a narrow FINS request projection, not the original Modbus FrostyGoop precedent or a completed state change.

Exact complete IPv4 UDP/9600-to-9600, FINS command header ICF 80, RSV 0, GCT 2, local networks and CPU units (0), distinct nodes 1–254, arbitrary SID, command 0102, DM word area 82, start 0–32752 and bit offset zero, count 16, exactly 32 zero data bytes. Total 50 bytes. The address cap is a chosen narrow 32K-word subset, not a claim about all PLC models. Sixteen words is an engineering heuristic, not a calibrated anomaly. No memory address, SID or data retained. Response/no-response, other areas/commands/counts, partial or nonzero values, routed or non-CPU units excluded. No device model, safe range, approval, command acceptance or physical effect inferred.

Dedup: R983 FINS/TCP node negotiation, R982 Modbus mask write, R968 Modbus write burst. Distinct UDP command and value predicate. Existing rules unchanged. Legitimate initialization and recovery may match. Independent captures, controller map and authorization/change-control/process context required before promotion.

34 authored xUnit cases: 3 positive, 27 negative, 4 facts for scope, forgery, state and registry. Windows compilation and execution pending.

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R984FinsDataMemoryClearQualityTests|FullyQualifiedName~R983FinsNodeNegotiationQualityTests|FullyQualifiedName~R982ModbusClearMaskWriteQualityTests"
```
Next R985 subject to live registry.
