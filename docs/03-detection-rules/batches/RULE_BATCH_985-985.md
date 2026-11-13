# R985 — public FINS controller STOP request
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow; tests authored, zero executed.

Owner workbook R2721 / AN1887 T0858: https://attack.mitre.org/detectionstrategies/DET0755#AN1887
Workbook directly inspected: mode-change command from unapproved engineering source, missing operator acknowledgement and change-control context. This candidate observes a narrow FINS request, not the Triton precedent or an actual mode transition.

Exact complete 12-byte IPv4 UDP/9600-to-9600 FINS header ICF 80, RSV 0, GCT 2, local source/destination networks and CPU units zero, distinct nodes 1–254, arbitrary SID, command 0402 (STOP), no parameters. Response-requested only, no routed or broadcast nodes, no appended bytes. No raw node, SID or payload retained. No accepted command, CPU mode, authorization, device identity or process impact inferred. Legitimate engineering and maintenance may match. Independent captures, asset policy and mode-state evidence required for promotion.

Dedup: R983 FINS/TCP node negotiation, R984 FINS Data Memory write, R477 S7 CPU start/stop. Different native protocol/operation; paired R984 positive and R985 negative. Existing predicates unchanged.

28 authored xUnit cases: 3 positive, 20 negative, 5 facts for paired write, scope, forgery, state and registry. Windows compilation/execution pending.

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R985FinsControllerStopQualityTests|FullyQualifiedName~R984FinsDataMemoryClearQualityTests|FullyQualifiedName~R983FinsNodeNegotiationQualityTests"
```
Next R986 subject to live registry.
