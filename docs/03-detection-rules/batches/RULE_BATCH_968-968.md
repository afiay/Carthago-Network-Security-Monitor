# CARTHAGO R968 — repeated public Modbus same-register writes
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow, no execution or production promotion.

Original owner workbook R2725, Detection of Brute Force I/O — Embedded (AN1870), T0806.
Source: https://attack.mitre.org/detectionstrategies/DET0737#AN1870

Narrow projection: public IPv4 source to private TCP/502 peer, exact standalone Modbus TCP function 06 single-register write as the first client payload after observed SYN, complete IP packet, no normalization/overlap or known TLS. MBAP protocol ID zero, length six, unit 1–247, exact 12 bytes; retain only internal unit/register key, not value or transaction ID. Five distinct client ports, same source/destination/unit/register, sliding inclusive ten-second window; bounded 512 keys and 32 entries per key, monotonic UTC and duplicate rejection. Cooldown scoped to point. Multiple writes on one long-lived connection, coalesced/split frames, unit zero/255 and other functions are deliberately excluded. No scan-cycle baseline, authorized-source inventory, authenticated control identity, write success or physical effect inferred. A client reconnecting during legitimate commissioning/recovery may match. Distinct ports are not proof of distinct authenticated sessions.

Dedup: R240 detects generic parsed Modbus write; R476 is coil write burst; R548/R557 detect target fanout; R871 is multi-device payload walk. R968 requires same register and distinct client ports with actual function 06 bytes. Targeted screening, not exhaustive semantic equivalence proof.

26 authored xUnit cases: two capture positives/register boundaries, eleven read/malformed/unsupported ADU controls, missing SYN/gap/retransmission/later-payload regression, nine point/peer/port/time controls, forged labels/JSON and contradictions, cooldown/point isolation, registry. Synthetic packets only; independent capture/review and per-point operational baseline required before promotion.

Windows pending:
```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R968ModbusSameRegisterQualityTests|FullyQualifiedName~R966SnmpEnterpriseSetQualityTests|FullyQualifiedName~R967Dnp3UnsolicitedBinaryEventQualityTests"
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release
```

Next ID R969 subject to live registry. Frozen holdouts, existing predicates and floors unchanged.
