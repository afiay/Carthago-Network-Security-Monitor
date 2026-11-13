# CLI-006B.3C2C — Portable protocol exchanges

**SOURCE CANDIDATE — UNVERIFIED.** 14 portable and one Windows xUnit cases authored; zero executed in this session.

Core compiles eleven existing protocol inspector/tracker sources covering IEC104, OPC UA, Modbus, LDAP, TFTP and SMB2. Windows excludes the canonical files and forwards thirteen public types. Original source, namespace, correlation windows, direction checks and privacy semantics unchanged. TFTP and SMB2 target context use the already shared TrafficRecord. PacketHandler retains ownership of per-flow orchestration and native capture. Tests exercise IEC sequence/reset, OPC UA matching buffers/time, Modbus transaction and quantity, LDAP attestation/privacy, TFTP one-shot/expiry, SMB reply identifiers/ack/time and assembly compatibility. SMB target-context full behavior remains covered by existing Windows tests; the new portable batch asserts its assembly ownership.

Publication rebased onto ecc243b2db46aa5f21a6b2a5ee63aebcef35832b to preserve concurrent R986 and reviewed DNS intake changes; no overlapping changed files.

Qualification:
```powershell
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortableExchangeInspectorTests"
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~PortableExchangeCompatibilityTests|FullyQualifiedName~Iec104|FullyQualifiedName~OpcUa|FullyQualifiedName~Modbus|FullyQualifiedName~Ldap|FullyQualifiedName~Tftp|FullyQualifiedName~Smb2"
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release
```

Repeat portable tests on Linux/macOS. Next: inventory PacketHandler's remaining helper and flow dependencies; extract in coherent groups. No Actions execution requested.
