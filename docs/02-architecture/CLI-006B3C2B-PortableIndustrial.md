# CLI-006B.3C2B — Portable industrial protocol inspectors

**SOURCE CANDIDATE — UNVERIFIED.** 22 portable and one Windows xUnit cases authored; zero executed in this session.

Core compiles eleven existing wire-inspector sources: SNMP enterprise SET (also UPS reboot, GetBulk, system fingerprint GET and connection-table GetNext), BACnet BVLC/DCC/Object_List/restart/WriteProperty, DNP3 unsolicited events/restart/disable unsolicited, Modbus single-register and clear-mask write. Windows excludes the same canonical files and forwards seven public BACnet types. Existing sources and namespaces are unchanged, including shared DNP3 CRC. No protocol recognition or detection threshold changes; no authenticated identity, authorization or device outcome implied. The existing BACnet Event_Enable inspector was previously extracted. Stateful exchange inspectors remain for a separate batch.

Qualification:
```powershell
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortableIndustrialInspectorTests"
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~PortableIndustrialCompatibilityTests|FullyQualifiedName~Snmp|FullyQualifiedName~Bacnet|FullyQualifiedName~Dnp3|FullyQualifiedName~Modbus"
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release
```

Repeat portable tests on Linux/macOS. Next CLI-006B.3C2C: IEC104/OPC UA, remaining exchange and infrastructure inspectors. No Actions execution requested.
