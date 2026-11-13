# CLI-006B.3C2A — Portable fingerprints and selected wire inspectors

**SOURCE CANDIDATE — UNVERIFIED.** 12 portable and one Windows xUnit cases authored; zero executed in this session.

Core compiles the existing HttpJa4H, TlsJa4, TcpJa4T, SshJa4SSH, Hassh, Resp2CommandInspector, Resp2SimpleReplyInspector and Smb2CompleteWriteInspector sources. Windows excludes those exact files, retains their namespaces and call sites, and forwards all ten relocated public types. Existing internal access is unchanged. No source algorithm or fingerprint format changed. These are existing CARTHAGO fingerprints, including JA4-like variants and existing HASSH composition, not newly certified external standard implementations. The TLS fingerprint helper assumes validated input and has existing malformed-input limitations; this extraction does not harden or expose it as an independent parser. X509Ja4X stays in Windows pending platform-independent SAN counting and parity review. Redis request/reply correlation and SMB exchange state remain in PacketHandler. No native capture dependency.

Qualification:
```powershell
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~PortableFingerprintInspectorTests"
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~PortableFingerprintCompatibilityTests|FullyQualifiedName~Redis|FullyQualifiedName~Smb2|FullyQualifiedName~Tls"
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release
```

Repeat portable tests on Linux/macOS. Next: CLI-006B.3C2B — extract additional protocol inspectors, then flow state. No Actions execution requested.
