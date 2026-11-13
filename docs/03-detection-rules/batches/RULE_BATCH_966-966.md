# CARTHAGO R966 — external SNMP enterprise SET
**SOURCE CANDIDATE — UNVERIFIED.** Owner resumed expansion with quality tests. R966 stays Candidate/Shadow; prior qualification obligations remain open.

Original owner workbook R2773, Detection of Native API — Network Devices (AN2183), T0834.
Source: https://attack.mitre.org/detectionstrategies/DET0753#AN2183

Narrow projection: complete IPv4 UDP/161 v1/v2c definite-length BER SET request with a structurally valid enterprise object identifier (1.3.6.1.4.1.<enterprise>.<object>) from public source to private peer. Capture producer parses the complete message and all variable bindings, supports only INTEGER and OCTET STRING values, limits 4096 bytes/32 bindings/1024 value bytes. No community, OID, or value retained. No vendor-specific/undocumented OID knowledge, device role, approved NMS inventory, authenticated authorization or accepted modification inferred. SNMPv3, fragmented traffic, non-supported value types and other transports excluded.

Dedup review: R771 port-161 public burst, R773 private SNMP target fanout, R804 SNMP probe followed by SSH; this is one decoded SET, not another rate or port-only variant. Targeted comparison, not exhaustive semantic proof.

Quality: R966SnmpEnterpriseSetQualityTests includes 26 test cases: raw capture positive v1/v2c, polling/response negatives, malformed/unsupported BER, scope/bounds, synthetic labels and contradictory fields, cooldown/duplicate/reverse UTC/peer isolation, independent rule instances, privacy and registry. Synthetic raw frames, not independent lab or field evidence. Legitimate external NMS SET may still match. No claim of measured precision/recall; independent reviewed attack/benign captures required for promotion.

Windows execution pending:
```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R966SnmpEnterpriseSetQualityTests|FullyQualifiedName~TftpCaptureQualificationTests|FullyQualifiedName~DnsCaptureQualificationTests|FullyQualifiedName~Smb2CaptureQualificationTests"
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release
```
Next unallocated ID R967, subject to live registry. Existing confidence floors, frozen holdouts and scored corpora unchanged.
