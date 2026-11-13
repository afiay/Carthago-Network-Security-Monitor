# CARTHAGO R967 — external DNP3 unsolicited binary event
**SOURCE CANDIDATE — UNVERIFIED.** Candidate/Shadow, no execution or production promotion.

Original owner workbook R2781, Detection of Spoof Reporting Message — Network Devices (AN2236), T0856.
Source: https://attack.mitre.org/detectionstrategies/DET0746#AN2236

Narrow projection: public IPv4 source to private UDP/20000 peer (both ports 20000), complete single DNP3 unconfirmed outstation link frame; exact length, valid header CRC and every 16-byte data block CRC; one complete transport/application unsolicited response fragment, indexed group 2 variation 1 binary-input event objects, 1–32 events. No raw point indexes, values, link addresses or IIN retained. CRC detects corruption, not identity/authentication. No enrolled point-to-device mapping, DNP3 Secure Authentication, actual spoofing, industrial role, operator authorization or process-state effect inferred. Null unsolicited responses, solicited responses, other variations/qualifiers, TCP, fragmented/multi-frame, confirmed link data and unsupported objects excluded. Legitimate remote outstations can match.

Dedup: R224 DNP3 outside approved segment, R875 public DNP3 SYN then payload, R853 source MAC change; R967 is distinct decoded unsolicited application content, not a port, TCP connection or generic MAC observation. Targeted screening only.

28 xUnit cases: independent CRC-16/DNP check vector, three raw-capture positive sizes, twenty malformed/benign controls (CRC including second block, count, framing, direction, fragment, function, qualifier), scope/incomplete UDP, spoofed JSON/labels, state isolation/cooldown and registry. Synthetic packet fixtures; no independent benign/attack corpus yet. Independent lab/field evidence, asset enrollment and measured false positives/recall remain necessary.

Windows pending:
```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R966SnmpEnterpriseSetQualityTests|FullyQualifiedName~R967Dnp3UnsolicitedBinaryEventQualityTests|FullyQualifiedName~TftpCaptureQualificationTests|FullyQualifiedName~DnsCaptureQualificationTests|FullyQualifiedName~Smb2CaptureQualificationTests"
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release
```

Next ID R968, subject to live registry. Prior quality gate, confidence floors and frozen holdouts preserved.
