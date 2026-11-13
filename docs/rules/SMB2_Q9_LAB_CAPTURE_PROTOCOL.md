# Q9-v1 — Original SMB2 lab capture intake and replay

## Status and scope

Owner checkpoint 6a677b7: Q8 22/22, combined 104/104, full 12,354/12,354 (288.3s), Release 52s. Q7 frozen synthetic metrics unchanged. This phase delivers a packet-only offline runner and 15 synthetic reader/replay contract cases, not an independent capture corpus or production accuracy result.

Use an isolated Windows lab with a client, an SMB server and, for R942, a third controlled host. Use a private virtual switch or dedicated lab VLAN, no connection to public or production networks. Use ordinary harmless text files and dedicated test accounts; no real secrets, production traffic, malicious executables or destructive actions. Keep default security settings; do not weaken production SMB signing/encryption. Encrypted, segmented, compound and late-after-budget writes may legitimately remain unqualified.

## Acquisition

1. On the lab capture workstation install/use Wireshark with Npcap. Start before opening the SMB connection (SYN and negotiation required). Select the client/server observation point that sees all relevant directions; for R942 also capture the server-to-third-host flow (e.g. lab mirror or capture on server). Save classic PCAP, not pcapng, with full snap length; keep capture short (under 10 minutes, 20,000 frames, 32 MiB).
2. Example on the client for an isolated private SMB server: copy a small text file to a dedicated lab share. Record the operation separately from CARTHAGO (operator/change record, Windows SMB/security logs and server-side file existence/hash or explicit failure). Use a fresh case ID, UTC start/end, isolated test account, exact endpoints and outcome. Record authorized vs unauthorized-simulation labels independently; a malicious-simulation case is an approved exercise whose simulated operation violates the lab policy, not actual unauthorized activity.
3. For R942, after a WRITE, use `Test-NetConnection -ComputerName <controlled-third-host> -Port 502` on the SMB server within 45 seconds. Use a test listener or no listener; do not send Modbus writes or control equipment. Separate legitimate maintenance, simulated unauthorized sequence, and a benign control with no follow-up. For R908, public-to-private classification requires a source address accepted by the rule's public-IP predicate; TEST-NET and RFC1918 do not satisfy it. Only use an address you control in an isolated lab, or defer R908; never use someone else's public address on a connected network.
4. Export a separate ground-truth evidence file (e.g. redacted operator log plus audit event references, status and file hash). Review the label before running CARTHAGO. Hash the capture and evidence file, store them in a private directory outside the repository. Do not commit PCAPs or logs. The runner verifies hashes and bounds, not the authenticity of the evidence file.

## Manifest (one case, same directory as input files)

Use a JSON object, camelCase, version 1; replace placeholders with real values. Example R942:

```json
{
  "version": 1,
  "caseId": "LAB-R942-001",
  "label": "benign",
  "targetRule": "R942",
  "captureFile": "case.pcap",
  "captureSha256": "<64 hex chars>",
  "groundTruthFile": "ground-truth.txt",
  "groundTruthSha256": "<64 hex chars>",
  "sourceIp": "10.77.1.20",
  "destinationIp": "10.77.2.40",
  "followupDestinationIp": "10.77.3.60",
  "startsUtc": "2026-11-13T12:00:00Z",
  "endsUtc": "2026-11-13T12:05:00Z",
  "expectedWrite": true
}
```

Labels: benign or malicious-simulation. expectedWrite means independently expected on-wire WRITE attempt, not successful storage. For R908 or process-dependent rules omit followupDestinationIp. Use actual capture bounds (UTC) and exact IPv4 endpoints. Hash with `Get-FileHash -Algorithm SHA256`. Relative filenames only, unique JSON fields, no path traversal. Keep manifest and inputs private; report contains case/label and hashes (including the manifest itself), not raw packets, paths, addresses or ground-truth text.

## Run (one explicit invocation per case)

```powershell
dotnet build .\Carthago.Benchmarks\Carthago.Benchmarks.csproj -c Release
dotnet run --project .\Carthago.Benchmarks\Carthago.Benchmarks.csproj -c Release --no-build --no-restore -- --smb2-lab-manifest "C:\PrivateLab\case\manifest.json"
```

Use a separate CLI process per case. Output JSON is diagnostic, not a quality verdict. Original classic PCAP 2.4 (little/big endian, micro/nanosecond, Ethernet or raw IPv4), packet timestamps drive rule evaluation and PacketHandler's UTC correlation clock. Timestamp nanoseconds truncate to 100ns; nonmonotonic captures reject. No stream reconstruction, packet mutation or process injection. Four process-dependent rules R903/R910/R919/R950 report process-attribution-unavailable (no false detector FN). Only R908/R942 are evaluated using scoped original packets and the Research precision gate with empty approved-assets configuration; not the full runtime deployment or Q8 authorization system. Capture truncation, no scoped traffic, missing expected WRITE or ground-truth conflict remain distinct coverage statuses even if a partial raw match is observed. Reports are ineligible for promotion.

Next: capture and independently review real lab cases; freeze hashes and labels before tuning. Add authenticated endpoint/process evidence, capture-time provenance and actual operation outcomes before assessing the other rules. Do not infer authorization from an admin host, process name or maintenance window. Do not compute a confusion matrix by mixing producer gaps with eligible detector cases. Full real-capture accuracy remains pending.
