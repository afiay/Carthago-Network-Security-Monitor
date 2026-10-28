# R231–R235 — typed IoT discovery and boundary precision candidate

**CANDIDATE — UNVERIFIED.** Authored 2026-10-28 on the existing `feature/carthago-reliability-hardening` branch. **48 advanced rule xUnit facts plus 7 parser facts authored; zero executed.** No build, xUnit, replay, holdout, CI or runner was executed. No new frozen or development replay fixtures were manufactured.

## Actual source and test paths

Production: `Carthago/Engine/Rules/Expansion/R231_CoapMulticastDiscoveryBurstRule.cs`, `R232_MdnsServiceEnumerationBurstRule.cs`, `R233_PrinterAdminProtocolExternalAccessRule.cs`, `R234_IpCameraRtspExternalStreamRule.cs`, `R235_OnvifDiscoveryFromWorkstationRule.cs`, `NetworkBatch231235Evidence.cs`; `Carthago/Services/NetworkBatch231235Wire.cs`, `PacketHandler.cs`; scoped event privacy in `Carthago/Engine/Rules/IotOt/IotOtPrecisionDetectionRuleBase.cs`.

Tests: `Carthago.Tests/NetworkBatch231235Context.cs`, `R231AdvancedAccuracyBatchTests.cs` (9 facts), `R232AdvancedAccuracyBatchTests.cs` (11), `R233AdvancedAccuracyBatchTests.cs` (9), `R234AdvancedAccuracyBatchTests.cs` (9), `R235AdvancedAccuracyBatchTests.cs` (10); `NetworkBatch231235WireTests.cs` (7). All **unexecuted**.

## Evidence, precision and tests

- **R231:** Only parsed CoAP GET `/.well-known/core` on UDP/5683 qualifies; count ten distinct packet IDs from one source in the original window. Tests cover positive burst, isolated onboarding, spoofed Info, ordinary CoAP, contradictory transport, duplicate, source isolation, out-of-order and Shadow/76.
- **R232:** Only typed mDNS UDP/5353 PTR service queries to the correct multicast address qualify. Count 20 **distinct service qnames**, not 20 repeats of one query or narrative text. The packet adapter now routes UDP/5353 through the existing bounded DNS question parser. Tests cover positive distinct services, isolated Bonjour, Info spoof, A vs PTR, response vs query, contradictory transport, duplicate service, privacy, source isolation, out-of-order and Shadow/76.
- **R233:** Only parsed cleartext HTTP GET/POST on printer IPP port 631 with anchored `/admin` path and a crossing boundary qualifies. No PJL/IPP success is inferred from Info. Tests cover typed positive, normal print job, Info spoof, same-subnet print server, TLS/wrong port, similar benign path, duplicate, secret redaction and Alert/78.
- **R234:** Only a parsed RTSP `PLAY rtsp://...` request on TCP/554 or TCP/8554 across a boundary qualifies. The capture path now clears HTTP fields if generic HttpLight initially mistakes an RTSP request line for HTTP. No video stream delivery, camera identity, or authorization is inferred. Tests cover positive, internal viewing, port/Info spoof, DESCRIBE-only, UDP contradiction, wrong port, duplicate, secret URL redaction and Alert/84.
- **R235:** Only bounded XML-parsed WS-Discovery Probe carrying an ONVIF `NetworkVideoTransmitter` type, UDP/3702 multicast and explicit workstation process attribution qualifies. Count five unique packet IDs per workstation, not distinct multicast destinations. Tests cover positive, isolated onboarding, Info spoof, missing process, camera process, wrong multicast, duplicate, independent sources, out-of-order and Shadow/76. Parser tests include ONVIF Probe, generic WS-Discovery rejection and DTD rejection.

Per-instance bounded counters from `NetworkBatch226230Evidence.Window` reject repeated packet GUIDs, out-of-order samples and saturation. Shared IoT evidence redacts raw Info, host and destinationHost for R226–R235; R233 admin path is a fixed redaction marker. Confidence floors, default runtime modes, thresholds, cooldown profiles, asset approvals and baseline-readiness gates remain unchanged.

## Limitations and deferred verification

- CoAP and RTSP parsing recognizes only bounded first-packet request frames, not arbitrary fragmented TCP/UDP payloads or encrypted sessions.
- DNS/mDNS query parsing has no verified live packet replay. `DnsTtl` and `DnsAnswers` remain unpopulated by the inspected PacketHandler DNS path.
- WS-Discovery ONVIF classification requires process enrichment, whose live availability is not established; an ONVIF Probe is not proof of camera compromise.
- A different IPv4 /24 is a **heuristic**, not an approved segment boundary. Printer and RTSP requests do not prove an administrative change or delivered media.
- Parser-authored xUnit facts are unexecuted; static source review cannot establish compilation, runtime behavior, accuracy or emitted-alert recall.
- The consolidated Windows verifier `scripts/verify-all-rule-batches.ps1` remains unchanged and must not run until the owner explicitly authorizes testing.
- Frozen R102 V1 holdout remains **FAILED 4/6**, immutable; V2 independent licensed PCAP and analyst approval remain pending. R102 80%, R118 86%, R163 84% floors unchanged.

**Next consecutive five: R236–R240, then R241–R245.**
