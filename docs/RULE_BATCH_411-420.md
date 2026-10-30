# GA R411–R420 — Family attribution, beacon cadence and appliance-probe provenance

**SOURCE CANDIDATE — UNVERIFIED · 2026-10-30.** Existing branch:
`feature/carthago-reliability-hardening`. Inspected live pre-change HEAD:
`e1e9fd5b862ced09bc7ab807f28e26639c976e0b` (includes independent UI-06).
Source commit `408eaddaa0398ee120044edacef9b3556ed52d35`;
authored-test commit `c9a4ccdfe87a217c7783a845e438363ca9ba42c9`.
The documentation-descendant commit is the complete candidate's publication
target. Its exact SHA is obtained from the remote branch ref after a single
non-forced expected-HEAD update; a commit cannot contain its own SHA.

## Ten-rule evidence contract and original profiles

The ten existing [R411–R420 classes](../Carthago/Engine/Rules/Expansion/)
inherit `MalwareC2PrecisionDetectionRuleBase` (R411–R412) or
`NetworkApplianceExposurePrecisionDetectionRuleBase` (R413–R420).
They use the shared
[EvidenceDrivenPrecisionRuleBase](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs).
Their generic name tokens, common HTTP routes, client-controlled headers,
TCP/UDP ports and protocol labels are not authenticated vendor identity,
malware-family attribution, exploit outcome or measured beacon cadence.

The real [PacketHandler](../Carthago/Services/PacketHandler.cs) has a bounded
4,096-byte early TCP inspection window, not general stream reassembly or TLS
decryption. Its flow and early HTTP metadata cannot establish a verified
appliance model, login success, malicious intent, exploit payload execution,
UDP discovery response/exposure, or a per-flow low-jitter interval series.
`TrafficRecord.Info`, `ProcessName`, `HttpHost` and headers are not
independent authenticated audit evidence. The existing burst counters count
observations; they do **not** calculate R412's inter-arrival variance.

| Rule | Existing name | Actual producer and visible fields | Missing predicate for claimed behavior | Disposition | Original mode / severity / floor | Threshold / window / cooldown | Legitimate-traffic false-positive risk |
| --- | --- | --- | --- | --- | --- | --- | --- |
| R411 | Lumma Stealer Gate Pattern | Packet/early HTTP flow, path/port and untrusted Info; no independent target/outcome producer | Family-specific payload/agent attribution | **BLOCKED** | Alert / Critical / 86 | 1 / 30m / 45m | Common /gate.php paths, red-team simulation |
| R412 | Generic Beacon Jitter Low Variance | Packet/early HTTP flow, path/port and untrusted Info; no independent target/outcome producer | Timestamped, attributable independent flow intervals with variance analysis | **BLOCKED** | Alert / Medium / 86 | 4 / 60m / 45m | Scheduled polling, health checks, backups |
| R413 | Citrix Netscaler Gateway Scan Pattern | Packet/early HTTP flow, path/port and untrusted Info; no independent target/outcome producer | Verified Citrix asset identity plus scan sequence | **BLOCKED** | Alert / High / 82 | 1 / 10m / 30m | Normal VPN login, inventory and approved scanners |
| R414 | Ivanti Connect Secure Exploit Probe | Packet/early HTTP flow, path/port and untrusted Info; no independent target/outcome producer | Verified target plus exploit-specific request/payload evidence | **BLOCKED** | Alert / High / 82 | 1 / 10m / 30m | Legitimate VPN/API requests and patch validation |
| R415 | F5 BIG-IP TMUI Probe | Packet/early HTTP flow, path/port and untrusted Info; no independent target/outcome producer | Verified F5 TMUI asset and unauthorized probe evidence | **BLOCKED** | Alert / High / 82 | 1 / 10m / 30m | Ordinary admin login and device health checks |
| R416 | SonicWall SSLVPN Exploit Probe | Packet/early HTTP flow, path/port and untrusted Info; no independent target/outcome producer | Validated SonicWall-specific exploit signature and target identity | **BLOCKED** | Alert / High / 82 | 1 / 10m / 30m | Generic .ovpn/client.conf downloads |
| R417 | Cisco ASA WebVPN Probe | Packet/early HTTP flow, path/port and untrusted Info; no independent target/outcome producer | Verified ASA identity and distinct unauthorized probe behavior | **BLOCKED** | Alert / High / 82 | 1 / 10m / 30m | Normal WebVPN authentication and approved scans |
| R418 | MikroTik Winbox External Access | Packet/early HTTP flow, path/port and untrusted Info; no independent target/outcome producer | Verified MikroTik asset and Winbox protocol/session evidence | **BLOCKED** | Alert / High / 82 | 1 / 10m / 30m | Unrelated TCP/8291 services, approved admin sessions |
| R419 | Ubiquiti Discovery External Exposure | Packet/early HTTP flow, path/port and untrusted Info; no independent target/outcome producer | Attributable discovery request/response and externally exposed Ubiquiti device | **BLOCKED** | Alert / Medium / 82 | 1 / 10m / 30m | Unrelated UDP/10001 traffic, approved discovery |
| R420 | QNAP QTS Admin Probe | Packet/early HTTP flow, path/port and untrusted Info; no independent target/outcome producer | Verified QNAP target and probe beyond normal authentication | **BLOCKED** | Alert / High / 82 | 1 / 10m / 30m | Ordinary QTS login and administration |

R413, R414, R415, R417 and R420 include ordinary login/API endpoints.
A cleartext request to those paths may prove only a **request shape**, not
a scan, target device identity, unauthorized access, successful login, or
exploit. R416's generic VPN configuration filenames do not identify
SonicWall. R418's TCP destination port 8291 does not prove Winbox service.
R419's UDP 10001 does not prove a Ubiquiti discovery reply. For R411, even
a visible `/gate.php` is not a vetted Lumma signature. R412's four-request
threshold is not a measured jitter statistic. No sound positive
family/scan/exploit result is representable by the current producer.

## Source changes and safety boundaries

- **Production source:** [EvidenceDrivenPrecisionRuleBase.cs](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs). Ten per-ID fail-closed reason codes are added to the existing evidence guard before `CollectSignals`, burst state, confidence, cooldown or event/evidence construction. No generic signal is promoted to proof.
- **Authored tests:** [NetworkBatch411420AccuracyTests.cs](../Carthago.Tests/NetworkBatch411420AccuracyTests.cs).
- **Documentation:** this batch document and [progress ledger](RULE_HARDENING_PROGRESS.md).

All ten original classes, serialized/public rule IDs, enabled defaults, Alert
modes, severities, confidence floors, threshold/window/cooldown settings,
approval and suppression controls remain unchanged. No changes to WPF,
models, services, packet capture, journal, baseline, frozen R102 data or
unrelated detection IDs. No new state, credentials, retained raw payload,
request-body capture or sensitive event evidence is introduced. Blocked
rules cannot emit alerts until a separately reviewed trusted producer is
connected. This precision safeguard reduces unsupported attribution but
**does not validate detection recall** and can suppress true positives.

## Authored xUnit scenario inventory — ZERO EXECUTED

The new test file contains **two theory methods and 120 concrete xUnit
invocations**: ten rule IDs × eleven behavioral variants (110), plus one
profile invariant for each rule (10). Each rule receives all twelve:

| # | Scenario | Expected source-only contract |
| --- | --- | --- |
| 1 | plausible | Rule-specific visible path/port/flow, no trusted target or outcome; exact missing-producer reason and no event |
| 2 | descriptor-spoof | Free-form Info claims authenticated success; no event |
| 3 | normal-admin | Benign browser/approved administrator request; no misattributed alert |
| 4 | forged-asset-header | Client-supplied X-Device-Verified, X-Audit-Outcome and X-Appliance-Vendor; no trusted attestation |
| 5 | tls-only | Encrypted TLS metadata without visible request; no family/appliance attribution |
| 6 | missing-source | No source attribution; no event |
| 7 | malformed-path | Invalid percent encoding/path traversal; no event |
| 8 | privacy-placeholder | Synthetic token-like query/header; no evidence/event exposure |
| 9 | wrong-direction | Internal-to-internal flow, not claimed external boundary; no event |
| 10 | repeated-requests | Eight ordinary requests cannot create missing family, device, response or cadence proof; exact no-match reason |
| 11 | claimed-verified | Info claims Lumma family, zero-jitter intervals, Winbox session, Ubiquiti response or exploit; no trusted attestation |
| 12 | profile-invariant | Alert mode, original threshold, floor, window and cooldown unchanged |

Tests **AUTHORED: 120; EXECUTED: 0**. No `dotnet build`,
`dotnet test`, replay, holdout, CI, benchmark, Windows runner or
production capture was launched. No compilation, test pass, accuracy,
precision, recall, release-readiness or certification claim is made.
The earlier full `4,940/4,940` checkpoint predates this candidate.

## Static divergence review and outstanding GAs

- **Pre-change:** inspected live HEAD `e1e9fd5`, last published R401–R410
  batch, R411–R420 original rule files and profiles, shared evaluator,
  `PacketHandler`, existing authored tests, and
  [documentation standard](rules/RULE_DOCUMENTATION_STANDARD.md).
- **Pre-publication:** compare final tree against live branch for only the
  source guard, authored tests, this document and progress ledger. Confirm
  existing rule profiles, no UI-owned files, stable public API and no
  credential retention. Recheck remote HEAD and publish all commits
  atomically using non-forced expected-HEAD protection; never partially.
- **Open quality GAs:** owner-authorized Windows compilation and xUnit;
  independent, versioned family signatures; validated per-flow cadence
  samples; trusted appliance inventory and target identity; safe request
  parsing and verified scan/exploit context; Ubiquiti discovery response
  attribution; benign/malicious field corpora; measured false-positive
  and false-negative rates; privacy and performance review.
- **Independent GAs:** R343/R295/R275/R163 replay expectations remain open.
  Frozen R102 V1 remains FAILED 4/6, V2 has 0/4 approved sources.
  Floors R102 80%, R118 86%, R163 84%, external R102 0.75 preserved.

**Next consecutive development GA: R421–R430**, only after coherent
R411–R420 publication and fresh live source inspection.

## References

- [MITRE ATT&CK — Active Scanning](https://attack.mitre.org/techniques/T1595/)
  — request or port observation is not itself verified exploit success.
- [MITRE ATT&CK — Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
  — common web protocol activity is not a malware-family signature.
- [Microsoft — C# identifier naming](https://learn.microsoft.com/en-us/dotnet/csharp/fundamentals/coding-style/identifier-names)
  — stable public identifiers are retained.
