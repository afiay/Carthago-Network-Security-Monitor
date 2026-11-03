# CARTHAGO — GA R555: outbound FTP upload-command public-subnet fanout

**Branch:** feature/carthago-reliability-hardening  
**Base HEAD:** 383d2f04391dbe36d9ba96ce3b2592d360cc85c3 (2026-11-02).  
**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**. No restore, build, xUnit, replay, holdout, CI, runner, capture or packet scan was executed.

## Detection decision and existing-rule reconciliation

| Rule | Source and overlap | Exact new predicate | Disposition |
| --- | --- | --- | --- |
| **R555 — External FTP Upload Command Subnet Fanout** | The completed P0001–P0500 inventory has no direct FTP row: **do not invent a P ID**. P0006 SMB was the adjacent source for R554, but this FTP-only fanout is **not** SMB, SFTP (P0096) or rsync (P0054). R248 matches an individual external FTP STOR/APPE command; R554 requires an SMB2 WRITE-to-FTP sequence. Neither requires distinct public FTP destinations. | One RFC1918 IPv4 source sends **three** existing PacketHandler-classified FTP STOR/APPE requests on TCP/21 to **three distinct public IPv4 /24 networks** within **five minutes**. Require unique packet IDs, coherent TCP/IPv4 fields and bounded first-segment length. | **High / Candidate / Shadow / minimum confidence 88% / threshold 3 / window 5m / cooldown 10m**. CONDITIONAL on visible plaintext FTP control traffic and genuine capture origin. |

**Malicious hypothesis:** a compromised host may issue upload commands to several independent external networks during multi-destination exfiltration or automation abuse. **Only the command requests are observed**: no server acceptance, data-channel bytes, file content, completed transfer, authentication, compromise or CVE exploitation is established. Authorized multi-site backups, mirroring, software distribution and managed FTP integrations can look identical. A public source IP is not authenticated; NAT, VPN, TCP segmentation, encrypted FTPS and incomplete capture limit coverage. Shadow mode must remain until approved-host/maintenance controls and independently labeled replay evidence exist.

## Evidence and integration

- Producer: existing `PacketHandler` first-segment TCP fast path → `NetworkBatch246250Wire.FtpUpload` → `TrafficRecord.ApplicationProtocol = ftp.stor / ftp.appe`. The rule checks `Id`, `IsTcp`, `IsUdp`, `IsQuic`, `IpVersion`, `Protocol`, source/destination IPv4, TCP ports, `L4Len`, `Length`, and contradictory HTTP/DNS/TLS fields. It does **not** parse `Info`, filenames or guessed services. `ApplicationProtocol` is publicly settable, so imported records could spoof the label; live packet-producer provenance is required before alert promotion.
- State is instance-owned and lock-protected: maximum 1024 source buckets, 32 destination subnets and 128 packet IDs per source; expired entries are pruned and capacity saturation fails closed. Duplicate IDs and out-of-order observations do not count. Completed triples are consumed; a new triple during cooldown is suppressed without event emission.
- Event evidence contains only fixed operation and count/window markers. No FTP path, payload, username, password or raw Info is persisted. The normal RuleEngine retains journal-first persistence, Disabled/Shadow policy and suppression. No UI, historical P ledger, shared sensor, journal, workflow or frozen holdout was changed.
- Confidence and policy of R102/R118/R163 remain at least 80/86/84%; V1 frozen R102 4/6 and pending V2 are untouched. This rule has no operationally verified precision, recall or false-positive rate.

**Changed files:** [R555 rule](../../../Carthago/Engine/Rules/Expansion/R555_ExternalFtpUploadCommandSubnetFanoutRule.cs), [advanced tests](../../../Carthago.Tests/R555AdvancedAccuracyBatchTests.cs), [registry](../../../Carthago/Engine/Rules/Catalog/RuleRegistry.cs), this GA report, and [detection backlog](../../rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md).

## Authored test scenarios — 0 executed

| Group | Source-authored assertions |
| --- | --- |
| Real producer and positive | PacketHandler STOR/APPE positive, RETR negative, parsed three-/24 end-to-end correlation, severity and aggregate event evidence. |
| Benign and spoofed | One/two public subnets, three hosts in one subnet, reserved/private destination, nonprivate source, RETR/LIST, Info-only and port-only labels. |
| Malformed/contradictory | Invalid packet ID, payload bounds, reverse TCP direction, UDP/QUIC, TLS, HTTP and DNS conflicts, IPv6. |
| Temporal and concurrency | Duplicate IDs, out-of-order timestamps, distinct source separation, expired five-minute window, consumed chain, cooldown suppression and concurrent arrivals. |
| Policy/privacy | Secret-marker redaction, unique registry entry, Candidate/Shadow/88% floor. |

**Exact source-authored count:** 20 xUnit methods (17 Fact + 3 Theory), 28 concrete invocations (17 Fact + 11 InlineData). **Executed: 0.** These assertions have not been compiled or run. Next owner-authorized validation should include real FTP server/data-channel outcomes, approved FTP inventories, TCP reassembly, imported-record spoofing and Windows full-suite execution.

## Threat research and limitations

- [RFC 959 — FTP](https://www.rfc-editor.org/info/rfc959/), October 1985: STOR/APPE request server-side storage, but commands alone do not establish data transfer.
- [MITRE ATT&CK T1048.003](https://attack.mitre.org/techniques/T1048/003/), last modified **2026-09-03**, documents FTP as one possible unencrypted exfiltration protocol. [DET0149](https://attack.mitre.org/detectionstrategies/DET0149/), modified **2026-05-12**, expects corroborating file/process/flow context absent from this packet-only rule.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [FIRST EPSS](https://www.first.org/epss/) are vulnerability-specific; no applicable R555 CVE exploitation or EPSS score is asserted. This is a behavioral candidate, **not a zero-day detector**.

## Publication review and next cursor

Only the five detection-owned files listed above are authorized. Publication requires a fresh live HEAD read and one non-forced expected-HEAD-protected atomic ref update; conflicting writers must stop. **Proposed next cursor: R556**, subject to a new registry/producer/dedup audit. Do not restart protocol GAs or add unsupported inspectors.
