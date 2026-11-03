# CARTHAGO — GA R554: SMB2 write-request fanout followed by FTP upload command

**Branch:** feature/carthago-reliability-hardening  
**Base HEAD:** 66cb4863f6051bd4c2f7e9832760cb34199350aa (2026-11-02).  
**Source/test/documentation commit:** the cohesive commit containing this document; **publication SHA:** the non-forced, expected-HEAD-protected branch ref after publication (a commit cannot include its own SHA).  
**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**. No build, replay, holdout, CI, runner or live capture.

## Rule decision and evidence reachability

| Rule | Historical research and overlap | Observable predicate and producer | Mode / policy / disposition |
| --- | --- | --- | --- |
| **R554 — SMB2 Write Requests Followed by External FTP Upload Command** | **P0006 SMB** partial first-segment recognition; FTP control-command recognition already exists in R248 and NetworkBatch246250Wire (no invented P identifier). R553 counts three internal SMB2 WRITE destination subnets; R248 matches an external FTP upload command; R256 is repeated internal HTTP staging; R257 is credential-process/HTTP co-observation. None requires this exact two-subnet SMB2-to-external-FTP sequence. | One RFC1918 IPv4 source emits bounded PacketHandler-classified SMB2 WRITE request shapes to **two distinct other private /24s**, then a PacketHandler-classified FTP STOR/APPE control request to a public IPv4 address **strictly later and within 120 seconds of both SMB observations**. All observations are within five minutes. | **High / Candidate / Shadow / minimum confidence 88% / threshold 2 private subnets / 5-minute observation / 120-second sequence / 10-minute cooldown.** **CONDITIONAL** on visible unencrypted first TCP segments and the same capture vantage point. One registered ordinary rule; no new decoder or shared telemetry. |

**Falsifiable value:** this sequence may indicate a host writing to multiple internal shares and then attempting an external cleartext upload. It does **not** prove the host read or staged files, accessed authenticated shares, wrote successfully, delivered FTP data, received server acceptance, or exfiltrated anything. It does not identify a CVE or a zero-day. Backup, patch deployment, replication, legacy integrations and authorized maintenance are realistic lookalikes. FTP commands can be followed by failed data connections. SMB encryption and FTPS make payload classification unavailable. Source IP is a network observation, not authenticated identity; NAT/VPN and packet loss can misattribute or conceal a chain.

## Source, privacy and compatibility boundaries

- The existing PacketHandler TCP fast path calls NetworkBatch246250Wire.Smb2Write and FtpUpload only for first-segment, client-to-server byte shapes; the rule consumes their typed ApplicationProtocol labels plus coherent IPv4/TCP, ports, bounded L4Len and frame Length. No Info, guessed service name, arbitrary header, process label, file path, packet body, SMB user or credential is trusted as a positive.
- SMB2 requires TCP/445, request shape, at least 117 visible payload bytes and at most 4096; FTP requires TCP/21, STOR/APPE shape, 8–256 visible payload bytes, a public unicast IPv4 destination and a private IPv4 source. Source port must be a client port >=1024. Reject contradictory HTTP/DNS/TLS/QUIC fields.
- Instance-owned state: at most 1024 sources, 32 destination subnets and 128 packet IDs per source; monotonic timestamps; packet-ID deduplication; stale expiry; fail-closed on capacity. A completed chain consumes its SMB candidates; subsequent FTP commands alone cannot retrigger. New chains during cooldown return SuppressedMatch without emitting an event.
- Only fixed, aggregate, parser-attributed evidence is emitted. Raw Info, FTP paths, SMB paths, usernames and payloads are never copied. RuleEngine remains responsible for normal DetectionEvent handling, mandatory JSONL journal-first persistence, Shadow/Disabled modes and suppression policy. No direct UI/incident/sink calls.
- No changes to PacketHandler, TrafficRecord, TrafficCaptureService, rules R001–R553, profiles, frozen holdouts, UI/design, historical protocol GAs, runners, workflows or detection progress ledger. Preserve R102/R118/R163 floors 80/86/84% and all current precision policies.

**Owned files in this GA:** [rule source](../../../Carthago/Engine/Rules/Expansion/R554_Smb2WriteThenExternalFtpUploadRule.cs), [advanced xUnit tests](../../../Carthago.Tests/R554AdvancedAccuracyBatchTests.cs), [explicit registry](../../../Carthago/Engine/Rules/Catalog/RuleRegistry.cs), this document and the [detection-only backlog](../../rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md).

## Authored scenario matrix — not executed

| Source-authored scenario group | Intent |
| --- | --- |
| Producer and positive correlation | Actual PacketHandler SMB2 WRITE and FTP STOR/APPE classification; two distinct remote private subnets then public FTP within 120 seconds; High severity, count and fixed evidence. |
| Benign/cross-protocol negatives | FTP alone, SMB alone, one subnet, same source subnet, FTP before second SMB, unrelated source, RETR/LIST, internal and reserved destinations. |
| Malformed, spoofed and encrypted evidence | SMB CREATE/response, truncated FTP/SMB, wrong payload length, missing ID, Info/port-only claims, contradictory UDP/HTTP/DNS/TLS/QUIC and IPv6. |
| Temporal and resource safety | Duplicate IDs, out-of-order timestamps, inclusive 120-second boundary, expiry, cooldown suppression, consumed-chain replay and concurrent FTP evaluations. |
| Privacy, mode and registration | Raw Info and sensitive filenames absent from event evidence; unique R554 registry entry; Candidate maturity, Shadow default and 88% minimum confidence. |

**Exact authored count:** 23 xUnit test methods (21 Fact + 2 Theory), 29 concrete invocations (21 Fact cases + 5 destination Theory cases + 3 FTP-operation Theory cases). **Executed: 0.** These source-only assertions are unverified; no compilation, pass rate, field precision, recall, F1, throughput or operational alert coverage is claimed. Synthetic fixtures contain no credentials or private capture. First authorized validation must include real first-segment TCP reassembly/fragmentation and encrypted-path negatives, trusted sensor origin, representative backup/FTP allowlist controls, registry/config/journal integration and Windows full-suite execution.

## Primary threat references and limits

- [RFC 959 — File Transfer Protocol](https://www.rfc-editor.org/info/rfc959/), October 1985: STOR and APPE are FTP control commands requesting server-side storage/append; the command is not a transfer outcome.
- [MITRE ATT&CK T1048.003](https://attack.mitre.org/techniques/T1048/003/), last modified **2026-09-03**: unencrypted non-C2 protocol exfiltration can use FTP, HTTP or DNS; its detection guidance requires staging/file/process evidence that this packet-only correlation does not establish.
- [MITRE ATT&CK T1021.002](https://attack.mitre.org/techniques/T1021/002/), last modified **2026-05-12**: SMB/Windows Admin Shares lateral movement; R554 cannot identify ADMIN$ or authenticated share access.
- [Microsoft SMB signing/encryption overview](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview): passive capture does not expose encrypted SMB application content.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [FIRST EPSS](https://www.first.org/epss/): no R554-specific confirmed exploited vulnerability or CVE-specific EPSS score was established. **Threat classification: UNVERIFIED**, not a CVE/zero-day detector.

## Pre-publication source-only review and next GA

The live base registry contained unique R001–R553 and no R554; recent intervening commits were UI-only GA UI-77. The only intended changed paths are the five detection-owned files above. Publication requires re-reading live HEAD and a single non-forced expected-HEAD-protected atomic update; on overlapping edits or stale lease stop rather than overwrite. Tests remain **0 executed**.

**Next proposed cursor: R555**, conditional on fresh live registry, source-provenance and duplicate-coverage audit. Block authenticated SMB outcomes, decrypted FTPS and trusted file-access claims until owner-approved producers exist; do not add speculative rules or resume P protocol GAs.
