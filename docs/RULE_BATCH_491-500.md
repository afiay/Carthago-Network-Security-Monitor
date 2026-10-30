# GA R491–R500 — GOOSE, historian and sensitive-transfer evidence boundaries

**SOURCE CANDIDATE — UNVERIFIED · 2026-10-30.** Branch: `feature/carthago-reliability-hardening`. Inspected live base HEAD `316004fc4fe176ee3250add7c530282d3af30396`; source commit `77fd467f292c0b4ddccac0b28c2134f450f4baef`; authored-test commit `e64a5a3fcbedb5c3f7bea0ad842e4c016729e282`. The final documentation-descendant publication commit is the live branch ref after the expected-HEAD update; a Git commit cannot contain its own SHA. **230 concrete xUnit invocations AUTHORED; 0 EXECUTED.** No build, test, replay, holdout, CI, runner, benchmark or production capture.

## Evidence-first review and dispositions

[TrafficRecord](../Carthago/Models/TrafficRecord.cs) contains network/HTTP/process/packet metadata but no authenticated local file read, file-content identity, clipboard event, remote-desktop file-channel operation, verified upload completion, historian query result, or trusted asset inventory. [PacketHandler](../Carthago/Services/PacketHandler.cs) drops non-IP EtherTypes on its fast path, including IEC 61850 GOOSE (0x88B8). HTTP method, URI, request headers, process names, port 22, byte counts, protocol labels, synthetic Info strings and TLS metadata cannot be promoted to file-content provenance or successful outcomes. HTTPS payloads are not decrypted. The existing [OT recognizer](../Carthago/Services/OtProtocolLight.cs) does not supply GOOSE APDUs or historian query operations.

| Rule / original name | Missing trustworthy producer | Original Alert profile (severity; floor; threshold; window; cooldown) | Disposition / legitimate-traffic risk |
| --- | --- | --- | --- |
| R491 GOOSE Multicast Outside Substation | L2 GOOSE APDU, trusted publisher and substation boundary | Critical; 86%; 1; 10m; 45m | **BLOCKED** · `GOOSE_LAYER2_FRAME_AND_SUBSTATION_POLICY_UNAVAILABLE`; Approved IEC 61850 multicast between substations or maintenance labs |
| R492 Historian Bulk Query From Workstation | Trusted historian identity, decoded query/result volume, workstation role | High; 86%; 4; 10m; 45m | **BLOCKED** · `HISTORIAN_QUERY_IDENTITY_VOLUME_AND_SOURCE_POLICY_UNAVAILABLE`; Scheduled historian export, reporting and maintenance |
| R493 Browser Password Store File Upload | Trusted local credential-store file identity and upload correlation | Critical; 84%; 1; 20m; 35m | **BLOCKED** · `BROWSER_PASSWORD_STORE_FILE_UPLOAD_PROVENANCE_UNAVAILABLE`; Managed backup, DLP exercise and browser profile migration |
| R494 SSH Private Key Upload | File-read provenance, transfer direction, body association and outcome | Critical; 84%; 1; 20m; 35m | **BLOCKED** · `SSH_PRIVATE_KEY_FILE_UPLOAD_PROVENANCE_UNAVAILABLE`; Approved key escrow, encrypted backup, controlled key rotation |
| R495 KeePass Database Upload | Trusted KDBX identity, local file access and outbound transfer correlation | Critical; 84%; 1; 20m; 35m | **BLOCKED** · `KEEPASS_DATABASE_FILE_UPLOAD_PROVENANCE_UNAVAILABLE`; Approved encrypted vault backup and cloud sync |
| R496 VPN Config File Upload | Trusted local VPN configuration file and external upload correlation | High; 84%; 1; 20m; 35m | **BLOCKED** · `VPN_CONFIGURATION_FILE_UPLOAD_PROVENANCE_UNAVAILABLE`; Legitimate VPN provisioning, support and backup |
| R497 Browser Cookie Database Upload | Trusted cookie database identity, file access and transfer correlation | Critical; 84%; 1; 20m; 35m | **BLOCKED** · `BROWSER_COOKIE_DATABASE_UPLOAD_PROVENANCE_UNAVAILABLE`; Profile migration, endpoint backup and forensic collection |
| R498 Large Clipboard Sync Upload | Local clipboard origin/size, approved sync agent and correlated upload | Medium; 84%; 1; 20m; 35m | **BLOCKED** · `CLIPBOARD_CONTENT_AND_SYNC_TRANSFER_PROVENANCE_UNAVAILABLE`; Accessibility tools, approved clipboard sync and remote work |
| R499 Remote Desktop File Transfer Burst | Authenticated remote session, file-channel events, distinct transfers and baseline | High; 84%; 4; 10m; 35m | **BLOCKED** · `REMOTE_DESKTOP_FILE_CHANNEL_BURST_PROVENANCE_UNAVAILABLE`; Authorized helpdesk, remote administration and file copy |
| R500 Compressed Archive Then Cloud Upload | Ordered archive creation, local file identity and correlated cloud upload | High; 84%; 1; 20m; 35m | **BLOCKED** · `ARCHIVE_CREATION_TO_CLOUD_UPLOAD_CORRELATION_UNAVAILABLE`; Scheduled backups, deployment packages and artifact publishing |

**All ten BLOCKED:** no validated operational positive can be represented with current producers. The new guards prevent unsupported alerts, not prove detection recall, accuracy or successful upload prevention. Missing core telemetry returns `MISSING_CORE_TELEMETRY` where the shared evaluator is reached. For otherwise populated records the explicit evidence-gap code above is returned before generic scoring, threshold counting, cooldown mutation or event construction.

## Source, original contracts and divergence review

Source-only changes are limited to [shared evaluator](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs), [OT operation boundary](../Carthago/Engine/Rules/Expansion/OtDeepOperationEvidenceBoundary.cs), new [sensitive-transfer boundary](../Carthago/Engine/Rules/Expansion/SensitiveTransferEvidenceBoundary.cs), [authored tests](../Carthago.Tests/NetworkBatch491500AccuracyTests.cs), this batch document and [progress ledger](RULE_HARDENING_PROGRESS.md). No original R491–R500 classes, shared models, capture services, UI, runners, workflows, baselines, approvals, journal, or frozen evidence are modified.

R491–R492 keep their original 86% confidence floors, 10-minute windows and 45-minute cooldowns; R492 retains threshold **4**. R493–R500 keep 84%, Alert mode and 35-minute cooldowns. R499 retains threshold **4**, 10-minute window and zero minimum bytes; the other data-loss rules retain threshold **1**, 20-minute window and the original **5,242,880-byte** minimum. All original severities and other policy settings remain intact.

Original source inconsistencies are documented, not silently changed: R491's IP-flow-oriented spec cannot observe GOOSE L2 frames; R492 has generic OT and database-port indicators without a historian query/result producer; R494 combines `RequireHttp=true` with port 22 despite SSH/SFTP being encrypted native protocols; R495 has no file-path indicator; R498 lacks a clipboard producer; R499 lacks authenticated RDP channel evidence; R500 has no archive-creation-to-upload correlation. The generic `MinimumBytes` gate uses packet/flow size rather than a verified uploaded sensitive file, and the 5 MiB threshold may miss smaller credentials and keys. No thresholds were lowered.

**Privacy:** Do not capture credential-store contents, private keys, cookie values, clipboard text, VPN secrets, or arbitrary upload bodies. Future integrations should use authorized, privacy-preserving file identity or classification, bounded size/timing metadata, redacted identifiers, provenance-backed event correlation, consent and retention controls. Request-target and retained-header redaction require separate review. No new credential collection or secret persistence is introduced.

**Start/end static divergence controls:** inspected live HEAD, R481–R490 source/tests/docs, actual R491–R500 rule definitions, [PacketHandler](../Carthago/Services/PacketHandler.cs), [TrafficRecord](../Carthago/Models/TrafficRecord.cs) and shared evaluator. Added only explicit fail-closed missing-producer contracts; no speculative event types, parser rewrites, API/schema changes, dynamic state or policy relaxation. Before publication verify the six owned paths, exact three-commit ancestry, source/test/docs blobs, remote HEAD lease and nonoverlap with UI. This review is source-only, not compilation or field validation.

## Authored xUnit scenario matrix — UNEXECUTED

[NetworkBatch491500AccuracyTests](../Carthago.Tests/NetworkBatch491500AccuracyTests.cs) has **22 named variants × 10 rules = 220 concrete xUnit invocations**, plus **10 original-profile invariants**, totaling **230 authored, 0 executed**. Each variant is applied independently to every R491–R500 rule:

1. `plausible` — ordinary port/path/process clues only
2. `wire-label-only` — application label without validated protocol operation
3. `descriptor-spoof` — spoofed rule description and claimed result
4. `approved-activity` — approved backup or historian maintenance
5. `forged-audit` — forged authentication and upload audit headers
6. `tls-only` — TLS metadata without decrypted application evidence
7. `missing-source` — missing source address
8. `missing-destination` — missing destination and host provenance
9. `malformed` — malformed URI and truncated packet
10. `synthetic-secret` — redacted synthetic placeholder, never a real secret
11. `wrong-direction` — reversed network direction
12. `wrong-protocol` — incorrect transport protocol
13. `threshold-burst` — six distinct repeated observations without trusted evidence
14. `claimed-success` — fabricated success/acknowledgment text
15. `duplicate-id` — replayed duplicate record identity
16. `spoofed-process` — spoofed trusted process and application-service labels
17. `fragmentary` — fragmentary or zero-length payload
18. `after-cooldown` — repeated observations beyond original cooldown
19. `cross-boundary` — external trust-boundary clue without provenance
20. `spoofed-authority` — forged trusted file/asset authority headers
21. `request-only` — outbound PUT request without correlated server result
22. `response-only` — response-like text without authenticated request association

The profile invariant separately asserts original Alert mode, confidence, threshold, window and cooldown for every rule. Positive operational cases are intentionally absent: no trusted file/OT producer is available. The tests are authored, **not executed**; no pass, detection quality or certification claim is made.

## Outstanding quality GAs and next batch

Windows compilation and 230 authored xUnit executions remain unapproved. Subsequent independent integration GAs must provide trustworthy GOOSE L2 capture and substation inventory; historian query/result and workstation authorization; privacy-preserving file/process events correlated to outbound flows; authenticated remote-session transfer evidence; archive creation/upload sequence and outcome separation; calibrated benign/attack datasets and field false-positive/recall measurements. Existing R102 frozen evidence and R343/R295/R275/R163 replay obligations remain independent.

**Next contiguous ten-rule development GA: R501–R510**, subject to fresh live source/ledger inspection and confirmation these IDs exist and are unfinished. Do not start that batch before this complete candidate is safely published.

## References

- [Rule documentation standard](rules/RULE_DOCUMENTATION_STANDARD.md)
- [Wireshark GOOSE protocol field reference](https://www.wireshark.org/docs/dfref/g/goose.html) — GOOSE protocol identification, not evidence that Carthago decodes it.
- [Microsoft Defender XDR DeviceFileEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) — example of distinct file-event provenance, **not** an integrated Carthago producer.
- [Microsoft Defender XDR DeviceNetworkEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) — example network-event source; joining events requires validated identity/time correlation.
