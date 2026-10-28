# R246–R250 — typed exfiltration-request and bounded protocol attribution

**CANDIDATE — UNVERIFIED.** Authored 2026-10-28 on `feature/carthago-reliability-hardening`. **52 advanced rule xUnit facts (R246=11, R247=10, R248=10, R249=10, R250=11) plus 10 FTP/SMB wire-parser facts authored; ZERO executed.** No builds, xUnit, replays, benchmarks, holdouts, CI or Windows runner were launched.

## Changed paths

Production: `Carthago/Engine/Rules/Expansion/R246_SourceCodeArchiveUploadRule.cs`, `R247_SshScpHighVolumeEgressRule.cs`, `R248_FtpUploadToExternalHostRule.cs`, `R249_SmbUploadToExternalHostRule.cs`, `R250_LargeHttpPostToIpLiteralRule.cs`, `NetworkBatch246250Evidence.cs`, `CloudDevPrecisionDetectionRuleBase.cs`, `Carthago/Services/NetworkBatch246250Wire.cs`, and `Carthago/Services/PacketHandler.cs`.

Tests: `Carthago.Tests/NetworkBatch246250Context.cs`; `R246AdvancedAccuracyBatchTests.cs` through `R250AdvancedAccuracyBatchTests.cs`; `NetworkBatch246250WireTests.cs`. All authored, unexecuted.

## Evidence contracts and tests

- **R246 (11):** Private-to-external parsed cleartext HTTP POST/PUT/PATCH, source/repository-token archive filename in URL path, single declared Content-Length, approved sync/backup and official Git-client suppressions. Tests cover typed positive, generic archive, nonarchive, Info spoof, approved Git and sync, TLS contradiction, replay/out-of-order, redaction, Alert/82. **Request filename and declared length do not prove archive contents or delivery.**
- **R247 (10):** Internal-to-external TCP/22, exact SCP/SFTP process name and bounded per-instance **unique packet-ID observed byte window** (150 MiB within 20 min, up to 4096 packet IDs per source/target). Tests use 2401 distinct 65535-byte packet records to cross the threshold, with below-threshold, process/Info spoof, approval, TLS contradiction, duplicate, out-of-order, independent source, expiry and Alert/82 coverage. **Observed packet bytes include headers/retransmissions and do not establish unique TCP bytes, SCP direction or completed transfer.** Process enrichment remains unverified; no SSH decryption. A production-grade TCP sequence-aware volume source is still needed.
- **R248 (10):** Internal-to-external TCP/21, captured-byte FTP STOR/ APPE client command classification. Tests cover positive STOR/APPE, LIST benign, Info spoof, reversed control direction, internal destination, UDP contradiction, replay/out-of-order, redaction, Alert/82. **A control command is not evidence of data-channel completion.**
- **R249 (10):** Internal-to-external TCP/445, bounded NetBIOS-session/SMB2 WRITE request header, request direction and length consistency. Tests cover typed positive, CREATE/read-like benign, Info spoof, response, internal/wrong port, TLS contradiction, replay/out-of-order, privacy, Alert/86. **A WRITE request is not proof that the server accepted or persisted bytes.**
- **R250 (11):** Parsed cleartext external HTTP POST/PUT/PATCH, HTTP Host is the exact destination IP literal, consistent Host header, a single declared Content-Length >=20 MiB. Tests cover positive, named-host benign, small declared body, Info spoof, duplicate/contradictory headers, TLS contradiction, GET, replay/out-of-order, privacy, Alert/83. **Declared body length is not transferred bytes.**

## Parser and privacy limitations

`NetworkBatch246250Wire` parses a bounded first-segment FTP command line and SMB2 WRITE request frame; `PacketHandler` routes the normalized TCP payload only for client-to-server observations. Ten unexecuted parser facts cover FTP STOR/APPE, LIST, reversed direction, malformed framing, SMB2 WRITE, CREATE, response, length and wrong port. Fragmented/reassembled FTP commands, SMB3 encryption, SMB data completion, FTPS, SSH payloads and HTTPS remain unsupported. `TrafficRecord` has no verified unique-flow transfer counter. Existing `Sni`/`TlsSni` alias and DNS answer/TTL live gaps remain.

Shared event evidence now redacts host, HTTP path and destinationHost for R246–R250; the rule-owned evidence contains only classifications and numeric declared/observed counters, not FTP filenames, SMB paths, raw Info or HTTP request URI. Existing privacy for earlier rules remains unchanged.

Original confidence floors and default modes for R246–R250 remain Alert/82, Alert/82, Alert/82, Alert/86 and Alert/83. Existing global floors R102=80, R118=86, R163=84, thresholds, approval/baseline gates and frozen evidence are unchanged. Frozen R102 V1 FAILED 4/6; V2 pending independent licensed PCAP and analyst approval. `scripts/verify-all-rule-batches.ps1` remains the sole deferred Windows verifier, unexecuted.

**Next consecutive five: R251–R255, then R256–R260.**
