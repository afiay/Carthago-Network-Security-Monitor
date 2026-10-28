# R241–R245 — BACnet/NTP operation provenance and upload-request precision

**CANDIDATE — UNVERIFIED.** Authored 2026-10-28 on `feature/carthago-reliability-hardening`. **60 advanced rule xUnit facts (12 per rule) plus 6 bounded OT/NTP parser facts authored; zero executed.** No builds, tests, replays, holdouts, CI or Windows runner launched.

## Changed paths

Production: `Carthago/Engine/Rules/Expansion/R241_BacnetWhoIsIAmBurstRule.cs`, `R242_NtpAmplificationCandidateRule.cs`, `R243_LargeOutboundArchiveTransferRule.cs`, `R244_DatabaseDumpFilenameTransferRule.cs`, `R245_SensitiveFileExtensionUploadRule.cs`, `NetworkBatch241245Evidence.cs`, `CloudDevPrecisionDetectionRuleBase.cs`, `Carthago/Engine/Rules/IotOt/IotOtPrecisionDetectionRuleBase.cs`, and `Carthago/Services/OtProtocolLight.cs`.

Tests: `Carthago.Tests/NetworkBatch241245Context.cs`; `R241AdvancedAccuracyBatchTests.cs`, `R242AdvancedAccuracyBatchTests.cs`, `R243AdvancedAccuracyBatchTests.cs`, `R244AdvancedAccuracyBatchTests.cs`, `R245AdvancedAccuracyBatchTests.cs` (12 each); 6 new cases in `Carthago.Tests/OtProtocolLightTests.cs`. All unexecuted.

## Observable contracts and authored coverage

- **R241 (12):** UDP/47808 with parser-attributed BACnet unconfirmed Who-Is or I-Am operation, 15 independent packet IDs per source within two minutes. Includes typed positive, below-threshold benign, generic BACnet and Info spoof, transport/port contradiction, duplicate IDs, source isolation, out-of-order, expiry, evidence privacy, and original Shadow/76 contract. BVLC/NPDU/APDU parser recognizes only unconfirmed-service APDU at fixed offset; routing/segmentation variations remain unsupported.
- **R242 (12):** UDP/123 with parsed NTP private mode-7 MON_GETLIST_1 request (implementation 3, request code 42), five independent packets per source/destination within two minutes. Includes typed positive, benign time sync, port/Info spoof, contradictory transport, duplicate IDs, source isolation, out-of-order, expiry, privacy, and original Alert/80. This is **probing/request evidence**, not a measured reflection or amplification factor.
- **R243 (12):** Parsed cleartext external HTTP POST/PUT/PATCH with a filename-ending archive path and **declared Content-Length >=100 MiB**. The rule now says *upload request declared*, not archive transferred. Includes exact positive, close benign, method, TLS, internal boundary, missing length, approved sync client, UDP contradiction, duplicate/out-of-order, redaction, and original Alert/82.
- **R244 (12):** Parsed cleartext external HTTP upload request with dump/backup/export-named database artifact path and a declared body length. Does **not** infer DB contents or transfer completion. Same independent operational/negative/state/privacy/policy coverage; original Alert/86.
- **R245 (12):** Parsed cleartext external HTTP upload request with exact secret-bearing filename/extension; generic JSON/CSV is not a positive. No raw filename or token is persisted in rule-owned evidence. Same independent operational/negative/state/privacy/policy coverage; original Alert/83.

## Parser evidence and known limitations

`OtProtocolLight.TryIdentifyUdp` now identifies bounded BACnet Who-Is/I-Am from BVLC length, NPDU version/control and unconfirmed APDU service byte; recognizes mode-7 NTP monlist request only from version 3/4, implementation 3, response bit clear, destination UDP/123 and request code 42. The existing `PacketHandler` already routes UDP payloads to this parser. **No stream reassembly, authenticated BACnet operation validation, NTP response-size evidence, or proven amplification** is provided. Six parser facts cover positive BACnet Who-Is/I-Am, generic BACnet, NTP monlist, ordinary NTP sync and mode-7 response rejection.

R243–R245 require a parser-attributed cleartext HTTP request, a literal filename in the URL path and a single well-formed Content-Length header. `Content-Length` is **declared**, not transmitted bytes; a filename is an indicator, not file-content evidence. Multipart filenames in an unparsed request body and HTTPS uploads are **not observable** by this contract. The original approved-sync/backup suppression is preserved. Shared event evidence redacts host/path/destinationHost and avoids raw Info/secret values for these rules. False-negative risk is material when only encrypted HTTP, chunked uploads, body-only multipart filenames, process attribution gaps or absent Content-Length exist.

No confidence floors, modes, thresholds, asset approval or baseline-readiness gates were relaxed. Frozen R102 V1 remains **FAILED at 4/6**, immutable; V2 remains pending independent licensed PCAP and separate analyst approval. The single deferred Windows verifier `scripts/verify-all-rule-batches.ps1` is unchanged and unexecuted.

**Next consecutive five: R246–R250; then R251–R255.**
