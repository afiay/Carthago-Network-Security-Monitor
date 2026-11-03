# R251–R255 — conservative cleartext HTTP exfiltration request contracts

**CANDIDATE — UNVERIFIED.** Authored 2026-10-28 on `feature/carthago-reliability-hardening`. **52 advanced rule xUnit facts authored (R251=12; R252–R255=10 each); ZERO executed.** No builds, xUnit, replay, benchmark, holdout, CI or Windows runner.

## Changed paths

Production: `Carthago/Engine/Rules/Expansion/R251_MultipartUploadToUnknownDomainRule.cs`, `R252_HighEntropyOutboundUriPathRule.cs`, `R253_Base64BlobInHttpPostRule.cs`, `R254_RepeatedSmallChunkUploadsRule.cs`, `R255_OffHoursBulkEgressIndicatorRule.cs`, `NetworkBatch251255Evidence.cs`, and `CloudDevPrecisionDetectionRuleBase.cs`.

Tests: `Carthago.Tests/NetworkBatch251255Context.cs`, `R251AdvancedAccuracyBatchTests.cs` through `R255AdvancedAccuracyBatchTests.cs`, 52 unexecuted facts.

## Observable contracts and authored scenarios

- **R251 (12):** Parsed private-to-external cleartext HTTP multipart/form-data request, single valid boundary header, DNS hostname outside fixed common cloud-root exclusions, and first observation by this detector instance and source. Includes positive, plain form, Info spoof, sanctioned root, IP literal, internal destination, duplicate, first-observation reuse, independent source, contradictory Host, privacy and original Alert/84. **First observed in instance memory is not a durable approved baseline, domain age, analyst-approved novelty or file-body evidence.** Requires baseline integration before using as a trusted first-seen-domain signal.
- **R252 (10):** Parsed external cleartext HTTP upload with 32–256 character alphanumeric path segment entropy >=4.2, excluding browser clients. Includes positive, readable benign, browser, Info spoof, GET, TLS contradiction, duplicate, out-of-order, token redaction and original Shadow/74. **High entropy is not proof of exfiltration.**
- **R253 (10):** Parsed external cleartext HTTP upload with 64+ decoded bytes in an allowlisted `data`, `payload` or `blob` query parameter and exact process identity. Includes positive, JWT-only benign, Info spoof, short token, unrelated parameter, missing process, TLS contradiction, replay/out-of-order, redaction and original Alert/82. **The request body is NOT observable: this is query-only evidence, not a base64 POST-body finding.** Raw encoded values are never emitted.
- **R254 (10):** Parsed external cleartext HTTP POST/PUT/PATCH with single declared Content-Length 1–128 KiB; 12 distinct request record IDs within five minutes per source/destination/SHA256-path fingerprint. Includes threshold, below-threshold, duplicate, out-of-order, source and path isolation, expiry, approved sync, path privacy and original Alert/82/threshold12. **Repeated requests are not proof of transferred chunks.**
- **R255 (10):** Parsed external cleartext HTTP upload request with Content-Length >=250 MiB, independently attributed automation process, UTC off-hours/weekend heuristic, approved sync/backup suppression. Includes positive, business hours, small declared body, Info spoof, missing process, approved backup, TLS contradiction, duplicate, path privacy and original Alert/78. **UTC is not asset-local business time, and declared body length is not transmitted bulk egress.**

## Privacy, state and missing observability

Rule-owned state is instance-scoped and bounded: first-observed domain keys capped at 2048 with stale eviction; repeated small requests use the existing 512-ID per-source bounded monotonic window and a SHA256 path fingerprint, not raw paths. R251–R255 event evidence redacts clouddev.host, http.path and destinationHost, including structured evidence; no raw query token or packet Info is promoted to evidence. Process names are checked by exact executable allowlist for R253/R255; untrusted User-Agent does not substitute for process enrichment.

HTTP request bodies, HTTPS, multipart file bytes, completed uploads, TCP unique delivered bytes, domain registration age, durable approved first-seen baseline, and asset-local business schedule are **not observed** by these contracts. R251's instance-first observation must not be represented as baseline approval. Confidence floors, modes, thresholds, asset approvals, baseline readiness and frozen evidence are unchanged. Frozen R102 V1 FAILED 4/6; V2 pending independent licensed PCAP and analyst review. The sole deferred Windows verifier `scripts/verify-all-rule-batches.ps1` remains unchanged and unexecuted.

**Next consecutive five: R256–R260, then R261–R265.**
