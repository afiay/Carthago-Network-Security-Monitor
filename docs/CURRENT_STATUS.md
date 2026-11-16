# Carthago — current verification and authorization status

**Evidence reconciled 2026-11-16.** This page corrects misleading historical status labels. It is **not a new test, external evidence approval, deployment authorization, or latest-HEAD qualification**. Work takes place only on `feature/carthago-reliability-hardening`; preserve exact tested SHAs. A new commit does not inherit a prior PASS.

## Interpret status precisely

- **Owner-authorized**: a particular action or test was permitted, not necessarily performed or passed; this is not blanket permission to repeat live/invasive tests.
- **Implemented/candidate**: source exists, with execution or field claims limited to independent evidence.
- **Historical executed PASS**: the specific test, revision and scenario passed as recorded; it is not production readiness.
- **Pending**: a specific missing evidence or acceptance requirement.
- **Superseded historical statement**: a dated observation overtaken by later evidence in the same scope; retain it for audit.

## Reconciled progress and remaining gates

| Area | Verified or current classification | Evidence limits and sources |
| --- | --- | --- |
| Core detection rules | **1,000 registered R001–R1000** | Static source/tree reconciliation at `c54b87b4b6c6a7d82e64d7226f7c5899778d9313`; no blanket test/accuracy promotion. [Registry reconciliation](05-detection-quality/REGISTRY_RECONCILIATION_20261116.md). |
| Exact-ID positive/negative qualification | **Partial; still pending** | 27 classified Windows ID records: 17 historical-pass, 4 authored-unexecuted, 6 missing; another 973 IDs un-reconciled, not necessarily untested. Exact overall positive/negative counts unknown. [Exact-ID audit](05-detection-quality/EXACT_ID_QUALIFICATION_AUDIT.md). |
| Historical Windows TRX provenance | **6/42 original file copies linked; 36 unlinked; 41 unique TRX digests, 35 unique digests unlinked; 7 failure-containing TRX files** | Two original 189/189 TRX copies share one SHA-256, so they are not two independent execution proofs. Frozen 359-artifact recovery. New SOC 70/70 is outside this cohort; source filename hints do not attest execution. [42-file/41-digest backlog](05-detection-quality/HISTORICAL_42_TRX_BACKLOG_20261116.md). |
| Windows whole-suite xUnit | **Owner-reported historical PASS 14,361/14,361** at `3b54c742b5b1d2bfafc2d25840a7dfa34ee46f65` | Original TRX hash later confirmed, but strict contemporaneous runner-to-execution-SHA artifact linking remains missing for this run. This is not latest-source verification. [Validation ledger](DEVELOPMENT_VALIDATION_LEDGER.md), [evidence recovery](05-detection-quality/WINDOWS_EVIDENCE_RECOVERY_20261116.md). |
| Earlier pinned integration | **Windows 14,186/14,186 + CLI 653/653; benchmark PASS** at `ff35973a0373fb61ccee1a64d836944458d54f88` | Separate, source-linked earlier result, not SHA proof for the larger later Windows TRX. [GA-IQ-01](development/GA_IQ01_INTEGRATION_QUALIFICATION_20261113.md). |
| CLI Windows and Linux | **667/667 historical PASS on each platform** at `3b54c742b5b1d2bfafc2d25840a7dfa34ee46f65` | Linux total includes Windows-only early-return tests; count parity is not complete platform parity. [Validation ledger](DEVELOPMENT_VALIDATION_LEDGER.md). |
| Portable replay R586–R605 | **160/160 synthetic paired case executions PASS** at `dc43933775cb95a4685ecc860f93fa60b2ad3d1a` | 80 distinct PCAP/PCAPNG positive/negative cases, each executed on Windows and Linux. Not 160 rules or field validation. [Registry reconciliation](05-detection-quality/REGISTRY_RECONCILIATION_20261116.md). |
| Active sensors | **392/392 synthetic PASS and seven bounded physical gateway/SNMP lab cases PASS** at `ff35973a0373fb61ccee1a64d836944458d54f88` | General operational sensor health, unattended Windows services, coexistence and soak/release still pending. [Active Sensors](02-architecture/ActiveSensors.md). |
| Linux L8B | **Bounded non-root CAP_NET_RAW A/B and staging cleanup complete** at `dc43933775cb95a4685ecc860f93fa60b2ad3d1a` | Privilege masks verified on positive process; zero-capability negative inspected; no persistent Linux service or native physical deployment approval. L8C hosting/SIGTERM/recovery pending. [Validation ledger](DEVELOPMENT_VALIDATION_LEDGER.md). |
| Linux portable live monitor | **Bounded loopback and eth0 R586 capture, detection, journal and clean-stop evidence** | Not continuous unattended service or sustained network field assurance. [Validation ledger](DEVELOPMENT_VALIDATION_LEDGER.md). |
| DNS synthetic V2 contracts | **GA 6D 26/26, 6E 18/18, 6F 15/15 + 3/3, 6G sampled 3/6/12 rounds, 6H 6/6 GREEN** | Later Stage 6 synthetic auditor matrix cumulatively GREEN Nov 3; Stage 8 synthetic wire replay compatibility GREEN at `9f709d0`. The October parked matrix is historical. [Validation ledger](DEVELOPMENT_VALIDATION_LEDGER.md). |
| DNS compiler-guarded tests | **Stages 2, 3, 4 still pending** | Default xUnit excludes `DnsWirePacketTests`, `R102BinaryDnsPrecisionTests`, `DnsWireReplayHydratorTests` through `CARTHAGO_DNS_WIRE_STAGE2/3/4` guards. Do not infer them from aggregate test totals. |
| R102 independent holdouts | **V1 historical FAILED 4/6; V2 0/4 externally reviewed/approved R102 source pairs — PENDING** | Synthetic contract PASS is not source/rights/label approval, field accuracy, sample publication or freeze. [Holdout protocol](05-detection-quality/holdout/HOLDOUT_V2_PROTOCOL.md). |
| SOC workspace | **Verifier bug CLOSED; Windows SOC 70/70 and original-artifact hashes PASS at pinned SHA; G5/G6 manual/operational acceptance NO-GO pending** | Owner ran 27/27 offline assertions and 70/70 SOC tests at `971892ef4d18e18cbb2d8317c23c0ada64c2dc19`, produced a durable completion report, and confirmed the original TRX/source/log hashes match. This is **not** a manual WPF render, physical capture or field-accuracy approval. [Closure](05-detection-quality/SOC_VERIFIER_BUG_CLOSURE_20261116.md), [G5/G6 runbook](08-operations/guides/WPF_OPERATIONAL_ACCEPTANCE_G5_G6.md). |
| Windows SCM services | **Source candidates; service qualification pending** | Authorized/synthetic tests do not qualify native startup, dedicated identity, stop, journal/crash recovery, coexistence, soak or automatic startup. [Monitor guide](08-operations/guides/CARTHAGO_WINDOWS_MONITOR_SERVICE.md), [active service](08-operations/guides/CARTHAGO_WINDOWS_ACTIVE_SERVICE.md). |
| Detection visibility / incident rule links | **Source fix + regression tests authored; execution pending** | Persisted incident rule/event IDs are retained; Detection Coverage now adds per-rule no-alert diagnoses, match-to-emission counters, two-refresh engine progress, diagnostic filters and bounded copy text. Read-only source/tests authored only; no Windows build, xUnit evidence, live capture or accuracy approval on these commits. [Visibility fix and verification plan](05-detection-quality/DETECTION_VISIBILITY_FIX_20261116.md). |
| GUI and enrichment | **Implemented work in progress; end-to-end acceptance pending** | No implicit visual/DPI/runtime/physical qualification, nor current-source claim from older green tests. [UI ledger](design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md), [enrichment qualification](ENRICHMENT_QUALIFICATION.md). |

## Superseded statements that must not be treated as live blocks

| Historical wording | Current interpretation |
| --- | --- |
| October 30 "current GA verification" or PARKED V2 synthetic checks | Date-limited historical table; later owner results close named synthetic gates only. |
| Active sensors "Windows build/tests/live smoke pending" | Superseded for 392 synthetic checks and seven bounded physical lab cases; operational release still open. |
| CLI-001 "not a headless detection engine" | Initial CLI-001 only; later portable foreground capture/detection/journal capability has bounded qualification. |
| R001–R005 "do not begin R006–R010" and "544-rule full suite" | Historical batch policy, not current execution stop order; registered rules now R001–R1000, without automatic per-rule qualification. |
| Windows evidence "pending local reconciliation" | Later sections record completed read-only owner checks; large 14,361 TRX SHA-link deficit remains. |
| Early L8B "capability masks and staging cleanup pending" | Closed by later evidence; L8C remains unqualified. |
| V2 auditor script "PARKED" | Original authorization guard; synthetic matrix later executed, external V2 R102 evidence still pending. |

## Documentation maintenance contract

Preserve original historical test results, failed holdouts, batch records, and path-stable automation files. Add a dated top-of-file status overlay and a source link when an earlier pending state is superseded. Never overwrite evidence, infer per-rule quality from aggregate xUnit totals, or promote a historical PASS to moving HEAD. Run `python scripts/build_docs_index.py --check`, `python scripts/check_docs_links.py`, and `python scripts/check_docs_status.py` after documentation changes. These are documentation-only checks.
