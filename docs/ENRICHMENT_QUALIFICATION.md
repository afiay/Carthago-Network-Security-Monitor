# Enrichment Phase 16.1 — focused Windows qualification

Parent: `af7d218642ebfcb4d2257ade26a310a343ce6c1c`; tree: `b67a68d8dbb87ef3de24e5a87c2dc3b489ff6e06`. Reviewed root verify-local.ps1, Windows test project, worker health source/tests, test inventory and development ledger. The existing full verification runner remains unchanged; this companion is intentionally scoped to enrichment and asset/communication tests.

Run from a clean Windows checkout:

```powershell
git switch feature/carthago-reliability-hardening
git pull --ff-only origin feature/carthago-reliability-hardening
.\verify-enrichment.ps1 -SelfTest
.\verify-enrichment.ps1 -LiveOutput
```

Each run uses a unique build-verify/enrichment directory, records exact HEAD, Release test-project build (including app reference), filters, exit codes, TRX counters and JSON summary. Zero tests, skipped tests, missing/malformed TRX, failures or source changes cannot qualify. The two groups are selected from existing test classes; counts are measured, not assumed. SelfTest checks four synthetic TRX outcomes and missing evidence. No native capture, visual or performance qualification is performed; these remain explicitly not-run. No tests or PowerShell execution occurred during authoring. Windows owner execution pending. The JSON qualified flag refers only to these focused tests, not overall enrichment completion.

Next: review actual Windows evidence and extend the runtime sampling protocol with a local process sampler and explicit session/backend metadata; retain native capture and visual checks as separate gates.

## Phase 16.2 — read-only runtime sampling

Run after starting the desired capture and warming up for five minutes. Supply the actual application PID (Get-Process), backend and remote enrichment configuration. Example: ` .\\measure-enrichment-runtime.ps1 -TargetProcessId 1234 -Backend Npcap -RemoteEnrichment Disabled -DurationMinutes 30 `. Use 120 minutes for the extended run. `-SelfTest` exercises four CPU arithmetic fixtures. CSV samples include monotonic elapsed time, UTC, private bytes, working set, thread count, cumulative CPU and normalized CPU percent (first sample blank). JSON records declared configuration, checkout HEAD (not proof of binary provenance), process start identity and completion or failure. Process exit/reuse is not a successful run. No capture is started or stopped; record dashboard counters and shutdown separately. No performance thresholds or runtime passes claimed.
