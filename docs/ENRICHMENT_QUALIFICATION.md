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
