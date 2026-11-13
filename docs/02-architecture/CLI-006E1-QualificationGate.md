# CLI-006E.1 — Pinned CLI synthetic qualification gate

**SOURCE CANDIDATE — UNVERIFIED.** Parent `e9b3ff95651de71f76d8c67329c206c7a28922c6`. This is a prepared owner-run gate, not an observed pass. No builds, tests, capture, replay or Actions executed by this publication.

On the existing feature branch, use a clean checkout and the exact selected SHA. Explicit owner test-time authorization is required. The portable gate builds the CLI test project (including Core and Contracts), executes the entire CLI test suite, checks fresh TRX counters and minimum passed cases per required class, and invokes the actual built CLI for supported and unsupported capability JSON. The replay classes cover synthetic PCAP and PCAPNG; no real capture is required. On Windows, the optional parity stage builds the Windows test project and checks all three parity classes (minimum 23 passed cases).

```powershell
git switch feature/carthago-reliability-hardening
git pull --ff-only origin feature/carthago-reliability-hardening
$sha = (git rev-parse HEAD).Trim()
.\\scripts\\verify-cli-qualification.ps1 -SourceSha $sha -AuthorizedTestTime -IncludeWindowsParity
```

For a Linux portable-only run use PowerShell 7: `pwsh -NoProfile -File scripts/verify-cli-qualification.ps1 -SourceSha <exact-sha> -AuthorizedTestTime`. Windows parity is intentionally unavailable there. A portable-only pass cannot certify Windows parity or Linux live monitoring.

Fresh ignored output: `build-verify/cli-qualification/<run-id>/qualification.json`, logs and TRX. Report records SHA, SDK, OS, stage exits, actual counters and required-class passed counts. Build/test commands run locally only; checkout is checked before and after each stage. A failed stage is not a successful qualification; partial portable success is reported separately from Windows parity. The gate uses compiled synthetic test evidence, not real-field precision/recall, live capture, service deployment, or release approval. Existing GA-IQ-01 full integration gate remains unchanged. Next: execute on owner-authorized machines, review results and repair actual failures before CLI-007.
