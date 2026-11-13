# GA-IQ-01 — pinned solution integration and rule qualification

**SOURCE CANDIDATE — UNVERIFIED.** Base `97014f387ce96118191645efeb8bff92053cbe61`. Existing feature branch only. No builds, application tests, replays, CI or live probes executed by this publication.

## Integration gap and correction

The prior DOTNET.sln explicitly listed only Carthago, Carthago.Tests and Carthago.Benchmarks. Core and Contracts may build transitively; that did not guarantee CLI, CLI tests or Monitor coverage. The solution now explicitly lists all eight projects with Debug/Release Any CPU build configurations. No project reference, target framework, detector, profile or sensor policy changed.

The new owner-run script `scripts/verify-integration.ps1` requires an exact commit SHA, correct branch, clean tracked/untracked checkout and explicit test-time switch. It creates a unique ignored run directory, builds the full solution, runs CLI tests with fresh TRX and nonzero all-passing counters, then invokes the existing Windows verifier in a child shell. It rechecks the checkout between stages and records stage exits and CLI counters. Success means synthetic integration only; it does not certify live capture, deployment or detection accuracy.

## Qualification inventory

The source inventory remains authoritative for candidate associations, not runnable tests. The current registry contains 1,000 contiguous core IDs at the inspected base. Use the existing pinned source inventory rather than inferring test coverage from filenames or batch sizes. Keep the historical 965-rule/12,371-test baseline at c164be6 distinct from the new inventory; 19 paired benchmark controls at that baseline do not represent all xUnit coverage.

Owner commands from a clean Windows checkout:

```powershell
git switch feature/carthago-reliability-hardening
git pull --ff-only origin feature/carthago-reliability-hardening
$sha = (git rev-parse HEAD).Trim()
New-Item -ItemType Directory -Force build-verify | Out-Null
.\scripts\inspect-rule-source-inventory.ps1 -SourceSha $sha |
    Set-Content -Encoding UTF8 "build-verify/rule-source-$sha.json"
.\scripts\verify-integration.ps1 -SourceSha $sha -AuthorizedTestTime
```

The source inventory is read-only against Git blobs; its script/module are from the checked-out revision. Review unresolved declarations, grouped tests and producer dependencies; do not mark missing associations as zero tests. Rebuild the generated catalog separately with `python scripts/build_rule_catalog.py` and the docs index if needed; commit intended generated changes before a clean integration run.

## Qualification acceptance

For each rule record exact SHA, source/descriptor, positive and negative cases (including benign lookalikes), producer path, observed test results, replay evidence and operational disposition. Missing producer or independent labels remain blocked. Preserve R102 frozen V1 and pending V2, Shadow/Disabled semantics, confidence floors, and all historical test results. No new IDs in IQ-01.

Next: review the pinned inventory and resolve source ambiguities; execute the integration gate on Windows, record actual results, then prioritize R966–R1000 and producer-dependent rules. Active sensors have a separate synthetic verifier (`verify-active-sensors.ps1`); live network checks and UI visual acceptance remain separate authorized gates.
