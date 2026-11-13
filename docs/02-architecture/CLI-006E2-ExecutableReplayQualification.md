# CLI-006E.2 — Executable capture replay qualification

**SOURCE CANDIDATE — UNVERIFIED.** Parent `9ca3cf9a9c838d84639951374c7fe427837454d2`. Extends the owner-run CLI-006E.1 gate; no execution performed.

After the full portable test suite and capability smoke checks, generate two deterministic synthetic RAW IPv4/TCP capture files in the fresh ignored report directory. Classic PCAP and PCAPNG contain seven HTTP packets: five independent positive signatures (R586–R590), one R586 cooldown repeat, and one R588 benign near miss. Invoke the built CLI with all five IDs plus R1000 and assert exit zero, schema/provenance, seven parsed packets, five findings, one suppression, no truncation or clock reset, exact per-rule counts and finding packet ordinals, and explicit unsupported R1000. Require absence of the raw command marker in findings/output. Record fixture SHA-256 and observed counts in qualification.json; portable qualification requires both formats to pass. No live network or real capture used.

Owner run from clean pinned branch:
```powershell
$sha = (git rev-parse HEAD).Trim()
.\scripts\verify-cli-qualification.ps1 -SourceSha $sha -AuthorizedTestTime -IncludeWindowsParity
```

Portable-only omit IncludeWindowsParity. The script and fixture generator remain unexecuted; passing synthetic evidence does not establish real-field accuracy, live capture, deployment or runtime policy qualification. Next: collect actual owner-authorized results, repair observed failures, then portable headless monitoring.

## 2026-11-14 — Owner-run CLI-006E evidence receipt

Owner ran `scripts/verify-cli-qualification.ps1 -SourceSha $sha -AuthorizedTestTime -IncludeWindowsParity` on the retained `ff35973a0373fb61ccee1a64d836944458d54f88` checkout after GA-IQ-01 and AS-Q01 passed. The supplied console transcript prints the report directory `build-verify/cli-qualification/20261113-234446-ff35973a0373-92088621` and returns to the prompt with no visible error. The verifier writes qualification.json in a finally block for both success and failure, so the directory alone is not sufficient evidence of the final status. Source review confirms the success branch sets SyntheticPortableAndWindowsParityPassed only after portable build/tests, capability and unsupported-detector checks, both executable replay smoke cases and Windows build/parity checks succeed. The transcript does not expose the JSON status, counters, stage exit codes or qualification flags; full report review is pending. Read the existing qualification.json before rerunning or pulling. No new source or test changes, live capture, deployment or field-accuracy claim. The prior 653/653 CLI and 14,186/14,186 Windows regression and 392/392 active sensor results remain verified at the pinned baseline.
