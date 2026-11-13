# CLI-006E.2 — Executable capture replay qualification

**SOURCE CANDIDATE — UNVERIFIED.** Parent `9ca3cf9a9c838d84639951374c7fe427837454d2`. Extends the owner-run CLI-006E.1 gate; no execution performed.

After the full portable test suite and capability smoke checks, generate two deterministic synthetic RAW IPv4/TCP capture files in the fresh ignored report directory. Classic PCAP and PCAPNG contain seven HTTP packets: five independent positive signatures (R586–R590), one R586 cooldown repeat, and one R588 benign near miss. Invoke the built CLI with all five IDs plus R1000 and assert exit zero, schema/provenance, seven parsed packets, five findings, one suppression, no truncation or clock reset, exact per-rule counts and finding packet ordinals, and explicit unsupported R1000. Require absence of the raw command marker in findings/output. Record fixture SHA-256 and observed counts in qualification.json; portable qualification requires both formats to pass. No live network or real capture used.

Owner run from clean pinned branch:
```powershell
$sha = (git rev-parse HEAD).Trim()
.\scripts\verify-cli-qualification.ps1 -SourceSha $sha -AuthorizedTestTime -IncludeWindowsParity
```

Portable-only omit IncludeWindowsParity. The script and fixture generator remain unexecuted; passing synthetic evidence does not establish real-field accuracy, live capture, deployment or runtime policy qualification. Next: collect actual owner-authorized results, repair observed failures, then portable headless monitoring.
