# Rule quality: R001–R005

Status: dedicated test sources committed; Windows verification is still required.
Do not begin R006–R010 until both focused testing and complete regression pass.

## One test file per rule

| Rule | File | Scenario boundaries |
| --- | --- | --- |
| R001 Port Scan | Carthago.Tests/R001Tests.cs | Distinct SYN ports; benign ACK and SYN/ACK; retries; source/target separation; expiry; incomplete telemetry; spoofed flag words |
| R002 Flood / DoS | Carthago.Tests/R002Tests.cs | SYN/byte floods; balanced handshakes; insufficient bytes; independent targets/senders; time-window expiry |
| R003 Threat Feed | Carthago.Tests/R003Tests.cs | Exact synthetic indicators; case normalization; lookalikes; source/destination differences; cooldown; independent sources |
| R004 Brute Force | Carthago.Tests/R004Tests.cs | Actual failure messages; benign SSH handshakes; FTP USER/PASS noise; target separation; expiry; unrelated service contexts |
| R005 Suspicious Protocol | Carthago.Tests/R005Tests.cs | TELNET/FTP/SMB/SNMP; benign modern protocols; incidental log words; sparse telemetry; duplicate flow; independent source |

Every rule has its own file and its own failure reporting. The five-rule batch is a **development and testing scope**, not a single test suite that hides which detector failed.

Key changes: R001/R002 parse actual SYN/ACK flag tokens; R002 counts per sender/target, not per sender across unrelated targets; R004 counts observed authentication failures instead of assuming every SSH/RDP packet is a login attempt; R005 requires attributable network endpoints. No confidence floors or deployment policy modes were lowered.

## Windows verification

From the repository root:

    git fetch origin feature/carthago-reliability-hardening
    git merge --ff-only FETCH_HEAD
    .\scripts\verify-rule-batch.ps1 -First 1 -Last 5
    .\scripts\run-accuracy-verification.ps1

The batch script builds once and then runs each dedicated test class separately, stopping at the first failure. It saves per-rule TXT and TRX logs under build-verify/rule-batches/. The full accuracy command includes the entire suite, development replay and separate pinned holdout.

## Gate before the next batch

1. Every per-rule file builds and passes all cases, with no skipped tests.
2. Both positive and benign controls behave as expected; no leaked synthetic secrets.
3. The full 544-rule regression and replay validations pass with no unexpected benign alerts.
4. The pinned holdout maintains its existing expectations and remains separate from the development corpus.
5. Any failing case is diagnosed and corrected without re-labeling a case to raise a score or relaxing production thresholds.

Synthetic test success does **not** establish field precision or production accuracy. Move to R006–R010 only after these checks succeed.
