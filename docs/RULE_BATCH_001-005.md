# Carthago accuracy batch 01 — R001–R005

**State:** Candidate implementation; **Windows build, expanded advanced test suite, full 544-rule regression and isolated synthetic holdout pending**. No rule has been promoted to Alert, no precision floor lowered, and R006–R010 must not begin until this batch is verified and reviewed.

The five rules already had baseline unit tests. This batch **adds at least five deliberately adversarial tests for each**, retaining the original tests. Stateful tests use the isolated `Legacy rules R001-R005 isolated` collection and reset detector state before/after each case.

| Rule | Detection behavior | Advanced acceptance scenarios (five minimum) | Corrective code |
| --- | --- | --- | --- |
| **R001 Port Scan** | Unique TCP SYN ports to one destination from one source over a bounded window | (1) five real distinct SYNs; (2) a future-dated SYN cannot preload current windows; (3) retransmissions plus ACK/SYN-ACK cannot count as additional ports; (4) invalid destination ports cannot prime state; (5) interleaved source/destination pairs remain isolated | Reject invalid ports inside the detector as a second defense and discard future-dated state during eviction |
| **R002 Flood/DoS** | Strong TCP SYN/ACK imbalance, substantial bytes and packet volume to an attributed destination service | (1) two parallel destination ports cannot pool counters; (2) different clients cannot pool counters; (3) balanced SYN/ACK is benign despite throughput; (4) many tiny packets do not satisfy the byte gate; (5) UDP and invalid-port noise cannot contribute to a TCP flood; (6) future timestamps cannot preload the present; (7) expired bytes cannot accumulate into a current-window flood | Partition by **source + destination + destination port** and use the same bounded, 100 ms-bucket observation window for packet, byte, SYN, and ACK evidence |
| **R003 Threat Feed Hit** | Exact match to an observed destination indicator in the locally registered threat host set | (1) absolute FQDN with DNS root dot; (2) uppercase and whitespace normalization without partial matching; (3) reputation flags and scary text alone cannot impersonate a feed; (4) lookalike subdomains/prefixes/suffixes cannot inherit identity; (5) repeated hits are debounced without suppressing independent clients | Normalize the observed domain representation before exact feed membership |
| **R004 Brute Force** | Repeated, attributed failed authentication outcomes to one source/destination/service | (1) five recognized failure phrases; (2) successes interspersed with failures do not inflate counts; (3) SSH and RDP failures do not pool; (4) out-of-order future timestamps do not prime current counts; (5) UDP and unrelated HTTP-like failure text cannot become failed logins | Existing source+destination+port and auth-outcome gates retained; additional scenario coverage |
| **R005 Suspicious Protocol** | Attributed observation of Telnet, FTP, SMB or SNMP service, with compatible transport | (1) normalized whitespace and service-case variants; (2) wiki/log vocabulary and incorrect transport rejected; (3) SNMP observed over TCP or UDP; (4) invalid or unattributed endpoints rejected; (5) duplicate flow suppression does not hide independent services | Normalize the observed service name identically in the validator and detector |

## What these tests do **not** establish

- The R001 burst is a **scan hypothesis**, not proof of malicious intent; approved inventory scanning can look the same.
- R002 packet/byte samples are synthetic traffic summaries. Distributed flooding, TCP state tracking, retransmissions, packet loss and real bandwidth remain separate field-evaluation tasks.
- R003 uses synthetic `.invalid` indicators in tests; threat-feed freshness, source reliability, false-positive retractions and feed-to-asset context need external data.
- R004's legacy `Info` parsing is not the same as a trusted structured SSH/RDP identity-provider failure event; stronger authentication-attribution telemetry is needed for production accuracy.
- R005 identifies an **insecure or unexpected service**. A normal authorized SNMP/Telnet flow is not automatically an attack. Do not reclassify every positive as a confirmed malicious incident.

## Mandatory Windows acceptance

```powershell
git fetch origin feature/carthago-reliability-hardening
git merge --ff-only FETCH_HEAD

# Five or more advanced tests per rule PLUS all existing R001-R005 suites,
# followed by full 544-rule build/verification and separate holdout.
.\scripts\verify-first-rule-batch.ps1
```

The targeted test TRX is saved as `build-verify/rule-batches/R001-R005.trx`. The gate fails if **any test fails or fewer than 25 advanced cases are discovered**; additional cases are encouraged. The full stage subsequently checks for zero benign alert regressions and explicit replay expectation mismatches. The separate holdout remains independent of these five legacy rules and is **not evidence of their accuracy**; it guards against collateral R102/R118/R163 regressions.

R002's fixed-size buckets aggregate dense traffic without one state entry per packet. Buckets whose start precedes the sliding cutoff are conservatively omitted: this avoids stale-evidence false positives at the cost of potentially missing observations at the first 100 ms of a window. A cap of 4,096 buckets per source/target/service bounds exceptionally long configured windows; evidence dropped under this cap cannot strengthen a detection. Full Windows verification and performance measurements remain mandatory before accepting this change.

The normal `build-verify/local-logs/` stage logs and `build-verify/tuning-benchmark.md` remain available for diagnosis. Run the accuracy inspector after checking out the latest branch—the fix for omitted nullable confidence bounds is included here.

## Promotion / continuation rules

Only after a clean Windows run, review each rule's returned evidence and remaining limitations. Further calibration requires **independently labeled field data**, particularly legitimate inventory scans, authorized service tests, known-good administration, threat-feed retractions and explicit authentication outcomes. Do not auto-promote rules or loosen Shadow/Disabled policies to manufacture high recall. The next batch will be **R006–R010**, and only after this batch is accepted.
