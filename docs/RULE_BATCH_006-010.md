# Rule accuracy batch 02 — R006–R010

**Status: CANDIDATE — UNVERIFIED.** No build, xUnit, development replay, holdout or Windows runner was executed while authoring this batch. The local acceptance gate remains deferred until the owner explicitly declares test time. All thresholds, runtime modes, confidence floors, frozen holdout files and approval safeguards are unchanged.

## Detector and evidence review

| Rule | Evidence boundary and candidate correction | Advanced xUnit cases |
| --- | --- | ---: |
| R006 DNS Anomalies | Only attributed DNS **queries** with a plausible QNAME count; responses, empty/malformed QNAMEs and UDP/53 port-only noise cannot inflate volume. Trim future-dated state before threshold evaluation. Preserve configured 20 queries / 30 seconds at Balanced sensitivity; high severity still requires an unusual query label at the threshold. Do not disclose the query name in the alert description. | 7 |
| R007 C2 Beaconing | Partition observations by source, destination, **destination port and transport**. Exclude non-public/unknown endpoints, invalid ports, nonpositive payloads, duplicate-timestamp bursts, stale/future observations. Bound each flow to 128 observations / 30 minutes. Recognize mathematically perfect cadence without treating undefined zero-variance autocorrelation as a negative result. Preserve configured six samples and 60 seconds minimum observation. | 8 |
| R008 Exfiltration | Only attributed positive-length TCP/UDP egress to a public IP with a valid destination port contributes. Trim future and stale observations. Sum bytes using 64-bit arithmetic and saturate the legacy int event count. Preserve 5,000,000 bytes / 60 seconds at Balanced sensitivity. Describe a volume hypothesis, **not confirmed theft**. | 9 |
| R009 VPN/Proxy | Require explicit observed IsVpn/IsProxy flag, valid attributed source/target, service port and TCP/UDP transport. Untrusted Info text or a characteristic port alone cannot assert a VPN. Preserve Medium severity and existing suppression semantics. Authorization remains unknown. | 8 |
| R010 GeoIP | Use the **destination's GeoIP ISO2** and a public destination IP. Do not promote WHOIS registration country, source country or missing/contradictory country metadata to a destination policy finding. Preserve the configured blacklist and High severity; report normalized destination country. | 9 |

Total: **41 advanced xUnit facts**, all individually named, plus four development replay fixtures (one simulated R006 positive and three explicit benign negative controls for R006, R009 and R010). They are new unexecuted cases, **not 41 passes**. The replay samples are synthetic and cannot measure independent field precision.

## Coverage design

The tests exercise true detector predicates and threshold boundaries, close benign lookalikes, missing/contradictory enrichment, source/flow isolation, stale/future timestamps, overflow and cooldown. The R006 replay positive is deliberately constructed to resemble a DNS tunnel; it is **not evidence of a real exfiltration incident**. The R009/R010 controls explicitly distinguish classification and registration metadata from actual malicious behavior.

### Residual risks and tradeoffs

- R006 high entropy plus volume is not enough to prove DNS tunneling; CDN and security-research traffic can be noisy. Current severity uses the query that crosses the threshold, not the full history of suspicious names. DNS-over-TCP, DoH, incomplete QNAME capture and resolver aggregation need field validation.
- R007 perfectly periodic software update polling and legitimate health checks can resemble C2. The rule detects a **beaconing candidate**, not intent. Excluding hostnames/non-public IPs and requiring valid L4 ports reduces unsupported positives but may reduce recall. A production decision should use allowlisted processes, approved endpoints and baseline readiness, which this batch does not fabricate.
- R008 high outbound volume can be legitimate backup, synchronization or streaming. It is still labeled Critical by the legacy detector, so policy gating and analyst review are essential. Per-source aggregation across different destinations and limited directionality are unresolved attribution risks. No production exfiltration accuracy is claimed.
- R009 a VPN or proxy is frequently authorized. The flag may originate from an enrichment provider and its reliability must be validated independently. ESP/AH and portless tunnels are intentionally not inferred from weak evidence.
- R010 destination GeoIP can be stale, wrong or misleading under VPN/CDN/anycast. A blocked country is a **policy candidate**, not proof of hostile intent. Requiring destination ISO2 intentionally drops WHOIS-only legacy hits; real-world impact must be reviewed before acceptance.
- The public-address helper excludes common non-routable and documentation ranges; it is not a complete IANA special-purpose registry implementation. IPv6 edge cases and carrier NAT remain future tests.

## Deferred Windows verification

The existing consolidated verifier automatically discovers the five new RNNNAdvancedAccuracyBatchTests.cs classes, enforces contiguous R001–R010 coverage and at least five passing cases per rule, then runs one full xUnit suite, one development replay and one separate frozen holdout. It preserves stage logs and a timestamped TXT. The script was **not executed or modified in this batch**.

When the owner explicitly says it is test time, freeze the exact branch HEAD and invoke:

```powershell
.\scripts\verify-all-rule-batches.ps1
```

Never mark this batch accepted merely because the files exist or a future script starts. Review the actual TRX, replay profile outcomes, explicit negative assertions, and holdout before any promotion. Keep R102 >= 80%, R118 >= 86%, R163 >= 84%, and retain Shadow/Disabled, asset approval and baseline safeguards.
