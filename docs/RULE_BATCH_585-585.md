# R585 — External three-service administrative request probe

**Status:** SOURCE CANDIDATE — UNVERIFIED; **12 authored xUnit methods (14 invocations), 0 executed**. No build, tests, replay, CI or holdout performed.

## Threat and evidence
One globally routable public IPv4 client sends **all three distinct classified request types** to the **same RFC1918 host** within 300 seconds:
1. HTTP/1.x GET/POST to an anchored admin path with a parser-confirmed known-default Basic credential, stored only as a redacted header.
2. RESP2 Redis CONFIG SET request (not a reply or configuration change).
3. Bounded SMB2 WRITE request shape (not a successful file write).

These are independent parser-backed TrafficRecord classifications already consumed by other production rules. No new sensor, packet parser, model or runtime is added. Requests may occur in any order; exact source/host equality, three distinct service bits, monotonic timestamps and unique packet IDs are mandatory.

## Security value, existing coverage and limitations
Unlike R566–R579 two-service ordered pair correlations, and R580–R584 single-service subnet fanout, R585 requires three *different* administrative service request classes against one exact internal host. This is a stronger cross-service probing predicate, broadly consistent with MITRE ATT&CK T1046 service discovery, but it is **not proof of scanning tools, brute force, compromise, Redis modification or exfiltration**. Authorized vulnerability scans, inventory and maintenance are realistic lookalikes. NAT, proxying, encrypted payloads and partial capture limit identity and recall.

**Policy:** High, Candidate/Shadow, confidence floor 90%, threshold three distinct classes in 300 s, cooldown 600 s, 512 peer-pair cap, 128 packet IDs per pair, fail closed at capacity, approved admin host exclusion. Evidence uses fixed labels only; no Authorization values, paths, Redis arguments, SMB filenames or raw payloads.

**Research:** MITRE ATT&CK T1046 and DET0376 (https://attack.mitre.org/techniques/T1046/ and https://attack.mitre.org/detectionstrategies/DET0376/). Protocol inventory P0001–P0500 is research background only; no P entry is claimed as newly integrated by this rule.

**Verification:** 12 authored xUnit methods, with a three-case Theory (14 total invocations), cover positive order variants, missing service, wrong peers, duplicates, out-of-order, expiry, port-only/Info-only, contradictions, cooldown, redaction and Candidate/Shadow registry invariants. These tests use synthetic typed TrafficRecord fixtures, not an executed wire replay. All claims remain unverified.
