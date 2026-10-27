# Rule accuracy batch 03 — R011–R015

**Status: CANDIDATE — UNVERIFIED.** This is source/test/replay-fixture authoring only. No build, xUnit, replay, holdout or Windows verifier was executed. Preserve existing rule activation, runtime modes, confidence floors, thresholds and frozen holdout. Never infer operational accuracy from the new test count.

## Detector review and proposed precision boundaries

| Rule | Current risk and candidate correction | Advanced xUnit facts |
| --- | --- | ---: |
| R011 DHCP Abuse | Previous global DHCP list combined unrelated clients and counted server replies or a free-text DHCP label. Require positive-length UDP client 68→67, identify each client by valid unicast Ethernet source MAC or private renewal source IP, isolate client windows, exclude future/stale timestamps and clear bounded state even under cooldown. Keep configured 20 requests / 60 seconds at Balanced. This is a client-rate hypothesis, not detection of rogue DHCP servers. | 8 |
| R012 Suspicious TLS | Previous Info substring flags could manufacture certificate findings on TCP/443. Require attributed TCP/443 with structured expired/not-yet-valid certificate dates or a self-issued certificate supported by TLS version and issuer/subject fields. Contradictory or Info-only text does not override structured evidence. Do not echo subject/issuer. Keep Medium severity. | 8 |
| R013 Uncommon Ports | Previous UDP positive byte length alone could be treated as an observed service, SYN-ACK text could be mistaken for SYN, and arbitrary service names appeared in alert descriptions. Require valid endpoints, a TCP initial SYN (including numeric flag checks) or explicit UDP service, reject unclassified ephemeral traffic, preserve allowlist and configured anomaly floor, and omit untrusted service strings from alerts. | 9 |
| R014 Cleartext Credentials | Previous regex treated SMTP MAIL FROM, RCPT TO and AUTH LOGIN negotiation as passwords, including unscoped Info strings. Require an attributed positive-length unencrypted TCP/HTTP flow with a credential-bearing FTP PASS, SMTP AUTH PLAIN or HTTP Authorization: Basic command on known cleartext service ports. Exclude TLS/QUIC and never emit raw credentials. Keep legacy Critical severity pending policy review. | 9 |
| R015 ARP Spoofing | Previous single arbitrary Info mapping change triggered High, including malformed MACs, conflicting link-layer headers and normal address movement. Parse explicit ARP is-at claims, validate private IPv4 and unicast MAC, require Ethernet source MAC agreement, and require two temporally distinct conflicting claims within 30 seconds before promoting the candidate mapping. Evict stale mappings by observation time. Do not emit MACs. | 10 |

**Total: 44 newly authored xUnit facts** (8+8+9+9+10). These are not test passes. Five labeled benign development replay fixtures provide explicit negative controls; positives remain xUnit hypotheses rather than misleading 'malicious' replay labels. No field-labeled precision claims are made.

## Replay-fixture intent

- R012 text-only ExpiredCert: explicit negative; the expired structured-certificate positive remains an xUnit scenario, not a malicious replay label.
- R014 SMTP envelope-only traffic: explicit negative; synthetic FTP PASS positives remain xUnit scenarios because exposure alone does not prove malicious intent.
- R011 DHCP server replies: explicit negative (must not count as client request abuse).
- R013 SYN-ACK service mismatch: explicit negative (not a new initial SYN).
- R015 one changed ARP claim: explicit negative (requires a second temporally distinct claim).

Only benign negative replay controls are added in this batch. The replay corpus cannot establish whether any observed activity was authorized or malicious. Do not use these fixtures to promote Alert/Shadow modes or to tune the precision floors.

## Residual risks and assumptions

- **R011:** Rate-based DHCP detection can still flag legitimate boot storms and large rollouts; it does not detect a single rogue server. Broadcast clients with no valid MAC are intentionally ignored. A private source-IP fallback can conflate hosts behind a shared source.
- **R012:** A self-issued certificate is not necessarily self-signed or untrusted. The structured dates are sensor-provided and can be inaccurate. Requiring TCP/443 drops TLS on alternative ports; Info-only InvalidCert is intentionally excluded pending a trusted validator result.
- **R013:** IANA/service registry mappings and application classification can be stale or ambiguous. UDP classification remains weaker than a verified application handshake. The learner is unchanged; authorization and baseline-readiness controls must still be enforced upstream.
- **R014:** A plaintext command captured in Info or headers is not proof of a valid credential. STARTTLS negotiation may be missed if TLS metadata is absent. These detections should be reviewed under privacy policy before use in production.
- **R015:** Two ARP claims are not independent devices or proof of spoofing. Legitimate VRRP/failover, DHCP lease churn, and spoofed Ethernet source MACs remain confounders. Current state is in-memory and sensor-local; it does not validate switch-port identity.
- **Cross-cutting:** No rule policy, approval safeguards, confidence floor, replay holdout identity or threshold was changed. Test data is synthetic. New detector gates intentionally trade some recall for evidence quality and must be assessed with real benign and malicious traffic later.

## Deferred consolidated Windows acceptance

The existing one-run verifier at scripts/verify-all-rule-batches.ps1 auto-discovers R011AdvancedAccuracyBatchTests.cs through R015AdvancedAccuracyBatchTests.cs. It will require contiguous R001–R015 coverage and at least five passing advanced cases per rule, then run the complete xUnit suite once, the development replay once and the frozen synthetic holdout once, saving a complete timestamped TXT with stage logs.

**Do not execute any verification yet.** Only when the owner explicitly says "now it's test time", freeze the branch SHA, run the single verifier locally and review its TRX/replay/holdout evidence. Keep R102 ≥ 80%, R118 ≥ 86%, R163 ≥ 84%, Shadow/Disabled, IoT asset approvals and baseline readiness unchanged.
