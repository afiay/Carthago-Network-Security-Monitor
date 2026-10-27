# Rule accuracy batch 06 — R026–R030

**Status: CANDIDATE — UNVERIFIED.** Source, 41 advanced xUnit facts and five benign development replay controls authored. No build, xUnit, replay, holdout or Windows runner was executed.

| Rule | Candidate detection boundary | Advanced xUnit facts |
| --- | --- | ---: |
| R026 — SMB / RPC to Internet | Require private source, publicly routable destination, TCP/139 or TCP/445, positive packet size, and initial SYN or corroborating structured SMB/NetBIOS/RPC service. Reject UDP, contradictory classification, reverse packets and invalid endpoints. | 8 |
| R027 — Administrative service egress | Distinguish FTP, Telnet, SSH, RDP and WinRM from mail authentication. Require attributable TCP initial connection or matching structured service, and reject contradictory metadata. | 8 |
| R028 — Direct external DNS | Require observed query name, not response or port-only record; private source, public destination, UDP/DNS or explicitly classified TCP DNS. Never expose DNS name in alert text. | 8 |
| R029 — QUIC anomaly | Require corroborated UDP/QUIC observation, non-443/non-DNS/NTP port, missing ALPN, attributable private-to-public flow; deduplicate timestamps and bound per-flow debounce instead of blocking unrelated destinations. | 8 |
| R030 — Internal admin lateral sweep | Require distinct private targets with genuine initiating TCP SYN to an admin port; isolate source/port, discard stale/future state and duplicate targets, and clear suppressed completed windows. Preserve eight hosts in 60 seconds. | 9 |

**Total: 41 authored advanced xUnit facts.** No pass counts or field accuracy are claimed.

## Benign development replay controls

- `r026-udp445-not-smb-egress.json` — UDP/445 with SMB diagnostic prose is not TCP SMB egress.
- `r027-mail-auth-not-admin-egress.json` — IMAPS/993 is not administrative service egress.
- `r028-dns-response-not-outbound-query.json` — DNS response is not a direct outbound query.
- `r029-udp-quic-metadata-not-observation.json` — uncorroborated QUIC version metadata is not observed QUIC.
- `r030-synack-not-lateral-sweep.json` — eight SYN-ACK packets are not initiating lateral probes.

These are explicitly benign negative controls, not independently labeled field traffic or evidence of malicious intent.

## Residual risks and acceptance boundaries

- R026 port 139/445 egress can be approved partner access. RPC endpoint mapper port 135 is deliberately not included without stronger protocol evidence.
- R027 authorized SSH/RDP/WinRM/FTP/Telnet sessions can look identical. No approved remote-admin destination inventory is available to the detector.
- R028 direct public DNS does not prove resolver-policy bypass without an approved-resolver inventory. Missing query metadata can lower recall on truncated captures.
- R029 nonstandard QUIC and missing ALPN are weak heuristics, not maliciousness proof. Per-flow debounce trades some sensitivity for duplicate suppression.
- R030 authorized inventory, vulnerability scans and fleet-management may look like lateral movement; asymmetric capture and dropped SYNs reduce recall.
- Structured application classifications and source attribution may be inaccurate; alerts do not contain raw DNS names, credentials or QUIC payloads.
- The broad `AuthPorts` used by brute-force detection remains untouched. R102 >=80%, R118 >=86%, R163 >=84%, Shadow/Disabled policy, baseline readiness, asset approvals and frozen holdout fixtures are unchanged.
- No confidence, precision, recall, F1, promotion or acceptance claim is made before deferred verification.

## Deferred single-run acceptance

`scripts/verify-all-rule-batches.ps1` automatically discovers R026–R030 advanced classes and checks each for at least five passing cases, alongside one full xUnit suite, one development replay and one frozen holdout. Execution remains prohibited until the owner explicitly says **now it's test time**.
