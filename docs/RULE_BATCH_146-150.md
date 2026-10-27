# R146-R150 TLS summary attribution and endpoint precision

**CANDIDATE - UNVERIFIED (2026-10-27).** Authored six production
files (five detectors plus `NetworkBatch146152Evidence.cs`) and six
test files (five eight-case advanced classes plus fixture). **40 xUnit
facts authored; zero executed.** No build, benchmark, replay, holdout,
Windows runner or GitHub workflow was invoked.

| Rule | Candidate production behavior | Eight new test cases |
| --- | --- | --- |
| R146 | Require typed TLS/TCP, valid source/destination attribution and bounded TLS failure summary before accepting a configured 12-event spike. Instance-owned, source+destination+port-specific duplicate-resistant window. | 12 independent positives, duplicate ID, destination isolation, successful sessions, UDP contradiction, HTTP-only context, oversized summary, threshold/Shadow floor. |
| R147 | Require typed TLS/TCP plus a bounded explicit ECH/Encrypted ClientHello summary from the record, rather than arbitrarily matching process/host/certificate text. Remains a low-severity privacy-context signal, not an attack classification. | Explicit ECH, alternate encoding, ordinary TLS, process-name decoy, QUIC contradiction, TCP-only Info, HTTP contradiction, Shadow/floor. |
| R148 | Require observed TLS SNI, strict transport, external IP socket and provider subdomain, rather than inferring from HTTP Host or DNS qname; preserve browser suppression. | Dynamic-DNS SNI, provider apex, provider substring in unrelated domain, browser, internal socket, HTTP-only host, conflicting SNI, Shadow/floor. |
| R149 | Require parser-observed IP-literal SNI on typed TLS/TCP; do not treat destination IP, HTTP Host or packet Info as SNI. Hash cooldown keys. | Literal positive, hostname, absent SNI, HTTP-only, UDP, conflicting SNI, Info-only, Shadow/floor. |
| R150 | Require typed TLS/TCP, observed JA3/JA4 and bounded explicit malware-like label summary. Do not infer labels from arbitrary host/process strings. Retain existing Core/Alert policy and 88% floor; label from packet Info is UNVERIFIED threat-intel context and cannot justify an unreviewed enforcement action. | Fingerprint+label, label only, fingerprint only, host decoy, UDP, oversized packet summary, TCP-only label, Alert/floor. |

## Engineering guardrails and open risks

- The source commit `03561a9e83dac813fe2212e4c8cf01df6d904861`
  tightens typed transport and socket attribution with the existing
  `NetworkBatch141145Evidence.TlsSession`, plus bounded untrusted
  packet summary recognition and a duplicate-resistant observation window.
- Test commit `9fb2caee6190682234d635ee577b31f17b389d48`
  adds **40 authored but unexecuted** advanced facts, discoverable by the
  deferred verifier `scripts/verify-all-rule-batches.ps1`.
- R146's packet Info string is not a parsed failure status; R147's Info
  is not a cryptographically proven ECH-extension indicator. R150's
  annotation is not independently sourced or signed threat intelligence.
  Positive synthetic fixtures only check matching behavior.
- R150 existing Alert/default and all tenets of global precision gates
  are unchanged. R146-R149 keep original Shadow behavior. No thresholds,
  confidence minima, baseline approvals, frozen holdout samples or labels
  have been weakened or modified.
- Source/transport parser completeness, out-of-order events, state
  concurrency, false-negative costs and output serialization privacy all
  require a later user-approved consolidated run and operational review.
- Frozen V1 synthetic holdout remains FAILED 4/6 for R102.
  Independent PCAP-based V2 remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW.

**Next five-rule batch: R151-R155.**

## Static fixture correction after code review

`TrafficRecord.Sni` / `TlsSni` share a backing field, so the original
two-source conflict test was not a representable traffic record.
R148 and R149 now assert that parser-attributed TLS with contradictory
HTTP request metadata is rejected. No detector behavior, threshold or
policy changed. **CANDIDATE - UNVERIFIED**.
