# Exact-ID detection qualification audit — GA-09bk

**Current denominator (2026-11-16): 1,000 registered core rules.** The [registry reconciliation](REGISTRY_RECONCILIATION_20261116.md) and [per-ID CSV](registry-reconciliation.csv) now cover every source ID. This historical audit remains bounded; the machine-readable Windows exact-ID inventory has 27 records (17 historical test-run attestations, 4 authored-unexecuted, 6 missing). Schema v2 separates positive and negative detector outcomes per exact ID. The 17 positive synthetic cases matched; the negative side contains six Q7 SMB2 benign-lookalike false positives and eleven other historical controls that rejected. The 17 historical records are reviewed ledger attestations without original TRX artifacts; zero artifact-backed executions and zero independent validation are admitted. The 20 portable paired rules are accounted separately. Do not read a historical test-suite pass as both detector polarities passing, or infer field accuracy from synthetic evidence.

Evidence snapshot: `b7e12d829df243cb40b6612af140bcd42f7d3712` (2026-11-15). This is a bounded audit, not the complete registry inventory. A row is not a promotion or a new verification result. The rule qualification stream owns Q4–Q9 implementation; this audit consumes its evidence without duplicating its tests.

## GA-09bm — polarity-separated exact-ID evidence

The schema-v2 inventory stores `positiveEvidence` and `negativeEvidence` independently. Each polarity is explicitly `executed-pass`, `executed-fail`, `authored-unexecuted`, or `missing`, with an outcome, execution source SHA, test reference and provenance. An executed SHA in the current inventory is a reviewed historical test-run source SHA, not a retained TRX digest or proof of independent accuracy. The six Q7 SMB2 negative lookalikes are detector-level false positives even though the test suite itself passed; Shadow alert suppression is reported separately. R275/R295/R343/R437/R508/R516 remain producer-limited missing evidence, not detector failures.

## First six IDs: SMB2 Q7/Q9

| ID | Rule-level and paired synthetic evidence | Capture producer / limitation | Policy evidence | Independent holdout / next gate |
|---|---|---|---|---|
| R903 | Q7 four scenarios, raw malicious and benign lookalike match; benign port control rejects | Raw WRITE; PowerShell identity synthetic | Research precision gate Shadow | Q9 process-attribution-unavailable; authenticated process instance and WinRM sequence |
| R908 | Q7 four scenarios, raw malicious and benign lookalike match; source-port control rejects | Raw WRITE and SYN; no authorization proof | Research Shadow | Q9 packet-only eligible; independent public-to-private lab cases pending |
| R910 | Q7 four scenarios, raw malicious and benign lookalike match; LDAP host control rejects | Raw WRITE; PowerShell identity synthetic | Research Shadow; Q8 exact maintenance annotation | Q9 process-attribution-unavailable; independent LDAP/SMB and process evidence |
| R919 | Q7 four scenarios, raw malicious and benign lookalike match; RPC port control rejects | Raw WRITE; PsExec identity synthetic | Research Shadow | Q9 process-attribution-unavailable; authenticated process and RPC evidence |
| R942 | Q7 four scenarios, raw malicious and benign lookalike match; Modbus source control rejects | Raw WRITE and follow-up SYN; no industrial operation proof | Research Shadow | Q9 packet-only eligible; independent three-host lab cases pending |
| R950 | Q7 four scenarios, raw malicious and benign lookalike match; non-script control rejects | Raw WRITE; HTTP and PowerShell typed synthetic observations | Research Shadow; Q8 exact maintenance annotation | Q9 process-attribution-unavailable; authenticated process and captured HTTP evidence |

Historical Q7 execution: 25/25 at e64e2df; raw TP6 FP6 FN0 TN6, alert TP0 FP0 FN6 TN12, six truncated-WRITE producer-limited cases excluded. These six scenario gaps are **not** the separate six registered producer-gap IDs R275/R295/R343/R437/R508/R516. Q8 22/22 at 6a677b7. Q9 authored, no independent lab corpus or current execution established. Q7 is frozen; do not tune and call it independent. No current full-suite verification inferred.

Evidence: [Q7 test](../../Carthago.Tests/Smb2PairedAccuracyQualificationTests.cs), [Q7 protocol](../rules/SMB2_Q7_SYNTHETIC_ACCURACY_PROTOCOL.md), [Q9 protocol](../rules/SMB2_Q9_LAB_CAPTURE_PROTOCOL.md), [qualification gate](../rules/DETECTION_QUALIFICATION_GATE_20261112.md).

## Remaining audit

Only six exact IDs accounted for in this document; do not subtract from historical 965 as if current registry membership were verified. Next: enumerate live registry and join exact IDs to existing qualification inventory, then audit TFTP/DNS Q1–Q3 and priority R102/R118/R163. Keep authored tests, executed tests at exact SHA, synthetic raw producer evidence, policy and independent validation separate. No promotion, holdout edits or threshold changes. GA-08 Windows pending; R102 independent authority/V2, R118 independent identity/outcome, R163 authenticated causal producer remain open.

Windows targeted historical regression rerun: `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~Smb2PairedAccuracyQualificationTests|FullyQualifiedName~Smb2MaintenanceScopeTests|FullyQualifiedName~Smb2LabCaptureRunnerTests"`.

## GA-09bl — Q1–Q3 ten TFTP/DNS IDs

Source snapshot: `283487c189db8c2fffa048c973bcac90bc7b8e8e`. Reviewed current TftpCaptureQualificationTests and DnsCaptureQualificationTests, and Q1–Q3 gate. Historical owner 338/338 targeted and 12,192/12,192 full at 4cc680b; no execution at this snapshot. These are paired synthetic rule/producer controls, not independently labeled accuracy pairs. Candidate/Shadow per gate; no new policy execution.

| ID | Rule-level / paired controls | Producer evidence and limitation | Policy / independent next gate |
|---|---|---|---|
| R946 | RRQ/DATA1 and WRQ/ACK0; arbitrary UDP, unrelated request reject | Raw IPv4 TFTP exact request GUID; initial exchange only | Shadow; benign authorized private transfers and independent capture |
| R947 | SSH then public RRQ; malformed UDP rejects | Raw TFTP; SSH SYN synthetic, no authentication | Shadow; captured SSH and authorized public transfer controls |
| R949 | FTP STOR then WRQ; malformed UDP rejects | Raw TFTP; FTP STOR synthetic, no file identity | Shadow; captured FTP and benign file-placement controls |
| R708 | Public-to-private RRQ/WRQ; opposite direction rejects | Raw initial exchange; no transfer completion | Shadow; authorized inbound transfer controls |
| R715 | Private-to-public RRQ/WRQ; opposite direction rejects | Raw initial exchange; no transfer completion | Shadow; authorized outbound transfer controls |
| R792 | FTP then WRQ; RRQ/malformed reject | Raw TFTP; FTP and hostd PID synthetic | Shadow; authenticated process and benign ESXi workflow |
| R819 | HTTP config GET then WRQ; RRQ/malformed reject | Raw TFTP; HTTP GET synthetic, no export outcome | Shadow; captured HTTP and authorized config export |
| R881 | Public FTP SYN then private WRQ; RRQ/malformed reject | Raw TFTP; FTP SYN synthetic, no causal link | Shadow; captured FTP and benign maintenance |
| R916 | Matching NXDOMAIN; wrong transaction and unvalidated fields reject | Raw IPv4 DNS; hostd PID/name synthetic | Shadow; authenticated process and benign NXDOMAIN controls |
| R962 | Three distinct low-TTL A answers; wrong transaction/PID/port reject | Raw IPv4 DNS; query PID synthetic; normal CDN churn can match | Shadow; independent CDN/fast-flux controls and process provenance |

Evidence: [TFTP tests](../../Carthago.Tests/TftpCaptureQualificationTests.cs), [DNS tests](../../Carthago.Tests/DnsCaptureQualificationTests.cs), [Q1–Q3 gate](../rules/DETECTION_QUALIFICATION_GATE_20261112.md). No OACK, full transfer, DNSSEC, TCP/IPv6 DNS or independent field qualification inferred. Total documented distinct IDs now 16; live registry denominator still pending. Next: enumerate registry and audit priority IDs; do not duplicate Q1–Q3 implementation.
