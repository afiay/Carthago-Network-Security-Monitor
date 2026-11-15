# Exact-ID detection qualification audit — GA-09bk

Evidence snapshot: `b7e12d829df243cb40b6612af140bcd42f7d3712` (2026-11-15). This is a bounded audit, not the complete registry inventory. A row is not a promotion or a new verification result. The rule qualification stream owns Q4–Q9 implementation; this audit consumes its evidence without duplicating its tests.

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
