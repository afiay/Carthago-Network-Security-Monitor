# R343 - authenticated Windows/WinRM audit producer trust boundary

**Status: DESIGN CONTRACT ONLY.** No service, signing key, transport, signed audit producer, or R343 alert promotion is implemented here. R343 continues to return `WINRM_COMMAND_AUDIT_UNAVAILABLE`. This contract guides the next isolated development increments.

## Verified foundation and deliberate limitations

- CARTHAGE Stage 1 lab validated Security event 4688 generation and a bounded event-to-process match using the harmless test process's PID and executable path. Process Creation auditing was restored to the original `No Auditing` baseline after the test.
- 4688 means a process was created, **not** that a PowerShell command completed, that it originated from an unauthorized WinRM session, or that its arguments were malicious.
- Local 4624/4688 XML candidates and `WinRmAuditCandidate.FromLocalSecurityLog` are explicitly **unsigned** and must not be converted directly into `AuditClaim`, `SignedAuditEnvelope`, or `VerifiedAuditReceipt`.
- Stage 2 command-line inclusion is not authorized or enabled. No application-wide administrative privileges are authorized.

## Source hierarchy and provenance checks

1. **OS intake:** an isolated, narrow local Security-log reader, not the WPF UI, acquires native EventRecord data from the local `Security` channel. Validate event ID, provider, machine, record ID, timestamp, record ordering and freshness. Treat event XML fields as untrusted even when delivered by Windows.
2. **Process identity:** correlate a real 4688 to an actual 4624 logon session with nonzero logon ID, consistent process ID and parent process ID, OS event metadata and bounded chronology. Executable basename alone is insufficient: canonical parent `wsmprovhost.exe` and PowerShell image locations provide candidate filtering only.
3. **WinRM authority:** require independently authenticated session attribution and a verifiable operation outcome from an authorized WinRM/service audit producer. A packet to port 5985/5986, process ancestry, timing, or script text cannot substitute for an authenticated WinRM outcome.
4. **Authorization context:** the outcome producer must record a source-backed allow/deny decision that distinguishes approved admin/automation from unauthorized operation; an emitted 4688 or valid `-EncodedCommand` flag is not itself malicious intent.
5. **Signer:** only a separately managed, least-privileged producer holding an operator-provisioned non-exportable signing key can produce an `AuditClaim` payload and RSA-PSS-SHA256 envelope. Signer identity, rule scope and key rotation must be pinned by the verifier's operator-controlled `TrustedAuditIssuer` configuration; never derive trust anchors from event data, repository fixtures, or a network packet.
6. **Consumer:** `TrustedAuditReceiptVerifier` validates signature, domain separation, issuer scope, claim fields, freshness and replay. `TrustedAuditReceiptCorrelation` requires independent issuer keys under the same registry and matching subject/trace. **Even a correlated pair does not by itself authorize alert promotion.**

## Privilege separation

- Never run the whole Carthago WPF UI elevated to read the Security log. Prefer an independently deployable Windows service or tightly ACL-restricted helper with the minimum actual log-reading right; review and document its SID and audit access on the target host.
- Protect IPC with Windows access controls and per-connection peer identity, bounded frames, authenticated requests, strict parsing, replay-resistant correlation IDs and explicit authorization. No unauthenticated socket or caller-supplied trust flag is allowed.
- Keep private keys out of repository/configuration/diagnostic logs; never serialize, copy, or expose raw command lines, encoded payloads, session tokens, credentials or personal identifiers through UI IPC. Audit any exceptional access without exposing secrets.
- Access to the Security log and modification of Audit Process Creation or command-line inclusion policy are different privileges and separate operator decisions. Re-enabling lab auditing must never occur automatically from the app.

## Non-negotiable fail-closed states

| Missing or invalid prerequisite | Required behavior |
| --- | --- |
| Windows Security log inaccessible, audit policy disabled, or records stale | No authenticated producer output; diagnostic state only |
| Parent process basename matches but path is writable or unexpected | Reject R343 unsigned candidate |
| PowerShell 4688 image and the command-line launcher disagree | Reject R343 unsigned candidate |
| Network 4624 and process 4688 lack exact session/chronology binding | Reject candidate |
| No authorized WinRM session outcome or source identity | No signed claim, no alert |
| Audit issuer key unknown, wrong rule scope, stale/replayed evidence | Signature verifier rejects |
| Two receipts share issuer/signing key, registry differs or subjects mismatch | Correlation rejects |
| Only signed claims exist, without independent malicious-intent/authorization evidence | No alert promotion |

## Narrow incremental roadmap

1. **Current increment:** harden the existing unsigned candidate parser to reject user-writable executable lookalikes and to bind encoded-command flags to the observed PowerShell launcher. Add adversarial synthetic tests. No source policy changes.
2. **Next:** define a read-only service-to-consumer IPC contract with explicit identity and capability checks, then add purely offline negative tests. Do not create a signing key or service installer as part of the contract review.
3. **Then:** implement an operator-provisioned source with real authenticated WinRM operation/outcome correlation and explicit authorization provenance, initially producing diagnostic-only data.
4. **Last:** after successful real-source tests, security review, and independently corroborated outcomes, consider signing receipts and separately reviewing R343 alert-promotion policy. Never modify existing confidence floors or relabel malicious fixtures to pass certification.

## Source references

- Windows PowerShell and pwsh.exe default locations: https://learn.microsoft.com/en-us/powershell/scripting/whats-new/migrating-from-windows-powershell-51-to-powershell-7
- PowerShell 7 installer folder and preview paths: https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows
- Microsoft Security event 4688: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688

## Verification required on CARTHAGE

These changes are source-committed but **not compiled or executed** in this environment. Run the focused `WinRmSecurityAuditIntakeTests` first, then the regular full verification only when the operator requests it. The previously verified full xUnit baseline is **4,851/4,851 at `290a327`**; four replay expectation blockers (R343, R295, R275, R163) remain unresolved.
