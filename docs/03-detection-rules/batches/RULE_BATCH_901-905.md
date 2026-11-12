# CARTHAGO — R901–R905 observable research candidates

**SOURCE CANDIDATE — UNVERIFIED.** Five independent Candidate/Shadow rules; xUnit source authored first. Zero builds, tests, CI jobs or runtime replays executed. No promotion, convergence, shared capture-producer edits or changes to earlier rules.

| New ID | Workbook origin | Predicate and evidence boundary |
| --- | --- | --- |
| R901 | R1991 | Same private source, nltest PID and private peer receive TCP/389 then TCP/3268 SYNs within 45s; LDAP queries, domain trust enumeration and authentication are not observed. |
| R902 | R2054 | Public TCP/22 SYN to a private host followed by locally attributed screensharingd TCP/5900 SYN-ACK back to the same public peer within 45s; no SSH or VNC authentication or linked user session is established. |
| R903 | R1321 | Same private source and PowerShell PID send a parsed SMB2 WRITE request to TCP/445 then a TCP/5985 SYN to that private peer within 45s; file creation, transfer completion, authenticated WinRM and execution are unknown. |
| R904 | R2375 | Local curl attribution and a public cleartext HTTP PUT with exact application/octet-stream content-type, typed request and at least 512 transport payload bytes; file contents, upload completion and exfiltration are unknown. |
| R905 | R1764 | Same private source and mmc PID initiate TCP/445 to a private peer then TLS-marked TCP/443 data to a public peer within 45s; MMC document loading, COM activation, DLL loading and causality are not observed. |

## Duplicate and telemetry screening

R901 requires nltest and LDAP/389 followed by Global Catalog/3268, unlike R808 LDAP modify/Kerberos and R823 dscl LDAP/LDAPS. R902 requires public SSH then a screensharingd VNC SYN-ACK to the same external peer, unlike R774 isolated VNC response, R775 sshd response then user-tool egress, and R891 inbound VNC client data. R903 requires a parser-classified SMB2 WRITE and WinRM/5985 SYN, same private source, target and PowerShell PID; R554 SMB2 WRITE→FTP, R719 PowerShell external SMB payload, R789 net SMB WRITE→FIN and R631 command interpreter RDP have different predicates. R904 requires curl, exact single binary Content-Type header and HTTP PUT, not generic upload, POST or download. R905 uses MMC private SMB SYN→public TLS under one local source/PID, unlike R345 DCOM MMC and R665 Explorer WebDAV→external SMB. Overlapping broader detections can still match; independence is not proven recall or precision.

Workbook full analytics require host audit, authenticated sessions, command lines, COM/DLL and file events, LDAP query content or confirmed transfer outcome. Those claims remain unsupported; these are explicitly restricted packet/process projections. R902 has no reliable account/session association between stages. R904 observes request headers and transport bytes, not binary file content; R903 observes a parsed request, not a successful write. R905 process attribution is local and not proof of COM operation. No raw request headers, payload, credentials or Info are included in event evidence.

R901/R903 correlate source, peer and PID; R902 correlates private/public addresses and requires screensharingd attribution only on response; R905 correlates source and PID across private and public peers. State is bounded by existing per-instance helpers; time windows 45 seconds and cooldown 10 minutes. R904 is a single request candidate. No endpoint audit producers added.

## Test source

`Carthago.Tests/R901R905ObservableCandidateBatchTests.cs`: per-rule positive, benign, missing/contradictory fields, duplicate/reverse/expiry, cooldown recovery, key isolation, exact content-type, parsed SMB evidence versus raw Info, cross-rule independence, registry uniqueness and Candidate/Shadow. **Not executed.**

## Owner workbook references

- R901 / R1991: https://attack.mitre.org/detectionstrategies/DET0007#AN0016
- R902 / R2054: https://attack.mitre.org/detectionstrategies/DET0269#AN0752
- R903 / R1321: https://attack.mitre.org/detectionstrategies/DET0183#AN0516
- R904 / R2375: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_susp_data_exfiltration_via_cli.yml
- R905 / R1764: https://attack.mitre.org/detectionstrategies/DET0222#AN0622

Next unallocated ID: **R906**, subject to fresh registry inspection.
