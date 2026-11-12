# CARTHAGO — R906–R925 observable research candidates

**SOURCE CANDIDATE — UNVERIFIED.** Twenty independent Candidate/Shadow rules, four groups of five. Test source authored first; zero builds, tests, CI jobs or runtime replays executed. No existing detector, capture producer, UI, runner or concurrent enrichment changes. The original workbook analytics require more telemetry than CARTHAGO has; these are restricted research-inspired observable projections, not full ATT&CK/Sigma implementations.

| ID | Workbook origin | Observable predicate and limitations |
| --- | --- | --- |
| R906 | R2110 | Rundll32-associated TCP/445 SYN then TCP data on the same public peer and source port. Remote DLL path, execution and authentication are unknown. |
| R907 | R2358 | MSHTA public HTTP GET for .png, .jpg or .pdf. File contents, polyglot format and execution are unknown. |
| R908 | R2239 | Public TCP/445 SYN to private host followed by parsed SMB2 WRITE on the same source port. Admin share, account, filename and write success are unknown. |
| R909 | R1122 | Private TCP/22 SYN to a private host followed by that host sending TCP/3389 SYN to a public peer. Bastion role, login and authorization are unknown. |
| R910 | R1223 | Same private source, PowerShell PID and private peer TCP/389 SYN then parsed SMB2 WRITE. GPO object, SYSVOL path, authentication and modification are unknown. |
| R911 | R1470 | Same private source and rsync PID sends TCP/873 data to three distinct private peers. File, arguments, authorization and execution are unknown. |
| R912 | R1643 | Public SSH SYN to private host then BusyBox TCP/873 data from that host to a private peer. Shell execution, SSH authentication and transfer are unknown. |
| R913 | R1689 | Hostd/vpxa PID sends four TCP/22 data records of at least 512 bytes to a public peer. SSH content, encoding and C2 are unknown. |
| R914 | R1769 | Rundll32 TCP/443 SYN followed by reverse-tuple certificate metadata with validity start more than 24 hours in the future. Certificate acceptance, library load and C2 are unknown. |
| R915 | R1827 | Same dsconfigad PID and private peer TCP/389 SYN then TCP/88 SYN. Domain enrollment, account creation and authentication are unknown. |
| R916 | R2055 | Hostd/vpxa UDP A query to public resolver followed by reverse-tuple NXDOMAIN with same normalized qname. DNS transaction ID, DGA and resolver trust are unknown. |
| R917 | R2642 | Private TCP/3389 SYN to private host followed by that host sending TCP/5985 SYN to another private peer. ICS role, approved matrix, login and execution are unknown. |
| R918 | R2656 | Same private source and PowerShell PID sends parsed private Modbus write request then public TLS/443 data. Script, OT role, authorization and write outcome are unknown. |
| R919 | R2344 | Same private source, PsExec PID and private peer parsed SMB2 WRITE then TCP/135 SYN. Named pipe, service creation, account and execution are unknown. |
| R920 | R2362 | Same private source and PowerShell PID sends public cleartext GET for .ps1 then public TLS/443 data. Download completion, IEX, execution and C2 are unknown. |
| R921 | R2476 | Same private source, AnyDesk PID and public peer TCP/6568 SYN followed by TLS/443 data. Installation path, interactive control, consent and session outcome are unknown. |
| R922 | R2193 | Public cleartext HTTP POST to /pswa/default.aspx or /pswa/ on a private host. PSWA installation, credentials and execution are unknown. |
| R923 | R1180 | Local w3wp attribution and outbound public HTTP POST to an .aspx path with at least 512 transport bytes. IIS module installation, contents, persistence and C2 are unknown. |
| R924 | R1345 | Public TCP/3389 SYN to private host followed by that host sending TCP/445 SYN to a private peer. Authentication, sessions and lateral compromise are unknown. |
| R925 | R1233 | Same private source and bitsadmin PID TCP/445 SYN to private peer followed by public HTTP GET. BITS job, notification command, transfer and persistence are unknown. |

## Duplicate and producer screen

The original workbook ranked rows and direct source references were consulted. R2300 excluded because R691 already implements public SMB listener exposure. R1716 excluded because R677 covers TLS on DNS/alternate HTTP ports. R2365/R2936 direct-IP BITS retrieval excluded because R686 covers that shape. The expansion cursor was checked for prior origins, registry IDs and relevant rule predicates. R906 is process-attributed SMB sequence rather than R691 listener response or R719 PowerShell SMB burst. R907 MSHTA image/PDF GET differs from R835 HTA then rundll32. R908 same-flow public SYN then parsed SMB2 WRITE differs from R556 fanout. R909 private SSH to public RDP differs from R886 public SSH to private SMB. R910 LDAP contact then same-target SMB WRITE differs from R903 SMB to WinRM. R911 private distinct rsync peers differs from R863 public same-peer burst. R912 public SSH then BusyBox private rsync-port data differs from R879 Telnet then public TLS. R913 hostd SSH-port burst differs from R855 HTTP/R858 TLS bursts. R914 future-validity reverse-tuple certificate differs from R811 expired certificate. R915 dsconfigad LDAP then Kerberos differs from R823 dscl LDAP/LDAPS. R916 hostd DNS query/NXDOMAIN tuple differs from R763 high-entropy queries and R844 low-TTL answers. R917 private RDP to private WinRM differs from R886. R918 Modbus WRITE then public TLS differs from R895 dual SYN and R557 public Modbus fanout. R919 PsExec SMB WRITE then RPC differs from R078 broad PsExec shape and R903 PowerShell/WinRM. R920 same-PID PS1 GET then TLS differs from R817 different shell egress and R814 media GET. R921 AnyDesk 6568/443 same-peer differs from R761 RMM cadence. R922 PSWA POST path differs from R630 outbound WinRM. R923 w3wp outbound ASPX POST differs from R839 inbound traversal to worker TLS. R924 public RDP to private SMB differs from R886 SSH to SMB and R917. R925 BITSAdmin private SMB to public HTTP differs from single BITS direct-IP GET R686. This is a targeted semantic screen, not an exhaustive formal equivalence proof; broader legacy rules may overlap.

## Telemetry and state limitations

Typed IPv4 packet fields, parser labels and local PID enrichment only. SYN/port contact is not established protocol or authentication; payload size is not decoded content. Host-only joins cannot establish common user/session or exclude unrelated peers beyond the explicit key. R916 cannot verify DNS transaction ID; R914 certificate metadata is capture-dependent and encrypted certificates may be unavailable. R918 is not an OT authorization analytic. R911 cooldown keyed by source/PID; others use final source/destination. Instance-owned bounded existing helpers; 45s correlation or 60s single-record profile; 10-minute cooldown. Existing helper and capture/ETW attribution limitations inherited. No inference of command lines, execution, authentication, actual file transfer, malicious intent, C2, GPO modification or authorization.

## Test source

`Carthago.Tests/R906R925ObservableCandidateBatchTests.cs`: positive and near-miss fixtures for every rule, missing/conflicting fields, empty/duplicate IDs, reverse/expired UTC, cooldown, flow/PID/DNS isolation, distinct-peer threshold, parser-label vs Info, future certificate and NXDOMAIN near misses, privacy, cross-predicate and registry tests. **Not executed.** Compilation, capture availability and precision remain unverified.

## Owner workbook direct source references

- R906 / R2110: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_rundll32_unc_path.yml
- R907 / R2358: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_mshta_susp_execution.yml
- R908 / R2239: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/builtin/security/win_security_smb_file_creation_admin_shares.yml
- R909 / R1122: https://attack.mitre.org/detectionstrategies/DET0269#AN0753
- R910 / R1223: https://attack.mitre.org/detectionstrategies/DET0305#AN0854
- R911 / R1470: https://attack.mitre.org/detectionstrategies/DET0183#AN0517
- R912 / R1643: https://attack.mitre.org/detectionstrategies/DET0384#AN1083
- R913 / R1689: https://attack.mitre.org/detectionstrategies/DET0108#AN0305
- R914 / R1769: https://attack.mitre.org/detectionstrategies/DET0543#AN1496
- R915 / R1827: https://attack.mitre.org/detectionstrategies/DET0003#AN0008
- R916 / R2055: https://attack.mitre.org/detectionstrategies/DET0419#AN1181
- R917 / R2642: https://attack.mitre.org/detectionstrategies/DET0804#AN1936
- R918 / R2656: https://attack.mitre.org/detectionstrategies/DET0929#AN2086
- R919 / R2344: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_sysinternals_psexec_remote_execution.yml
- R920 / R2362: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_powershell_download_iex.yml
- R921 / R2476: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk_susp_exec.yml
- R922 / R2193: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/powershell/powershell_script/posh_ps_powershell_web_access_installation.yml
- R923 / R1180: https://attack.mitre.org/detectionstrategies/DET0068#AN0184
- R924 / R1345: https://attack.mitre.org/detectionstrategies/DET0354#AN1004
- R925 / R1233: https://attack.mitre.org/detectionstrategies/DET0098#AN0274

Next unallocated ID: **R926**, subject to fresh live registry inspection.
