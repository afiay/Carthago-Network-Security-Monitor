# CARTHAGO — R926–R945 observable research candidates

**SOURCE CANDIDATE — UNVERIFIED.** Twenty independent Candidate/Shadow detectors, xUnit source tests authored first. No build, test, CI or runtime replay executed for this batch. Prior owner-supplied local test checkpoint at 0d2d7ef: 106/106 R906–R925 and 171/171 combined R896–R925, zero failed/skipped. That is unit-test evidence for the earlier batch only, not accuracy certification.

| ID | Workbook origin | Observable predicate and limitations |
| --- | --- | --- |
| R926 | R1672 | Odbcconf-attributed public HTTP GET for a DLL path. REGSVR arguments, DLL load, execution and authorization are not observed. |
| R927 | R1954 | Cscript-attributed public HTTP GET for a .sct resource. PubPrn invocation, script moniker and script execution are not observed. |
| R928 | R1835 | JamPlus-attributed cleartext HTTP GET for a .jam resource. Build invocation, file contents, child process and execution are unknown. |
| R929 | R1907 | Same private source and dfsvc PID GETs a public .application path then sends public TLS/443 data within 45s. ClickOnce install, manifest validation, child process and execution are unknown. |
| R930 | R1906 | Same local MSBuild PID retrieves a .targets path over cleartext public HTTP then initiates TCP/445 to a public peer. Build execution, downloaded contents and SMB authentication are unknown. |
| R931 | R2165 | Same private source and ntlmrelayx PID contacts private SMB/445 then LDAP/389 on another or same private peer. Credential relay, authentication and privilege changes are unknown. |
| R932 | R1072 | Public source sends parsed MQTT control-topic PUBLISH to private TCP/1883. Broker policy, acknowledgement, authorization and device action are unknown. |
| R933 | R1079 | Private client TCP/1883 SYN to private broker followed by same-flow parsed retained control-topic PUBLISH. Reconnection, delivery, command application and device response are unknown. |
| R934 | R1067 | Same private mosquitto_pub PID sends TLS/8883 to two distinct public peers within 45s. Broker trust-root changes, broker identity, MQTT session and policy are unknown. |
| R935 | R1613 | Hostd/vpxa TCP/443 SYN followed by reverse-flow visible TLS certificate whose issuer and subject strings are equal. Self-signature validity, vendor trust and C2 are unknown. |
| R936 | R2053 | Python-attributed public TCP/443 SYN followed by reverse-flow certificate metadata with NotAfter earlier than NotBefore. Parser observation only; certificate verification, acceptance, crypto library and compromise are unknown. |
| R937 | R1659 | Code or JetBrains Toolbox PID sends TLS/443 with marketplace SNI then TCP/22 SYN to a public peer. Extension installation, SSH tunnel and authorization are unknown. |
| R938 | R1290 | Ollama-attributed cleartext public POST to /api/embed or /api/embeddings on TCP/11434 with at least 512 transport bytes. Input contents, sensitive data, AI policy and exfiltration are unknown. |
| R939 | R1444 | Same private curl PID and public HTTP host/path sends four POST records of 512–4096 transport bytes at 5–20s intervals within 65s. Scheduled task, file contents and transfer completion are unknown. |
| R940 | R1806 | TeamViewer-attributed public TLS/5938 with SNI equal to teamviewer.com or its subdomain. Remote control session, installation provenance, persistence and consent are unknown. |
| R941 | R1925 | Public TCP/3128 SYN to a private host followed by that host initiating TCP/1080 SYN to another private peer within 45s. Proxy setup, forwarding configuration and actual relay are unknown. |
| R942 | R2654 | Private source sends a parsed SMB2 WRITE to a private host followed by that host initiating TCP/502 SYN to another private peer. File extension, execution, OT asset role and successful control action are unknown. |
| R943 | R1948 | InstallUtil PID sends public HTTP GET for an MSI path then public TLS/443 data. Signed binary status, installer contents, registration and execution are unknown. |
| R944 | R1874 | Same private source and MSHTA PID sends public HTTP GET for .hta then private TCP/5985 SYN. HTA execution, child process, authentication and remote command are unknown. |
| R945 | R1976 | Osascript-attributed cleartext public HTTP POST to Discord webhook path with exact Discord host. Webhook token, content, authorization and C2 are unknown. |

## Selection and limits

Original workbook rows and exact source URLs consulted; these are **research-inspired network projections**, not full ATT&CK/Sigma analytics. Prior R896 regsvr32 scriptlet retrieval, R907 MSHTA image/PDF retrieval, R920 PowerShell PS1 retrieval/TLS, R903 SMB/WinRM, R906 rundll32 SMB, R914 future certificate, R921 AnyDesk, R667 script MQTT control, R229 retain, R113 broker contact, R790 certificate issuer shift, R762 MSBuild TLS burst, R815 cadence and R886 public SSH/SMB were screened. The candidate predicates are narrower or different; broader legacy detections may overlap. Some source analytics require command line, file and module load, authenticated session, trust-store, process lineage, device identity, policy or host audit producers; those full analytics remain unsupported. Tool name attribution is optional local enrichment, not provenance. Some rare utility network behavior may be unreachable on standard installations; live producer tests are required before claiming coverage. Equal issuer/subject is not proof of self-signature. Inverted certificate dates can indicate parser or clock/metadata issues, not attack. MQTT topic flags are observation only. HTTP POST is a request, not completed transfer. Certificate visibility depends on TLS version and capture. No credential, raw Info, payload or raw HTTP header copied into detection evidence.

State is rule-owned and bounded via existing helpers; sequences 45s, cadence 65s, single-record 60s profile, cooldown ten minutes. R934 distinct peer threshold is address-based, not SNI uniqueness. Host-only joins R941/R942 cannot prove shared principal or causality. R939 cadence is packet/request shape, not scheduled-task evidence. Unit tests cover typed positives, near misses, missing/contradictory fields, empty/duplicate IDs, reverse/expired UTC, cooldown, PID/tuple separation, MQTT retain and distinct peers, cadence spacing, instance independence and registry. No accuracy or recall claim.

## Research references

- R926 / R1672: https://attack.mitre.org/detectionstrategies/DET0486#AN1335
- R927 / R1954: https://attack.mitre.org/detectionstrategies/DET0528#AN1464
- R928 / R1835: https://attack.mitre.org/detectionstrategies/DET0585#AN1610
- R929 / R1907: https://attack.mitre.org/detectionstrategies/DET0191#AN0550
- R930 / R1906: https://attack.mitre.org/detectionstrategies/DET0172#AN0488
- R931 / R2165: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_hktl_relay_attacks_tools.yml
- R932 / R1072: https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html
- R933 / R1079: https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html
- R934 / R1067: https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html
- R935 / R1613: https://attack.mitre.org/detectionstrategies/DET0543#AN1499
- R936 / R2053: https://attack.mitre.org/detectionstrategies/DET0543#AN1497
- R937 / R1659: https://attack.mitre.org/detectionstrategies/DET0561#AN1550
- R938 / R1290: https://attack.mitre.org/detectionstrategies/DET0927#AN2079
- R939 / R1444: https://attack.mitre.org/detectionstrategies/DET0397#AN1113
- R940 / R1806: https://attack.mitre.org/detectionstrategies/DET0496#AN1366
- R941 / R1925: https://attack.mitre.org/detectionstrategies/DET0445#AN1233
- R942 / R2654: https://attack.mitre.org/detectionstrategies/DET0745#AN1878
- R943 / R1948: https://attack.mitre.org/detectionstrategies/DET0081#AN0226
- R944 / R1874: https://attack.mitre.org/detectionstrategies/DET0506#AN1397
- R945 / R1976: https://attack.mitre.org/detectionstrategies/DET0348#AN0990

Next unallocated ID: **R946**, subject to fresh registry inspection.
