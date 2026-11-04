# CARTHAGO — R716–R725 independent workbook-derived source candidates

**SOURCE CANDIDATE — UNVERIFIED. xUnit authored; 0 tests, 0 builds, 0 replay runs.**

## Live-branch admission basis

Direct work on `feature/carthago-reliability-hardening`. Immediately before authoring, live HEAD was `ec9b2efedf29bcfd59f1eaab840195d85017706a`; the registry contained **715 registered rules / 715 unique IDs**, ending at R715, so R716–R725 were free. The branch must be re-fetched again before publication and the expected-HEAD lease must still match.

Research comes from the owner-provided `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`. No additional online research was used to select these candidates. Original workbook IDs and source URLs are retained below.

Every rule remains its own Candidate / Shadow detector. Shared code is restricted to evidence validation/classification; rule identities, predicates, state, cooldowns, tests and documentation remain independent. No process command line, file read/write, authentication outcome, exploit success, server response, device state, transfer completion, returned public IP, or encrypted payload is invented.

| Carthago | Workbook / rank | Narrow observable behavior | Existing overlap and limitation |
|---|---|---|---|
| R716 | R2697 / 29 | Same source sends 18-byte UDP datagrams to port 50000 on two distinct private devices within 60 seconds | Workbook evidence includes SIPROTEC restart/offline outcomes Carthago cannot observe. This keeps only the documented packet shape and distinct-target correlation; no device identity or restart result is asserted. |
| R717 | R1304 / 162 | PowerShell, curl or Python process sends cleartext POST to GitHub/GitLab repository API route | R656 owns Git smart-HTTP push; R504 owns Gist-specific behavior. File-read correlation, HTTPS body, authentication, accepted upload and exfiltration are unavailable. |
| R718 | R1330 / 175 | PowerShell/Office process produces four substantial TLS payload observations to a cloud-storage SNI | R104/R105 require explicit HTTP upload/baseline/volume context. R718 intentionally does **not** call packet lengths upload bytes and does not claim an upload or file read. |
| R719 | R1373 / 188 | PowerShell process produces three raw outbound TCP/445 payload observations to a public peer | R556 is public→private parsed SMB2 WRITE fanout; R719 is private→public process-attributed payload observation. SMB authentication, share access and file transfer are unknown. |
| R720 | R2325 / 1150 | wmic.exe-associated cleartext external GET for .xsl/.xslt | Sigma source is command-line SquiblyTwo detection. Carthago does not observe `/format:`, XSL contents, in-memory execution or application-control bypass. |
| R721 | R2321 / 1664 | HybridConnectionManager.exe-associated TLS SNI contact to Azure Service Bus | R629 is DNS-only HCM→Service Bus. R721 preserves a distinct TLS observation. Service state, configuration, authentication and relay establishment are unknown. |
| R722 | R2382 / 1688 | bitsadmin.exe-associated outbound GET ending in a high-risk script/executable/archive/web extension | R686 requires direct-IP Bitsadmin GET; R696 requires file-sharing-service contact. R722 instead requires the suspicious-extension request path. No local target or download outcome is visible. |
| R723 | R2664 / 2335 | Script process sends a direct external DNS query with a long/high-diversity first label | R268 is generic script DNS/HTTP and R102 is generic DNS long-label analysis. R723 requires exact script-process attribution + direct public resolver + bounded high-entropy shape. Resolver policy and tunneling are not established. |
| R724 | R2742 / 2473 | curl/wget/PowerShell contacts a bounded public-IP discovery service via cleartext GET or TLS SNI | Shell command intent and the returned IP are unavailable. This is service contact only, not proof of discovery intent or subsequent use. |
| R725 | R2783 / 2480 | curl/wget sends an outbound cleartext GET with browser-like Mozilla User-Agent | R642 is script-host POST; R682 is Rundll32/MSHTA heartbeat GET; R172 is inbound scanner/browser mismatch. R725 preserves exact curl/wget identity and does not claim spoofing intent. |

## Observable evidence boundaries

- **R716** requires coherent IPv4 UDP, destination port 50000, an 18-byte L4 payload, no contradictory HTTP/TLS/DNS/application classification, and two distinct private targets. It does not parse SIPROTEC restart content.
- **R717** accepts only parser-coherent cleartext POST requests to `api.github.com/repos/...` or `gitlab.com/api/v4/projects/...`, with an exact locally attributed PowerShell/curl/Python process. Git smart-HTTP and Gist routes are deliberately outside its predicate.
- **R718** requires TLS/443, a bounded cloud-storage SNI family, exact PowerShell/Office process identity and four 900–8192 byte payload observations totaling at least 6000 observed packet bytes within two minutes. Packet bytes are not unique transfer bytes.
- **R719** requires PowerShell/pwsh, private→public TCP/445, payload-bearing packets and either absent application classification or SMB-like classification. Three observations totaling at least 600 packet bytes are required in two minutes.
- **R720** requires a parsed cleartext GET and exact `wmic.exe` process attribution. Only the URI extension is evaluated; raw URI/query is never emitted in rule evidence.
- **R721** requires exact `hybridconnectionmanager.exe`, TLS/443 and SNI under `servicebus.windows.net`.
- **R722** requires exact `bitsadmin.exe`, parsed GET and one of the bounded suspicious extensions documented in source. Request observation is not download completion.
- **R723** requires parser-valid DNS query telemetry, destination port 53, private→public direction, exact script/interpreter process identity, and a first label 28–63 characters with at least four digits and fourteen distinct characters. Full QNAME is redacted from emitted event fields.
- **R724** requires exact curl/wget/PowerShell identity plus either cleartext GET host or TLS SNI matching one of: `api.ipify.org`, `ifconfig.me`, `ipinfo.io`, `icanhazip.com`, `checkip.amazonaws.com`, `ident.me`.
- **R725** requires exact curl/wget identity plus cleartext outbound GET and a browser-like User-Agent containing `Mozilla/5.0` and a Chrome/Firefox/Edge/Safari marker. User-Agent mismatch is not proof of malicious spoofing.

All state is bounded and rule-owned. The stateful candidates reject duplicate packet IDs, reverse time and expired windows; all rules use independent ten-minute cooldown state. Event evidence uses fixed labels and workbook IDs rather than raw payloads, URI queries, command lines, credentials or DNS names.

## xUnit source — authored, not executed

`Carthago.Tests/R716R725AdvancedAccuracyBatchTests.cs` covers:

- positive real-life-shaped observations for all ten candidates;
- benign near misses for each independent predicate;
- missing required telemetry and contradictory TCP/UDP fields;
- duplicate packet IDs, reverse timestamps and window expiry for correlated candidates;
- packet replay/reverse-time checks for single-event candidates;
- independent cooldown suppression and recovery for every rule;
- privacy/redaction checks for free-form Info, HTTP query values and DNS QNAME;
- explicit non-convergence checks between neighboring rule families;
- Candidate / Shadow registration and complete registry ID uniqueness.

**Zero tests, builds, CI jobs, packet captures, replay tests or holdouts were executed.**

## Workbook source references

- R716 ← R2697 (rank 29): https://attack.mitre.org/detectionstrategies/DET0801#AN1933
- R717 ← R1304 (rank 162): https://attack.mitre.org/detectionstrategies/DET0318#AN0895
- R718 ← R1330 (rank 175): https://attack.mitre.org/detectionstrategies/DET0570#AN1571
- R719 ← R1373 (rank 188): https://attack.mitre.org/detectionstrategies/DET0131#AN0367
- R720 ← R2325 (rank 1150): https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_wmic_squiblytwo_bypass.yml
- R721 ← R2321 (rank 1664): https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/builtin/servicebus/win_hybridconnectionmgr_svc_running.yml
- R722 ← R2382 (rank 1688): https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_bitsadmin_download_susp_extensions.yml
- R723 ← R2664 (rank 2335): https://attack.mitre.org/detectionstrategies/DET0934#AN2099
- R724 ← R2742 (rank 2473): https://attack.mitre.org/detectionstrategies/DET0357#AN1016
- R725 ← R2783 (rank 2480): https://attack.mitre.org/detectionstrategies/DET0898#AN2031

After successful atomic publication, the next contiguous candidate block is **R726–R735**, subject to a fresh live-branch check before allocation.
