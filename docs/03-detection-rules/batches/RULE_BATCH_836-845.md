# CARTHAGO — R836–R845 independent observable network candidates

**SOURCE CANDIDATE — UNVERIFIED. 0 tests, 0 builds, 0 CI, 0 replay, 0 holdouts executed.**

Source: owner-provided `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`. New CARTHAGO IDs below are independent of original workbook IDs. Ten separate C# rules with instance-owned bounded state, distinct Rule IDs, xUnit source and registry entries. All remain **Candidate / Shadow** with an **80% confidence floor**.

| New ID | Workbook | Specific packet-level observation | Essential limitation |
|---|---|---|---|
| R836 | R970 | Inbound public SYN to private PostgreSQL/5432 then `postgres`-attributed public TLS/8443 | No PostgreSQL COPY PROGRAM, SQL query, OS command or completed exfiltration |
| R837 | R1015 | Two different public resolvers return different single-public-IP A answers for a private client's same qname, followed by its SYN to the second answer | Resolver disagreement is not proof of DNS poisoning or trusted resolver status |
| R838 | R1217 | Same `npm`/`pip`/`dotnet` PID reaches known package registry SNI then a different public TLS/8443 peer | No dependency install, filesystem write, malicious package, child process or supply-chain compromise |
| R839 | R1230 | Public encoded `%2e%2e` traversal GET to private HTTP/80 then `w3wp` public TLS/8443 | GET does not prove exploit success or web worker causality |
| R840 | R1339 | Eight cleartext GET packets to one private HTTP/80 path from one public client in 20s, >=3,200 aggregate payload bytes | No request rate across all sockets, server exhaustion or DoS impact verified |
| R841 | R1370 | Local Firefox/Chromium JavaScript-path GET then `python` TLS/8443 to another public peer | No browser script execution, parent-child link or drive-by compromise |
| R842 | R2028 | PowerShell/wscript TLS packet to selected public API SNI then reverse 5-tuple payload response | Bidirectionality is ordinary for TLS and no encrypted command/C2 content is decoded |
| R843 | R2059 | Same curl/python2 PID and public peer: TLS1.3 metadata then TLS1.0/1.1 metadata in 90s | No handshake-negotiation provenance, active downgrade or security outcome |
| R844 | R2846 | One public DNS resolver sends three distinct *single-IP* low-TTL A answers for same qname/client in 45s | Separate from R096 (four answers in one response); not validated fast-flux or C2 |
| R845 | R1168 | Same scp PID transmits payload to TCP/22 in two different private /24 networks | No file transfer completion, VM/ESXi role or lateral execution proven |

## Evidence policy and no-convergence boundaries

- Every rule independently matches **only fields CARTHAGO can observe** on the typed packet/process record. No absent host, SQL, CI/CD, file writes, syscall, authorization, exploit outcome or external-service identity is inferred.
- Distinct per-instance correlation and cooldown state; R837 has a dedicated 512-key monotonic state machine, and R844 counts three separate canonical single-IP response records rather than one response with multiple answers.
- A two-step sequence is a temporal coincidence at a source IP or PID, not verified process lineage. A reverse TCP response (R842) is not a C2 verdict. Legitimate automation, upgrades, CDNs, geolocation DNS and admin transfers can match.
- Common typed protocol hygiene is reused without sharing a detector state. Other rules' predicates or thresholds are not merged; specifically the pre-existing R096 single-response fast-flux predicate is preserved.
- Rule events use **static research IDs, matched-condition tags and unknown-outcome strings**. Raw `TrafficRecord.Info`, qnames, paths, TLS payloads, hostnames and user identifiers are not added to custom evidence fields.
- Initial acceptance is source-only; the owner instructed to **not execute** tests/builds/Actions/holdout. Promotion requires positive/benign replay, producer capability, non-duplication, accuracy, and performance gates.

## xUnit source (authored first, not executed)

`Carthago.Tests/R836R845ObservableCandidateBatchTests.cs` supplies all ten coherent positive fixtures, benign near misses, contradictory TCP/UDP evidence and missing IPs, repeated packet IDs, expired first stages, cooldown suppression/recovery, raw Info exclusion, DNS resolver-answer specificity, reverse-tuple directionality, SSH subnet separation, and registry uniqueness with Candidate/Shadow profile assertions.

**These assertions have not been compiled or executed. They do not establish a passing test result.**

## Original owner-workbook references

- R836 / R970: https://www.postgresql.org/docs/current/runtime-config-logging.html
- R837 / R1015: https://attack.mitre.org/datacomponents/DC0085/
- R838 / R1217: https://attack.mitre.org/detectionstrategies/DET0009#AN0021
- R839 / R1230: https://attack.mitre.org/detectionstrategies/DET0080#AN0219
- R840 / R1339: https://attack.mitre.org/detectionstrategies/DET0173#AN0489
- R841 / R1370: https://attack.mitre.org/detectionstrategies/DET0176#AN0499
- R842 / R2028: https://attack.mitre.org/detectionstrategies/DET0035#AN0100
- R843 / R2059: https://attack.mitre.org/detectionstrategies/DET0350#AN0996
- R844 / R2846: https://attack.mitre.org/detectionstrategies/DET0485#AN1333
- R845 / R1168: https://attack.mitre.org/detectionstrategies/DET0183#AN0519

**Next unallocated CARTHAGO ID: R846. SOURCE CANDIDATE — UNVERIFIED.**
