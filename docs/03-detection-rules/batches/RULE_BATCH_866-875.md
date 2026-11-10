# CARTHAGO — R866–R875 typed-network source candidates

**SOURCE CANDIDATE — UNVERIFIED. Test source was authored before implementation; 0 tests, builds, CI jobs, replays or holdouts were executed.**

The owner workbook `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx` supplies research provenance. The original analytics frequently depend on trusted host logs, configuration events, asset roles, decoded industrial protocol functions or application responses that CARTHAGO has not demonstrated. The rules below implement **strictly narrower typed-packet observations**, not those complete analytics. All ten are independent `RulePrecisionMaturity.Candidate` / `RuleRuntimeMode.Shadow` registrations with a minimum confidence floor of 80 and ten-minute per-rule cooldown; no existing detector was changed.

| New rule | Original workbook ID | Accepted packet-visible predicate | Not established |
|---|---|---|---|
| R866 | R1007 | Three distinct A-response subdomains of one base domain from the same private resolver to the same private client resolve to the same public IPv4 within 60s | DNS wildcard, zone update, sensitive name, malicious answer |
| R867 | R1008 | Private DNS SRV answer naming a host, then same client's public TCP/443 TLS SNI for that host within 90s | Dynamic update, SRV authenticity, LDAP authentication, session success |
| R868 | R1019 | One private resolver returns a private A address and later a public A address for the same QNAME to *different private clients* within 90s | Split-horizon configuration, resolver trust, DNS poisoning |
| R869 | R1384 | Public-to-private TCP/135 SYN then same source/target TCP/49152–65535 SYN within 45s | DCOM invocation, account identity, remote process execution |
| R870 | R2036 | Four `hostd`-attributed HTTP/80 `GET /api/*poll*` requests to one public host within 40s | ESXi identity, command channel, remote response, encrypted payload or C2 |
| R871 | R2692 | `modpoll`-attributed TCP/502 data to four distinct private devices in one /24 within 60s | Modbus function code, successful reads, device inventory, data collection |
| R872 | R2788 | Same public client requests typed `GET /snapshot.jpg` and `GET /stream.mjpg` from a private HTTP service within 45s | Embedded device or camera identity, returned images, screen capture |
| R873 | R2772 | Private UDP/1900 to SSDP multicast followed by same source's private TCP/8008 SYN within 60s | Parsed M-SEARCH, IGMP membership, device discovery success |
| R874 | R2705 | Eight unique private TCP/502 SYN packets between the same two peers in 30s | Switch counters, packet loss, denial of service, target availability |
| R875 | R2778 | One public client's TCP/20000 SYN followed by same source/target application-sized TCP payload within 40s | DNP3 decode, authenticated remote access, control command or impact |

## Selection, isolation, source coverage

- Read the live registry and original workbook before allocating R866–R875. No selected workbook origin was already referenced by existing expansion rule sources. The packet predicates differ from older DNS-answer churn, conflicting-resolver-plus-SYN, public industrial SYN/ACK, HTTP upload, hostd POST and generic service-flood rules.
- A single typed packet is never sufficient to trigger these ten candidates. Independent per-rule state tracks unique packet identifiers, strictly increasing UTC timestamps and bounded peer/host/path/QNAME keys. Correlation is not shared between rules and does not imply causal sequence beyond arrival order.
- Reject malformed peers, missing or contradictory TCP/UDP fields, incorrect packet direction, unsupported or mismatched L7 labels, duplicate IDs, expired observations and out-of-order timestamps. Static evidence contains only the workbook identifier, predicate identifier and explicit unknown-outcome statement; it never echoes raw `Info`, DNS names/answers, hostnames, URLs, packet payloads or credentials.
- False positives are substantial for normal DNS responses, DNS service discovery, RPC negotiation, ESXi maintenance polling, industrial asset discovery, SSDP, device monitoring and high SYN rates. Rules remain Shadow. Local process names/PIDs, where available, do not establish host command lines or process ancestry.
- Source-only quality is not production quality: require trusted producer contracts, benign fixtures, authenticated-device inventory, live capture validation, deterministic replay, performance budgets and frozen holdout evidence before promotion. None were executed for this batch.

## xUnit source — authored, not run

`Carthago.Tests/R866R875ObservableCandidateBatchTests.cs` covers typed positives for each rule, benign near misses, null destinations, contradictory TCP/UDP markers, duplicate IDs, reverse UTC, expired first observations, cooldown suppression/recovery, SRV/SNI mismatch, DNS cross-client constraints, neighbor independence, raw-Info non-disclosure and unique Candidate/Shadow registry membership. **Compilation and test results remain unknown.**

## Original research references

- R866 / R1007 — https://attack.mitre.org/datacomponents/DC0085/
- R867 / R1008 — https://attack.mitre.org/datacomponents/DC0085/
- R868 / R1019 — https://attack.mitre.org/datacomponents/DC0085/
- R869 / R1384 — https://attack.mitre.org/detectionstrategies/DET0285#AN0791
- R870 / R2036 — https://attack.mitre.org/detectionstrategies/DET0581#AN1602
- R871 / R2692 — https://attack.mitre.org/detectionstrategies/DET0734#AN1867
- R872 / R2788 — https://attack.mitre.org/detectionstrategies/DET0751#AN2250
- R873 / R2772 — https://attack.mitre.org/detectionstrategies/DET0908#AN2051
- R874 / R2705 — https://attack.mitre.org/detectionstrategies/DET0723#AN2168
- R875 / R2778 — https://attack.mitre.org/detectionstrategies/DET0803#AN2224

**Next available candidate ID after publishing: R876. All R866–R875 remain SOURCE CANDIDATE — UNVERIFIED.**
