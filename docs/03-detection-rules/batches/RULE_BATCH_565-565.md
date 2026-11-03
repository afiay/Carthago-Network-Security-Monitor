# GA R565 — default HTTP Basic admin attempt followed by FTP callback

**Branch:** `feature/carthago-reliability-hardening` · **Source base:** `7f4139f23b2a3aef757e0f2d05eba97f0733dca2`.  
**Status:** **SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.** One coherent source-only rule, registration, authored tests and detection-owned documentation; no production promotion.

## Detection and novelty

| Rule / research mapping | Capture-derived predicate | Policy and existing coverage |
| --- | --- | --- |
| **R565** — default HTTP admin attempt followed by FTP upload-command callback; **500-entry inventory is contextual only** (P0001 HTTP/2 and P0002 HTTP/3 are *not* the HTTP/1.x source; the original P0001–P0500 roster does not contain an independent FTP entry). | A **globally routable public IPv4** peer sends one complete cleartext HTTP/1.x administrative request with a **PacketHandler-internal** known-default Basic credential flag to an RFC1918 host. Within **120 seconds**, that **exact private host** issues a parsed plaintext FTP `STOR` or `APPE` control command on TCP/21 **back to the exact same public IPv4 peer**. Two unique packet IDs, reverse endpoint match, coherent transport and strictly increasing timestamps required. | **High / Candidate / Shadow / 90% confidence floor / one two-stage chain / 120s / 600s cooldown.** R549 covers three-subnet private-to-private default-Basic fanout; R563 covers default-Basic then Modbus write to the same internal target; R554 covers SMB2 WRITE fanout then outbound FTP from the SMB client; R555 covers FTP commands to three public subnets. **None** requires an externally initiated default-credential attempt followed by a reverse-direction FTP command to that **same public peer**. |

**Threat semantics:** [MITRE T1078.001 Default Accounts](https://attack.mitre.org/techniques/T1078/001/) (modified **2026-05-12**) and [MITRE T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/003/) (modified **2026-09-03**) motivate the ordered hypothesis. [DET0465](https://attack.mitre.org/detectionstrategies/DET0465/) (modified **2026-05-12**) requires authenticated account evidence to establish actual abuse. [DET0149](https://attack.mitre.org/detectionstrategies/DET0149/) (modified **2026-05-12**) expects file/process/data-flow corroboration for exfiltration. The current packet-only rule has **none** of those outcomes. [RFC 959](https://www.rfc-editor.org/rfc/rfc959.html) (**1985-10**) defines STOR/APPE as FTP control requests; a control command is **not** a completed data-channel transfer.

## Producer, constraints and privacy

- `PacketHandler` uses bounded HTTP request parsing and redacts recognized Basic Authorization; `HttpBasicDefaultCredentialObserved` has an internal setter and is not populated by JSON imports. FTP `ftp.stor`/`ftp.appe` is classified from complete bounded first-segment plaintext commands by existing `NetworkBatch246250Wire` and `PacketHandler`; FTP's application label is **publicly writable** and not a cryptographic source attestation. No new capture/parser/telemetry contract was introduced.
- Only one **exact reverse RFC1918/public IPv4 pair** qualifies; the public peer must not be documentation, CGNAT, benchmark, private, multicast or loopback. FTP RETR/LIST, unknown/duplicated Authorization, non-admin routes, different callback hosts, wrong order, equal timestamps, TLS/QUIC, contradictory DNS/HTTP and port/Info-only guesses fail closed. HTTP/2, HTTP/3, HTTPS, FTPS, fragmented TCP and one-sided capture are outside this sensor's claim.
- Explicit `ApprovedAssetRegistry.Current` administrator hosts suppress recognized management peers or private admin endpoints; absence of policy does **not** establish unauthorized access. A management gateway using factory credentials to initiate an approved FTP backup can be benign; NAT/reverse proxy, spoofing, device asset roles and maintenance windows need review before promotion.
- State is instance-owned, lock-guarded and bounded to **512 private/public pairs** and **64 packet IDs per pair**, with stale-state pruning, 120-second ordered correlation and **600-second suppression cooldown**. A completed chain consumes its HTTP seed; FTP retries alone cannot produce another match. Saturation fails closed.
- Structured event evidence contains only fixed labels, count, window and `request_only_unverified`. It never copies Basic Authorization, username/password, HTTP Host/URI, FTP filename, raw Info, packet bytes or inferred file contents. Normal `RuleEngine` and mandatory JSONL journal remain the sole emission/persistence path. A detection **does not prove** HTTP authentication, compromise, FTP acceptance, file bytes, exfiltration, or any specific CVE.

## Authored source and test scenarios

- `Carthago/Engine/Rules/Expansion/R565_DefaultBasicAdminThenFtpCallbackRule.cs`
- `Carthago/Engine/Rules/Catalog/RuleRegistry.cs` — exactly one additive registration
- `Carthago.Tests/R565AdvancedAccuracyBatchTests.cs` — **16 xUnit methods, 20 concrete invocations authored, 0 executed** (**15 `[Fact]` plus one five-case `[Theory]`**)
- `docs/RULE_BATCH_565-565.md` and `docs/rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md`.

Scenarios cover actual raw IPv4/TCP PacketHandler HTTP and FTP recognition, positive reverse-peer sequence, benign unknown/duplicate Basic and non-admin/FTP read, exact endpoint correlation, five reserved/private peers, reverse/equal order, expiry/out-of-order, duplicate ID, port/Info-only FTP, TLS/DNS/QUIC contradiction, JSON forged HTTP flag, seed consumption/cooldown, concurrent duplicate, event privacy and registry/Shadow/confidence invariants. These are **source-authored assertions only**; no test, build, restore, replay, holdout, CI, runner, capture or benchmark executed. No precision, recall, F1, exploit attribution or production readiness claimed.

## Blocked and next

**BLOCKED**: FortiClient EMS header-based CVE exploitation needs parser-owned bounded Site-header classification and attested EMS version; GitLab CI-lint abuse needs app/worker logs; DNS rebinding needs parsed answer/TTL; IMDS credential extraction needs immutable metadata request and response/outcome. Shared producer contracts require owner approval. **REJECTED**: another Redis CONFIG SET OK/error permutation or mirrored OT subnet fanout without new action semantics.

**Primary research:** [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (consulted **2026-11-02**) and [FIRST EPSS](https://www.first.org/epss/) (consulted **2026-11-02**) establish no R565-specific exploited CVE or current EPSS score. No CVE signature is asserted. **Next proposed R566**, after a fresh branch/registry/producer audit, preferably with trusted Windows/AD identity outcomes rather than another request-only mirror. Frozen R102 V1, pending V2, R102/R118/R163 floors 80/86/84%, UI ownership and historical protocol research remain untouched.
