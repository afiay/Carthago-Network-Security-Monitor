# GA R566 — default HTTP admin credential attempt followed by Redis CONFIG SET OK-shaped reply

**Branch:** `feature/carthago-reliability-hardening` · **Source base:** `e67873cd3a2c78bdaee33295091922d311f6ba9f` (2026-11-02).  
**Status:** **SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.** One ordinary registered rule in the existing engine, no new producer or separate protocol runtime. Publication is not production promotion.

## Predicate, research mapping and novelty

**R566** correlates two **independently captured, typed, parser-origin signals** involving the **exact same globally routable public IPv4 client and RFC1918 private server**:

1. The public peer sends a complete, plaintext HTTP/1.x GET/POST to an anchored administrative path, with a known-default Basic credential internally recognized and redacted by `PacketHandler` (`HttpBasicDefaultCredentialObserved`).
2. Within **120 seconds**, the same private server sends that public peer a first-reply RESP2 `+OK` shape that `PacketHandler` has correlated to a **SYN/SYN-ACK-anchored, complete first `CONFIG SET` request** on TCP/6379 (`RedisRespConfigSetReplyOkObserved`).

The rule requires unique packet IDs, coherent first-segment IPv4/TCP fields, strict time ordering and exact reverse endpoint identity; it does **not** infer that the HTTP request authenticated, that the Redis server is authenticated, that the setting was security-relevant, or that any persistent change, compromise or exploitation occurred. The Redis response is only an observed wire shape. The rule does not inspect Redis command parameters or retain Basic credentials.

**Research crosswalk:** **P0024 Redis RESP** supplies the Redis-specific protocol context. The historical P0001/P0002 entries describe HTTP/2 and HTTP/3, **not** the existing HTTP/1.x producer; the original P0001–P0500 inventory has no independent HTTP/1.x entry. No new P ID or protocol GA is created.

**Existing coverage:** R437 detects Redis CONFIG SET indications; R561 and R562 cover same-server error/retry transitions; R564 covers `+OK` across two private subnets; R549 and R563 cover default-Basic fanout and HTTP→Modbus; R565 covers HTTP→FTP callback. **None requires an HTTP default-credential administrative request followed by a correlated Redis CONFIG SET OK-shaped response from the exact same host to the exact same public peer.** This is a cross-service ordered hypothesis, not a separate Redis inspector or a new claim of configuration success.

## Source, policy and false-positive controls

- **Producer:** existing `PacketHandler` HTTP/1.x parser and existing SYN-anchored RESP2 request/reply correlator. Both flags are `internal set` and cannot be set by imported JSON. Public `ApplicationProtocol`, `Info`, ports, headers or URI alone cannot fabricate either flag.
- **Required visibility:** capture of complete cleartext HTTP headers, the Redis SYN, SYN-ACK, first `CONFIG SET` request and first `+OK` reply, with accurate IP endpoints. HTTPS, Redis TLS, TCP segmentation gaps, NAT, proxies and one-sided capture limit the rule. No authenticated asset identity or application/server audit outcome exists.
- **Policy:** High severity; **Candidate / Shadow**; **90% configured minimum confidence**; one ordered pair in **120 seconds**; **600-second cooldown**. A configured approved administrator on either peer suppresses the rule; an empty allowlist is not an assertion of unauthorized activity. Routine multi-service provisioning and maintenance are realistic benign lookalikes.
- **State:** instance-owned lock, maximum **512 exact endpoint pairs** and **64 packet IDs per pair**; bounded stale-state pruning, strict monotonic time, seed consumption, cooldown suppression and saturation fail-closed. No raw packet, HTTP headers, Redis command parameters or secret values are stored in correlation state.
- **Privacy and lifecycle:** only fixed, non-secret structured evidence labels are added. No Authorization, URI, Host, command parameter/value, raw RESP or `Info` is copied into evidence. `RuleEngine` and its journal-first `DetectionEvent` lifecycle remain the sole emission path; no direct UI alert or alternate journal.

## Files and authored accuracy coverage

- `Carthago/Engine/Rules/Expansion/R566_DefaultBasicAdminThenRedisConfigOkRule.cs` — ordinary precision rule.
- `Carthago/Engine/Rules/Catalog/RuleRegistry.cs` — one additive registration.
- `Carthago.Tests/R566AdvancedAccuracyBatchTests.cs` — **17 xUnit methods, 21 concrete invocations** (**16 `[Fact]` and one five-case `[Theory]`**), **0 executed**.
- `docs/RULE_BATCH_566-566.md` and `docs/rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md` — detection-owned GA and screening decision.

The authored scenarios exercise real `PacketHandler` producer positives, benign non-default and duplicate Basic, non-admin path, Redis errors and PING, missing SYN-ACK, wrong peer/server, reserved addresses, reversed/equal/out-of-order time, expiry, duplicate IDs, JSON forgery, port/Info-only and TLS/QUIC contradiction, seed consumption, cooldown, concurrent duplicate, secret redaction, explicit approval logic, registry uniqueness and Shadow/90% policy. **No build, restore, test, replay, capture, holdout, CI, benchmark or runner was executed.** Counts are authored-source counts, not passing evidence.

## Blocked candidates and next cursor

**Windows/AD R566 alternative screened and BLOCKED:** `WinRmLocalSecurityAuditReader` currently yields **unsigned candidate** associations of local 4624 network logons and 4688 encoded PowerShell process creation. `WinRmTelemetryIpcContract` explicitly has **no authenticated transport adapter** and R343 intentionally returns `NoMatch` pending trustworthy operation/command outcome. Creating another WinRM/AD detection from these candidates would manufacture authentication or remote execution proof. Required integration: owner-approved, OS-authenticated local audit transport with source identity, consumer wiring, versioned schema, privacy contract and independent outcome evaluation. No shared edits made. FortiClient EMS Site-header, GitLab worker outcomes, DNS answer/TTL and IMDS credential-outcome candidates remain blocked for their documented producer gaps.

**Primary technical references (reviewed 2026-11-02):** [Redis CONFIG SET specification](https://redis.io/docs/latest/commands/config-set/) (documents `OK` semantics, not independent host attestation); [MITRE T1078.001](https://attack.mitre.org/techniques/T1078/001/) and [DET0465](https://attack.mitre.org/detectionstrategies/DET0465/) (both last modified **2026-05-12**, require authenticated account evidence for actual default-account abuse); [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); [FIRST EPSS](https://www.first.org/epss/) (probability, not exploitation proof). **No specific CVE, exploited Redis version or EPSS score is claimed.**

**Next proposed cursor:** **R567** only after a fresh live registry, producer and semantic deduplication review. Prior R102/R118/R163 floors **80/86/84%**, frozen V1 holdout (historical 4/6), pending V2, UI ownership and historical P research remain unchanged.
