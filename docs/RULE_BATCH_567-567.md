# R567 — Default HTTP admin attempt followed by Redis CONFIG SET denial

SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED.

## Distinct predicate
A parser-confirmed known-default HTTP Basic request to a private host's admin endpoint from a public IPv4 client precedes an independently TCP SYN/SYN-ACK-correlated RESP2 error reply to the same client's Redis CONFIG SET request on that private host within 120 seconds. This is a **denied/error-shaped Redis outcome**, unlike R566's +OK reply. It does not prove successful HTTP authentication, successful exploitation, Redis authorization, or a durable configuration change.

## Producer and research mapping
Existing PacketHandler HTTP Basic default-credential parser and Redis RESP2 CONFIG SET request/reply correlator. Protocol research P0024 (Redis RESP). No new producer, protocol inventory or packet handling modifications.

## Guardrails
Candidate/Shadow, 90% confidence floor, 120-second window, 600-second cooldown, bounded 512 pairs and 64 packet IDs per pair, approved-admin exclusion, fixed non-secret evidence. Denial may reflect ordinary defensive controls; treat as suspicious cross-service probing rather than compromise. The rule intentionally does not match +OK, PING, missing SYN-ACK, nondefault credentials, unrelated peers, stale/reversed timestamps or JSON-forged flags.

## Authored tests (not executed)
Seven xUnit tests cover parser-backed positive, +OK negative, benign HTTP, peer/handshake, expiry/duplicate IDs, spoofing/metadata, privacy and registry policy. No compilation or runtime verification claimed.
