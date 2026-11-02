# R568 — Redis CONFIG SET denial followed by HTTP default admin attempt

SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.

Ordered cross-service sequence: a parser-confirmed, SYN/SYN-ACK anchored Redis RESP2 CONFIG SET error reply to a public IPv4 client precedes a known-default HTTP Basic admin request from that same client to the same RFC1918 host within 120 seconds. Unlike R567, Redis is observed first, so the rule is a distinct temporal behavior, not a new Redis protocol. No authentication, exploitation or compromise is inferred. Candidate/Shadow, confidence 90%, 600s cooldown, bounded state, approved admin exclusions, fixed non-secret evidence. Seven authored xUnit scenarios exercise parser-backed positive, +OK negative, benign HTTP, missing handshake/wrong peer, expiration/duplicate IDs, spoofed flags, and privacy/registry policy. Not executed.
