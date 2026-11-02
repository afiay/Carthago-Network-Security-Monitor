# R571 — Redis CONFIG SET OK reply before default HTTP admin attempt

SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED.

Existing PacketHandler SYN/SYN-ACK-anchored Redis RESP2 CONFIG SET +OK reply to a public IPv4 client precedes a known-default HTTP Basic admin request from that client to the same RFC1918 host within 120 seconds. Unlike R568 (error outcome), R571 requires a successful RESP2 reply shape, but does not claim authenticated Redis identity, durable configuration change or compromise. Candidate/Shadow; 90% confidence; bounded pair state; 600-second cooldown; approved-admin exclusions. Seven xUnit scenarios authored but unexecuted.

The batch also repairs a malformed assertion in the previously authored R568 tests; this is source-only and not a test execution.
