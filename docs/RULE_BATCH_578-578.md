# R578 — Redis CONFIG SET request then default HTTP Basic admin attempt

SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED.

Parser-backed Redis RESP2 CONFIG SET request and known-default HTTP Basic admin request from exact same public IPv4 client to exact same RFC1918 server within 120 seconds. Order Redis before HTTP. Unlike R566–R568 and R571, no Redis reply is required or inferred. Neither credential acceptance nor Redis config change is claimed. Bounded state, approved-admin exclusions, cooldown, Candidate/Shadow. Eight xUnit tests authored but not executed.
