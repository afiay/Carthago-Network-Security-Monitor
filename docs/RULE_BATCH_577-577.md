# R577 — FTP upload attempt followed by Redis CONFIG SET request

SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED.

A parsed outbound FTP STOR/APPE request from a private server to a public IPv4 peer precedes a parser-confirmed Redis RESP2 CONFIG SET request from that same peer to the same private server within 120 seconds. Reverse sequence of R576; request evidence only, no FTP completion or Redis configuration outcome asserted. Existing bounded state, approved-host exclusion, Candidate/Shadow and cooldown. Eight authored xUnit tests, not executed.
