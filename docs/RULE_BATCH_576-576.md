# R576 — Redis CONFIG SET request followed by outbound FTP upload command

SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED.

Public IPv4 client issues a parser-confirmed RESP2 CONFIG SET request to an RFC1918 server; the same server subsequently issues parsed FTP STOR/APPE command to that exact client within 120 seconds. Unlike R572/R573, no Redis reply is required; this observes attempted configuration followed by attempted FTP transfer, not either outcome. Bounded per-pair state, Candidate/Shadow, approved-host exclusion and cooldown. Eight xUnit scenarios authored, not executed. This commit also corrects FTP CRLF fixture literals in R572–R575 tests.
