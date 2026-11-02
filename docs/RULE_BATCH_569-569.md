# R569 — FTP upload command followed by default HTTP admin attempt

SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED.

Distinct ordering from R565: a parser-classified FTP STOR/APPE upload *command* from a private host to a public IPv4 peer precedes a parser-classified known-default Basic HTTP admin request from that peer to the same private host within 120 seconds. This is not proof of a completed upload, login, or compromise. Existing PacketHandler HTTP/FTP evidence, bounded per-pair state, 600s cooldown, approved-admin exclusions, Candidate/Shadow maturity. Eight authored xUnit tests cover producer, positive, reverse/equal time, benign HTTP, FTP read/wrong peer, stale/duplicate IDs, privacy and registry. Tests not executed.
