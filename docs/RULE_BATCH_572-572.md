# R572: Redis Error before FTP STOR/APPE

SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED.

Exact public/private peer correlation of independently parsed Redis CONFIG SET Error reply and FTP upload command, ordered Redis then FTP within 120 seconds. No authenticated identity, transfer completion or durable change is claimed. Candidate/Shadow, approved admin exclusions, bounded state, cooldown. Eight authored xUnit cases: positive, reverse, equal time, expiry, duplicate IDs, FTP read, opposite Redis status, registration. No tests executed.
