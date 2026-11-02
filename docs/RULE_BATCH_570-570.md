# R570 — Modbus write request then default HTTP admin attempt

SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.

A parsed Modbus/TCP write request from a private client to a private target in another /24 precedes a parser-confirmed known-default HTTP Basic admin request from that exact client to the same target within 120 seconds. Distinct temporal ordering from R563. Does not establish successful login, Modbus write outcome, compromise or device identity. Existing PacketHandler evidence; Candidate/Shadow; 90% confidence; 600-second cooldown; bounded state and approved-admin exclusion. Seven authored xUnit scenarios: positive, reverse/equal order, read/wrong peer, benign HTTP, expiry/duplicate, privacy and registry. Not executed.
