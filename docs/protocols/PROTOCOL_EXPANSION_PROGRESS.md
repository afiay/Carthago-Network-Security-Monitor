# Carthago protocol intelligence — dedicated progress ledger

**Branch:** `feature/carthago-reliability-hardening`  
**Status:** SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; **0 EXECUTED**  
**Original inventory:** P0001–P0500, immutable research row identifiers from the owner's 2026-10-30 CSV (ChatGPT Library `/Carthago Protocol Expansion`). They are not detection-rule IDs.

## Completed source-only checkpoints

| GA | Base source SHA | Research IDs | Outcomes | Authored xUnit methods / invocations | Executed | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| [GA 0](PROTOCOL_GA_0_RECONCILIATION.md) | `7aa356429b674fab1975127f40f4fea6b312450b` | Inventory P0001–P0500, source reconciliation only | 436 provisional unverified research candidates, 23 reuse/extend, 41 variants/rejects; true distinct eligible count not yet established | 0 / 0 | 0 | Historical audit vs live HEAD, three detection-only commits; no changed packet producers |
| [GA P0001–P0010](PROTOCOL_GA_P0001-P0010.md) | `7aa356429b674fab1975127f40f4fea6b312450b` | P0001–P0010 | 2 IMPLEMENTED_ISOLATED, 2 PARTIAL, 4 DEFERRED, 2 REJECTED; 0 live integrated | 17 / 20 | 0 | HTTP/2 and DTLS bounded source inspectors and isolated xUnit scenarios |

**Last completed research GA:** P0001–P0010 (source-only, unverified). **Next exact ten IDs:** **P0011–P0020**. Do not skip blocked candidates, invent new P IDs, rewrite historical outcomes, or treat authored tests as executed. Recover live HEAD and compare concurrent detection/UI stream paths before publication.

## Unresolved independent obligations

- Owner approval and cross-stream review for any shared capture/telemetry/record schema integration; source-only isolated work may continue meanwhile.
- First actual build/xUnit/Windows replay awaits explicit owner command **“now it’s test time.”**
- Live sensor provenance, TCP stream boundaries, DTLS 1.3 encrypted records, endpoint/proxy logs and NetScaler asset/config/IOC correlation are not established by these isolated inspectors.
- Continue source-only with P0011–P0020; preserve detection and UI ledgers, frozen holdouts, journal-first raw DetectionEvents, privacy, cooldowns, thresholds and rule IDs.
