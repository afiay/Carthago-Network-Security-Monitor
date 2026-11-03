# Carthago session files and Excel exports

**SOURCE CANDIDATE — UNVERIFIED. TESTS AUTHORED — 0 EXECUTED.**

## Commands

| Command | Shortcut | Result |
| --- | --- | --- |
| File → Open Session | Ctrl+O | Opens `.csa` in an offline, read-only viewer. |
| File → Save Session | Ctrl+S | Saves the available current analysis; subsequent saves reuse the selected path. |
| File → Save Session As | Ctrl+Shift+S | Selects a new `.csa` path. |
| File → Export to Excel | Menu | Writes `.xlsx` with separate category worksheets plus a `DataQuality` completeness sheet. |

The session viewer can also export the opened archive to `.xlsx` without restoring
it into active capture. Opening a file does not create detection evidence, restart
capture, import journal entries or change alert policy.

File → Open also selects that validated `.csa` archive as the current manual Save
destination. Subsequent manual saves merge distinct historical category records
with the currently available analysis; duplicate stable event/record IDs are
not appended repeatedly, and more recently updated incidents take precedence.
File → Save As carries the active session's previous records to the chosen new
file. No automatic or timer-triggered saving is enabled.

## Native format

`.csa` means **Carthago Session Archive**. Format version 1 is a compressed ZIP
container comprising `manifest.json` and JSON arrays under `data/` for each
category. The manifest stores a schema version, UTC creation time, data-row
counts, limitations, and SHA-256 integrity digests of the uncompressed category
payloads. Open validates declared entries, sizes, hashes and row counts and
rejects unsupported versions. Save writes to a temporary file in the destination
directory before replacing the destination.

SHA-256 here detects accidental or unsynchronized payload changes. Because the
manifest is not digitally signed, a CSA file is **not** itself a tamper-proof
forensic chain-of-custody artifact.

The `.csa` extension is application-specific; other applications may independently
use the same three-letter extension. This format is **not** a `.pcap` file.

## Excel category sheets

`Overview`, `Traffic`, `Alerts`, `Incidents`, `Anomalies`, `Hosts`,
`Baselines`, `Evidence`, `Timeline`, `Rules`, `Enrichment`, plus an Excel-only
`DataQuality` sheet that reports field population, null/absent values, explicit
unknown sentinels, redactions and usable coverage.

Each available JSON field becomes a column. Nested fields and arrays are
retained as JSON text within cells. JSON numbers and booleans are written as
native Excel values; strings remain literal text cells and are never formula
cells. Blank cells preserve source null/empty/absent values rather than inventing
data. `Unknown`/`0` producer sentinels and `[REDACTED]` are reported separately
in `DataQuality` so missing, unavailable and intentionally removed data are not
silently conflated. Categories exceeding Excel's 1,048,575 data rows per worksheet
receive consecutively numbered sheets. Excel's 32,767-character cell limit
requires truncation of longer individual values; this does not alter the `.csa`
archive source record. A new workbook is assembled in a temporary file before
being moved to the destination path.

## Coverage contract — important

Current session export is a **snapshot of available analyzed data**, not a
complete historical record of every packet or every rule. Specifically:

- Traffic records are bounded by the current UI's 200-row retention window.
- Alerts are bounded by the current UI's 500-row window; full detection journal
  history is not automatically included.
- Incidents and anomalies are sampled from up to 1,000 analytics-cache entries
  each, without claiming complete historical LiteDB coverage.
- Hosts reflect last-seen data retained in the current UI.
- Baselines contain aggregate current status, not every persisted per-host
  baseline snapshot.
- Rules contains the full registered detection catalog with descriptor,
  intelligence and precision-profile metadata. `ObservedEvents` and
  `MostRecentUtc` still refer only to the currently retained recent-alert window
  and are not an operational certification claim.
- Evidence and timelines originate from these retained alert/incident records.
- Save is a non-atomic view across active processing queues: in-flight messages
  may not yet have reached the relevant UI or analytics cache.
- Manually repeated saves retain previous **saved** rows, but cannot recover
  records that were evicted from the UI **between** saves. The current format is
  not a lossless background packet recorder.

The manifest and Overview sheet disclose these limits. Captured-packet and
dropped-queue counters are included as separate metadata; they must not be
interpreted as equivalent to archived traffic rows.

Known sensitive property names (including credentials, tokens, authorization,
cookies and request headers) and evidence explicitly marked `IsSensitive`
are redacted. Other free-text fields may still contain private information.
The user must review exported files before sharing and protect local archives.

## Future coverage expansion

Lossless full-session packet history requires an explicitly designed, bounded,
backpressure-aware recording path (and a security decision about raw packet
payloads), plus integration and load verification. The new archive does not
silently change the capture producer or pretend that evicted UI rows can be
reconstructed. Any such producer change must use the existing shared-contract
review process. Ordinary scheduled development must not execute builds/tests;
the first verification run requires fresh owner authorization.
