# Carthago Session Recording and Optional Auto-Save — Design

**SOURCE CANDIDATE — UNVERIFIED. No builds or tests authorized.**

## Intent

When the operator enables Auto-save during monitoring, retain analysis in the
same active `.csa` archive, including after File → Open. Existing records must
never be silently replaced by an unrelated recent-window snapshot.

## Boundaries and decisions

- Existing branch and `.csa` v1 ZIP schema remain authoritative.
- Store parsed/analyzed **metadata**, not raw packet payloads or secrets.
- Checkbox defaults OFF; File → Save or Open establishes the destination. If
  no destination is active, enabling prompts for a `.csa` path; Cancel leaves it OFF.
- Checkpoint every **60 seconds while capture is running**. Do not serialize or
  write on the UI/capture callback. Only one background save at a time.
- Merge previous and current category rows by stable IDs, preferring latest
  versions for equal IDs. Preserve older distinct records and warn about
  incomplete UI history, missing producer input, size/storage failures.
- Existing `.csa` archives reopen read-only for inspection but become the
  active save target after File → Open, without treating imported metadata as
  trusted telemetry. No rule evaluation or alerts are generated from import.
- On I/O or archive integrity failure, do not discard the existing file. Stop
  auto-save and surface one actionable error; live monitoring continues.
- Future full-session recording must tap the parsed record producer **before**
  the UI's bounded retention window. Use a bounded, nonblocking background
  spool with explicit dropped-record and storage-limit accounting. Even this
  cannot mathematically guarantee losslessness when input exceeds disk speed;
  completeness must be explicitly reported.

## Approaches

1. **Repeated recent-window snapshots only:** simple but silently misses older
   traffic at high packet rates; not acceptable as full-session recording.
2. **Synchronous write on every capture callback:** can increase packet loss
   and slow the machine; rejected.
3. **Background bounded spool + periodic `.csa` checkpoint:** recommended.
   Decouples disk I/O from capture and makes overload explicit, at the cost of
   bounded storage and a required import/checkpoint boundary.

## Delivery sequence

1. Introduce reversible opt-in auto-save, path tracking and non-destructive
   merge for `.csa` snapshots. Add source-only tests, no execution.
2. Add a bounded background producer recorder and surfaced completeness flags
   after reviewing capture callers, cancellation and shutdown behavior.
3. Feed recorder history into `.csa` and Excel without requiring the UI to
   materialize huge traffic lists; independently validate memory and disk cost
   during a future explicitly authorized testing session.

## Safety

Do not change rule thresholds, evidence trust, packet filtering, detection
journaling, holdouts, or UI chart cadence. Existing data survives failed saves.
No tests, restores, builds, runner jobs or live packet captures until fresh
owner authorization.
