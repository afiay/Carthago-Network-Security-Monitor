# Carthago Session Auto-Save Implementation Plan

> **For agentic workers:** Implement this plan inline, in the existing branch only. Author tests now; defer all test execution until fresh owner authorization.

**Goal:** Opt-in periodic saving into the active `.csa` file, preserving previously archived categories and exposing failures.

**Architecture:** Keep existing archive ZIP writer. Introduce stable-ID merge at the data layer, then an application-owned dispatcher timer that runs only during active monitoring and invokes an asynchronous, serialized save. The subsequent full-history recorder is a separate GA crossing the capture producer boundary.

**Tech Stack:** C# 12, .NET 8, WPF, System.Text.Json, existing `.csa` archive service and xUnit.

**Spec:** `docs/superpowers/specs/2026-11-02-session-recording-autosave-design.md`

## Global Constraints

- Sole branch: `feature/carthago-reliability-hardening`; preserve concurrent automations.
- No build, restore, tests, benchmark or live capture until the owner authorizes the exact session.
- Never import archive rows into trusted capture/event producer paths.
- Keep existing privacy redaction and archive integrity validation.

## Review Focus

1. Archive reopened after long monitoring: older distinct rows survive subsequent Save.
2. Repeated 60-second saves of the same current rows: no duplicate traffic/alert IDs.
3. Two versions of one incident: newest state wins without losing unrelated incidents.
4. Failed/corrupt destination: existing data survives and auto-save disables with notice.
5. Timer during heavy capture or an ongoing export: overlapping saves are skipped.

---

### Task 1 — Stable category merge

**Files:** Create `Carthago/Services/SessionFiles/CarthagoSessionSnapshotMerger.cs`; test `Carthago.Tests/CarthagoSessionMergeTests.cs`.

**Interface:** `public static CarthagoSessionSnapshot Merge(CarthagoSessionSnapshot previous, CarthagoSessionSnapshot current)`.

- [ ] Author xUnit cases for preserved earlier IDs, collision replacement and repeated snapshot idempotence.
- [ ] Execution deferred: xUnit must NOT run during scheduled/source-only work.
- [ ] Implement deterministic category keys and preserve the original creation timestamp and limitations.
- [ ] Source-inspect consumers and stage a cohesive change.

### Task 2 — Save/Open path and opt-in UI

**Files:** Modify `Carthago/Views/MainWindow.SessionFiles.cs`, `Carthago/Views/MainWindow.xaml`; test source via Task 1 and add UI contract test only if existing UI test support can reuse it.

**Interfaces:** `AutoSaveDuringMonitoring_Checked`, `AutoSaveDuringMonitoring_Unchecked` and a 60-second `DispatcherTimer` callback; existing `RunFileOperationAsync` is the save serialization guard.

- [ ] Set File → Open target as active `.csa` path after successful integrity validation.
- [ ] Merge existing destination contents before overwriting, rather than replacing.
- [ ] Add unchecked-by-default checkable menu item; prompt for a target only on enable without one.
- [ ] Skip ticks if not monitoring or a save is in progress; never queue overlapping saves.
- [ ] On error disable and show one notice; avoid timer-triggered success dialogs.
- [ ] Source-inspect shortcut and designer bindings; no build or test execution.

### Task 3 — Full-session history integration (later GA)

**Files:** New bounded writer under `Carthago/Services/SessionFiles`, restricted additive `TrafficCaptureService` producer hookup, streaming archive and Excel readers, source-only tests.

- [ ] Review packet/ETW producer lifecycles and all consumers before contract edits.
- [ ] Design opt-in bounded queue, disk quota, shutdown flush and drop/failure counters.
- [ ] Extend archive reader/writer with streaming records, do not materialize unbounded lists.
- [ ] Keep `.csa` version compatibility, mark coverage gaps and test source paths.
- [ ] Require owner-authorized test session for performance/integration evidence.

## Publication

One non-forced expected-HEAD-protected update to the existing branch; stop on overlap. Report exact commit and `SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED`.
