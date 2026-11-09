# Monitoring Health Navigation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Build and test execution are expressly deferred by the CARTHAGO UI stream; static review cannot be reported as runtime verification.

**Goal:** Deliver a first-class in-window Monitoring Health page using existing capture counters and links to the related traffic workspace.

**Architecture:** Add an isolated `MonitoringHealthPage` WPF user control with immutable presentation updates, navigated by a Sidebar event through MainWindow. Populate it from the existing `UpdateMonitoringHeader` status refresh, not a new packet-event subscription or timer. Preserve all existing commands and data contracts.

**Tech Stack:** C# WPF, XAML, `TrafficCaptureService.CaptureFlowSnapshot`, `CaptureSourceHealth`.

**Spec:** `docs/design/CARTHAGO_SOC_WORKSPACE_INTEGRATION.md`

## Global Constraints

- Stay on `feature/carthago-reliability-hardening`; publish by non-force fast-forward only after re-fetch.
- No fabricated sensors, coverage, traffic direction, location, process attribution, or evidence.
- No engine/rule behavior changes or new capture hot-path subscribers.
- No builds, tests, runner jobs, or WPF-render assertions without owner authorization.
- Preserve existing named XAML controls and sidebar event subscriptions.

## Review Focus

- Paused/error/offline status must not present stale captured counters as current activity.
- Source-specific counter labels must not imply UI queue drops are sensor/parser drops.
- Repeated navigation must not duplicate event subscriptions or create timers.
- Narrow WPF widths and high DPI may clip new cards (requires owner-authorized render review).
- Closing capture while viewing health must not access disposed data (requires owner-authorized runtime verification).

---

### Task 1: Present capture and flow snapshots

**Files:** Create `Carthago/Views/MonitoringHealthPage.xaml`, `Carthago/Views/MonitoringHealthPage.xaml.cs`.

**Interfaces:** `MonitoringHealthPage.UpdateSnapshot(string status, string sourceName, CaptureSourceHealth source, TrafficCaptureService.CaptureFlowSnapshot flow, string? error, DateTime? lastAnalysisUtc)`; `RawTrafficRequested` event.

- [ ] Create source-accurate layout with state, selected source, observed/forwarded/source error counters, UI capture/delivery/drop counters, last recorded analysis, and diagnostic text.
- [ ] Keep values unavailable when no active capture and show meaningful empty/error text.
- [ ] Provide accessible `Open Live Traffic` button emitting event; no new service subscriptions.
- [ ] Inspect XAML/names/resources statically; record verification deferred.

### Task 2: Route health navigation

**Files:** Modify `Carthago/Views/Sidebar.xaml`, `Sidebar.xaml.cs`, `MainWindow.xaml`, `MainWindow.Navigation.cs`, `MainWindow.xaml.cs`, `MainWindow.Dashboard.cs`.

**Interfaces:** `Sidebar.MonitoringHealthRequested`, `MainWindow.Nav_MonitoringHealth_Click`, `MainWindow.OpenMonitoringHealthWorkspace()`.

- [ ] Add a first-class Monitoring Health button near Overview in the operations sidebar.
- [ ] Add a dedicated `MonitoringHealthView` content region and include it in `ShowView` collapse inventory.
- [ ] Wire the sidebar event idempotently and show the health page without external windows.
- [ ] Refresh the visible page through the existing `UpdateMonitoringHeader` timer and its real snapshots.
- [ ] Add a contextual `Health details` shortcut on Overview.
- [ ] Inspect changed files for accidental rule/capture changes; record runtime checks as deferred.

### Task 3: Publish and record truthful status

**Files:** Modify `docs/design/CARTHAGO_SOC_WORKSPACE_INTEGRATION.md` and optional UI implementation ledger.

- [ ] Review git diff and all changed paths; check for whitespace errors and no unrelated edits.
- [ ] Commit on the requested feature branch.
- [ ] Re-fetch, integrate independent remote changes safely, and push without force.
- [ ] Report source-candidate/unverified and list remaining nine capability milestones as pending.
