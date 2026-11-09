# Network Investigation Explorer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Owner-authorized builds and test execution remain deferred; do not report static checks as runtime verification.

**Goal:** Inspect a source/destination host across the bounded local traffic and detection buffers in one in-window workspace, with context links from the source tables.

**Architecture:** A view-only `NetworkInvestigationPage` takes snapshots of the existing `_traffic` and `_alerts` UI collections on navigation. It filters exact IP address matches in source/destination fields, or non-IP search text in recorded metadata, with no packet capture subscriptions or invented correlation. The sidebar and selected-record context menus route into the same page.

**Tech Stack:** .NET 8 WPF, existing `TrafficRecord`, `DetectionEvent`, `ObservableCollection` buffers.

**Spec:** `docs/design/CARTHAGO_SOC_WORKSPACE_INTEGRATION.md`

## Global Constraints

- Only the approved `feature/carthago-reliability-hardening` branch, expected-head/non-force publication.
- `_traffic` contains at most 200 retained UI items and `_alerts` at most 500. Show scope explicitly.
- Do not claim IP coincidence establishes incident correlation or complete source/destination flows.
- No build, test, replay or live capture without separate owner authorization.

## Review Focus

- Selected traffic or detection row missing its IP -> no fabricated host pivot.
- An IP in either traffic direction matches; unrelated addresses do not match partial strings.
- Empty/paused buffers -> visible empty state; never imply no network activity.
- Context actions must use selected record and not an unrelated earlier record.
- Repeated navigation must not duplicate event handlers or capture subscriptions.

---

### Task 1: Bounded, source-linked investigation page

**Files:** Create `Carthago/Views/NetworkInvestigationPage.xaml`, `NetworkInvestigationPage.xaml.cs`.

**Interfaces:** `UpdateSnapshot(IEnumerable<TrafficRecord> traffic, IEnumerable<DetectionEvent> detections, string? filter)`; `TrafficRequested`, `DetectionsRequested`, `AnalyticsRequested` events.

- [ ] Show source-accurate scope and privacy/attribution caveats.
- [ ] Provide one search field, selectable retained traffic and detections tables with real metadata and explicit match counts.
- [ ] Exact IP equality for source/destination; bounded text matching for non-IP terms.
- [ ] Provide buttons to existing Live Traffic, Raw Detections and Analytics views.
- [ ] Static XAML and reference checks only.

### Task 2: Connected navigation and source-table entry points

**Files:** Modify `Carthago/Views/Sidebar.xaml`, `Sidebar.xaml.cs`, `MainWindow.xaml`, `MainWindow.Navigation.cs`, `MainWindow.xaml.cs`; create `MainWindow.NetworkInvestigation.cs`.

**Interfaces:** `Nav_NetworkInvestigation_Click` and `OpenNetworkInvestigation(string? filter)`; selected-record context handlers.

- [ ] Add Network Explorer beside Live Traffic, with idempotent sidebar event wiring.
- [ ] Add a small global retained-evidence search in the application command row, routing to the same explorer.
- [ ] Open the view in the existing main content host, preserving other view behavior.
- [ ] Add selected source/destination pivot actions to Live Traffic and Raw Detections.
- [ ] Refresh snapshots on navigation rather than subscribing to the capture path.
- [ ] Inspect changed source and record unexecuted runtime checks.

### Task 3: Publish and report

- [ ] Update integration ledger with source-only SOC-02 details.
- [ ] Diff and XML well-formedness review, no build/test claims.
- [ ] Commit and publish by non-force expected-head atomic update.
