# WPF UI Baseline Refresh Coalescing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent per-record analytics baseline and incident notifications from accumulating full-dashboard dispatcher callbacks and starving bounded UI traffic batches.

**Architecture:** Keep analytics publication, capture, detection, alert delivery, the 5,000-record UI channel, and drop accounting unchanged. Group dashboard `BaselineStatusChanged`, `IncidentCreated`/`IncidentUpdated`, and `AnomalyObserved` signals behind one versioned, flag-accumulating refresh coordinator. Each burst reloads only the changed bounded snapshots and performs one full layout/header pass, with at most one pending callback plus one follow-up for updates arriving during refresh.

**Tech Stack:** .NET 8, C#, WPF dispatcher, xUnit.

**Spec:** User-provided CARTHAGO WPF delivery-stall requirements.

## Global Constraints

- Work directly on `feature/carthago-reliability-hardening`; do not create a branch, fork, or worktree.
- Preserve detection rules, rule registration, alert delivery, capture settings, packet parsing, and detection behavior.
- Preserve UI queue capacity 5,000 and existing queue-drop accounting semantics.
- Preserve bounded newest-first traffic history and session export/privacy behavior.
- Do not claim runtime verification without comparable Windows VPN evidence; otherwise report **NOT RELEASE READY**.
- Do not commit or push unless all publication gates pass and effective author/committer identity remains the configured owner identity.

## Review Focus

- Bursts of baseline and incident updates before dispatcher execution must each create one pending refresh; baseline refresh retains the newest status.
- An update arriving during a refresh must schedule exactly one follow-up so the newest status is not lost.
- A closed dashboard callback gate must prevent queued refresh work from touching disposed WPF controls.
- UI drain cancellation/fault behavior, queue counters, bounded history, and newest-first ordering must remain unchanged.
- Detection and sink/analytics alert paths must remain unchanged by the dashboard-only scheduling correction.

---

### Task 1: Grouped dashboard analytics refresh coalescer

**Files:**
- Create: `Carthago/Services/DashboardAnalyticsRefreshCoalescer.cs`
- Create: `Carthago.Tests/DashboardAnalyticsRefreshCoalescerTests.cs`

**Interfaces:**
- Consumes: existing `UiRefreshCoalescer.Request()`, `.Version`, and `.Complete(long)` scheduling contract.
- Produces: flags enum `DashboardAnalyticsRefreshKind` and `DashboardAnalyticsRefreshCoalescer` with `Request(kind)`, `TakePending()`, `Version`, and `Complete(long)`.

- [x] **Step 1: Write the failing tests**

  Add `RequestsFromAllAnalyticsSourcesScheduleOnceAndCombineWork`; assert incident, anomaly, and baseline requests produce one scheduled callback, `Version == 3`, and `TakePending() == All`. Add `UpdateDuringRefreshSchedulesOneFollowupWithPendingWork`; assert a baseline request arriving after `TakePending()` causes one follow-up and remains pending.

- [x] **Step 2: Run the focused tests and verify RED**

  Run: `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter FullyQualifiedName~DashboardAnalyticsRefreshCoalescerTests --no-restore`

  Expected: FAIL to compile because `DashboardAnalyticsRefreshCoalescer` does not exist.

- [x] **Step 3: Implement the minimal thread-safe coalescer**

  Accumulate validated refresh flags with `Interlocked.Or`, atomically consume them with `Interlocked.Exchange`, and delegate scheduling/version completion to one private `UiRefreshCoalescer`.

- [x] **Step 4: Run the focused tests and verify GREEN**

  Run the Step 2 command.

  Expected: both tests PASS with zero failures.

### Task 2: Coalesce related analytics-driven dashboard work

**Files:**
- Modify: `Carthago/Views/MainWindow.Dashboard.cs:40-157`
- Test: `Carthago.Tests/LatestUiRefreshCoalescerTests.cs`

**Interfaces:**
- Consumes: `DashboardAnalyticsRefreshCoalescer` from Task 1 and the existing `DashboardCallbackGate`.
- Produces: the three analytics event handlers requesting grouped work and one `PostDashboardAnalyticsRefresh()` callback that reloads changed snapshots and performs one layout/header pass at `DispatcherPriority.Background`.

- [x] **Step 1: Integrate one grouped coalescer at all three analytics event boundaries**

  Have incident, anomaly, and baseline handlers request their respective flag. The dispatcher callback atomically takes pending flags, refreshes only those bounded snapshots, performs one `RefreshDashboardLayoutFromPreferences()` and `UpdateMonitoringHeader()`, then uses `Complete(version)` in `finally` for one follow-up when needed.

- [x] **Step 3: Run focused UI pipeline regressions**

  Run: `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --no-restore --filter "FullyQualifiedName~DashboardAnalyticsRefreshCoalescerTests|FullyQualifiedName~UiRefreshCoalescerTests|FullyQualifiedName~DashboardCallbackGateTests|FullyQualifiedName~CaptureUiDrainTests|FullyQualifiedName~CaptureSessionDeliveryTests|FullyQualifiedName~CaptureSessionCoordinatorTests|FullyQualifiedName~BoundedTrafficRowsTests|FullyQualifiedName~CaptureFlowHealthTests|FullyQualifiedName~PerformanceMetricTests|FullyQualifiedName~AnalyticsPipelineTests|FullyQualifiedName~SinkManagerTests"`

  Expected: all selected tests PASS; existing capture/detection/sink tests remain green.

- [x] **Step 4: Inspect the focused diff**

  Confirm no change to `TrafficCaptureService`, `CaptureUiDrain`, rules, sinks, queue constants, counters, or capture configuration.

### Task 3: Validation evidence and release assessment

**Files:**
- Create: `docs/design/CARTHAGO_UI_BASELINE_REFRESH_COALESCING_20261111.md`
- Modify only if needed for exact commands: `scripts/watch-ui-pipeline.ps1`, `scripts/summarize-ui-operations.ps1`

**Interfaces:**
- Consumes: pre-fix CSV evidence in `%TEMP%/carthago-ui-pipeline-next.csv` and `%TEMP%/carthago-ui-operations.csv`; corrected build and the same Windows VPN workload.
- Produces: root-cause evidence, exact code/test results, before/after table, remaining risks, and release-readiness decision.

- [x] **Step 1: Run full local verification**

  Confirm Carthago is closed, then run: `powershell -NoProfile -ExecutionPolicy Bypass -File .\verify-local.ps1`

  Expected: all verifier stages PASS; otherwise record each failure and keep the candidate not release ready.

- [x] **Step 2: Run comparable Windows VPN validation when safely available**

  Use fresh diagnostic/profile paths, the same VPN workload/capture source/UI settings, and a 2–5 minute duration. Record captured/parsed/delivered/drops, drops per 1,000, maximum depth, dispatcher waits, oldest age, drain batches, CPU, memory, and responsiveness. Do not terminate an application with possible unsaved session data.

- [x] **Step 3: Document evidence and readiness**

  Record the confirmed per-record baseline callback chain and the observed failing segment. If corrected runtime evidence is unavailable or misses any acceptance criterion, state **NOT RELEASE READY** and include exact remaining PowerShell commands.

- [x] **Step 4: Publication gates**

  Inspect the diff/status, fetch and compare remote HEAD, reconfirm branch plus effective author/committer identities, and preserve concurrent changes. Commit and push without AI attribution only if every acceptance and publication gate passes; never force-push.

  Result: publication stopped. The final VPN run retained recurring multi-second dispatcher waits, the controlled baseline metadata is incomplete, and `verify-local.ps1` has four failing mutual-TLS relay tests. No commit or push was created.
