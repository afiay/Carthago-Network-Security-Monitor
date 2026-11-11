# WPF Dispatcher Final Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound production full-dashboard rendering to one refresh per two seconds, avoid hidden-view collection invalidation, and retain all incident, anomaly, baseline, and traffic-row updates.

**Architecture:** Replace immediate coalescer follow-ups with a thread-safe, time-aware state machine and a one-shot WPF `DispatcherTimer`. The timer drains combined pending flags on the UI thread and arms one delayed trailing refresh only when updates arrived during execution. Hidden Live Traffic updates mutate the same bounded backing collection without invalidating the collapsed grid; opening the view issues one Reset. Hidden Overview updates snapshots without rebuilding presentation, and navigation requests an asynchronous refresh.

**Tech Stack:** .NET 8, C#, WPF `DispatcherTimer`, `TimeProvider`, xUnit.

**Spec:** `docs/superpowers/specs/2026-11-11-dashboard-analytics-refresh-cadence-design.md`

## Global Constraints

- Work only on `feature/carthago-reliability-hardening`; do not create a branch, fork, or worktree.
- Preserve all current uncommitted changes and defer commits until every release/publication gate passes.
- Do not modify capture, parsing, rules, alerts, detection journal, durable outbox, queue capacity, or drop semantics.
- Do not weaken TLS/certificate verification or its tests.
- The production full analytics refresh interval is exactly two seconds and uses `DispatcherPriority.Background`; the coordinator remains configurable for deterministic boundary tests.
- Runtime acceptance requires a minimum five-minute comparable VPN workload near the 78-record/second baseline.

## Review Focus

- A request at the configured boundary must execute once, neither early nor twice; the production-default test owns the two-second setting.
- Updates racing with `TryBeginRefresh` or `CompleteRefresh` must remain pending for one trailing interval.
- Concurrent incident/anomaly/baseline notifications must produce one schedule decision and retain all kinds.
- Cancellation during scheduled or executing work must prevent new UI work without breaking completion cleanup.
- An early/spurious dispatcher tick must re-arm only the remaining delay and never perform layout.

---

### Task 1: Time-aware dashboard analytics refresh coordinator

**Files:**
- Modify: `Carthago/Services/DashboardAnalyticsRefreshCoalescer.cs`
- Modify: `Carthago.Tests/DashboardAnalyticsRefreshCoalescerTests.cs`

**Interfaces:**
- Consumes: `DashboardAnalyticsRefreshKind`, `TimeProvider`, and a configurable minimum interval.
- Produces: `Request(kind)`, `GetDelayUntilNextRefresh()`, `TryBeginRefresh(out kind, out retryAfter)`, `CompleteRefresh()`, and `Cancel()`.

- [ ] **Step 1: Write failing cadence and burst tests**

  Add `ContinuousBurstArmsOneRefreshAndCombinesAllKinds` and `RefreshCannotBeginBeforeMinimumInterval`. Use a manual `TimeProvider`; assert one schedule decision, `All` pending kinds, failure at 499 ms with 1 ms retry, and success at 500 ms.

- [ ] **Step 2: Run the new tests and verify RED**

  Run: `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --no-restore --filter FullyQualifiedName~DashboardAnalyticsRefreshCoalescerTests`

  Expected: compilation fails because the new time-aware constructor/methods do not exist.

- [ ] **Step 3: Implement the minimal lock-protected cadence state machine**

  Add the internal signature `DashboardAnalyticsRefreshCoalescer(TimeSpan minimumInterval, TimeProvider timeProvider)` and the interfaces above. Validate a positive interval and non-null provider; derive delays with `TimeProvider.GetElapsedTime`.

- [ ] **Step 4: Run the tests and verify GREEN**

  Run the Step 2 command; expected result is zero failures.

- [ ] **Step 5: Add trailing, overlap, concurrency, cancellation, and invalid-input tests**

  Add `UpdateDuringRefreshRunsOnceAfterFullTrailingInterval`, `OverlappingRefreshCannotBegin`, `ConcurrentNotificationsScheduleOnceWithoutLosingKinds`, and `CancelPreventsScheduledAndFutureWork`; retain invalid-kind cases. Each test must fail against a deliberate mutation of its owned branch/state transition.

- [ ] **Step 6: Run the complete coordinator test class**

  Run the Step 2 command; expected result is zero failures and no warnings attributable to the new code.

### Task 2: One-shot WPF trailing refresh timer

**Files:**
- Modify: `Carthago/Views/MainWindow.Dashboard.cs:40-160,1744-1761`
- Create: `Carthago/Services/DashboardPresentationGate.cs`
- Test: `Carthago.Tests/DashboardAnalyticsRefreshCoalescerTests.cs`
- Test: `Carthago.Tests/DashboardPresentationGateTests.cs`
- Test: `Carthago.Tests/DashboardCallbackGateTests.cs`

**Interfaces:**
- Consumes: Task 1 coordinator scheduling/delay interface and existing `DashboardCallbackGate`.
- Produces: one `DispatcherPriority.Background` timer arm per burst and one delayed trailing refresh when required.

- [ ] **Step 1: Integrate a one-shot analytics refresh timer**

  Add `_dashboardAnalyticsRefreshTimer`, attach its tick during dashboard initialization, and replace immediate `PostDashboardAnalyticsRefresh()` work with timer arming. On tick, honor `retryAfter`, skip `None`, apply one grouped refresh, and call `CompleteRefresh()` in `finally`.

- [ ] **Step 2: Add shutdown behavior**

  In `CleanupDashboardExperience`, stop/detach the timer and call `Cancel()` after closing the callback gate. Ignore event requests after gate closure.

- [ ] **Step 3: Run focused UI scheduling and delivery regressions**

  Run: `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --no-restore --filter "FullyQualifiedName~DashboardAnalyticsRefreshCoalescerTests|FullyQualifiedName~DashboardPresentationGateTests|FullyQualifiedName~UiRefreshCoalescerTests|FullyQualifiedName~DashboardCallbackGateTests|FullyQualifiedName~CaptureUiDrainTests|FullyQualifiedName~CaptureSessionDeliveryTests|FullyQualifiedName~CaptureSessionCoordinatorTests|FullyQualifiedName~BoundedTrafficRowsTests|FullyQualifiedName~CaptureFlowHealthTests|FullyQualifiedName~PerformanceMetricTests|FullyQualifiedName~AnalyticsPipelineTests|FullyQualifiedName~SinkManagerTests"`

  Expected: all selected tests pass; no capture service, parser, rule, alert-delivery, journal/outbox, queue-capacity, or drop-accounting changes.

- [ ] **Step 4: Suppress hidden-view presentation invalidation**

  Retain newest-first bounded traffic rows without collection notifications while Live Traffic is hidden, issue one Reset on navigation, suppress analytics and preference-driven Overview rebuilds while hidden, and route detection presentation updates through the bounded coordinator. Add failing bounded-row and hidden-preference presentation tests first.

- [ ] **Step 5: Inspect the focused diff and run `git diff --check`**

  Confirm no change outside the coordinator, dashboard scheduling, tests, plans, and validation documentation.

### Task 3: Redis mutual-TLS diagnosis

**Files:**
- Inspect only: `Carthago.Tests/RedisAuditMutualTlsRelayReceiverTests.cs` and relevant trusted-audit TLS helpers.
- Modify only when a code regression is proven and a separate failing test exists; never relax certificate validation.

**Interfaces:**
- Consumes: focused xUnit results, TRX error details, generated certificate properties, Windows trust/time configuration.
- Produces: a reproducible cause classification and safe remediation/remaining-risk record.

- [ ] **Step 1: Re-run the focused class once and capture exact failures**

  Run: `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --no-build --no-restore --filter FullyQualifiedName~RedisAuditMutualTlsRelayReceiverTests --logger "console;verbosity=detailed"`

- [ ] **Step 2: Trace certificate creation and both handshake validation callbacks**

  Record validity, EKU, SAN/name, thumbprint pinning, chain policy, private-key persistence, system time, and certificate-store assumptions. Compare passing and failing cases.

- [ ] **Step 3: Classify and document the cause**

  State whether the failure is deterministic environment/setup, certificate-generation behavior, or production regression. Do not change UI code based on this result.

### Task 4: Full verification, comparable runtime, and publication decision

**Files:**
- Modify: `docs/design/CARTHAGO_UI_BASELINE_REFRESH_COALESCING_20261111.md`
- Modify: `.superpowers/sdd/2026-11-11-wpf-ui-baseline-refresh-coalescing/progress.md` (ignored local execution ledger)

**Interfaces:**
- Consumes: focused tests, Task 3 TLS finding, `verify-local.ps1`, pipeline/profile CSVs, VPN/source state.
- Produces: complete evidence table, risks, release decision, and commit only if every gate passes.

- [ ] **Step 1: Confirm CARTHAGO is closed and run full local verification**

  Run: `powershell -NoProfile -ExecutionPolicy Bypass -File .\verify-local.ps1`

- [ ] **Step 2: Run a minimum five-minute comparable VPN workload**

  Use Npcap source `\Device\NPF_{020CA261-AEA6-48FC-B65F-CCE86BCC84E9}`, confirm `Norton VPN WireGuard` is `Up`, target approximately 78 records/second, and record every metric required by the request plus navigation and detection/alert integrity.

- [ ] **Step 3: Update the validation history and readiness decision**

  Preserve both earlier runs, add the new cadence result and workload-rate caveat, include the TLS diagnosis, and state `NOT RELEASE READY` if any criterion remains unresolved.

- [ ] **Step 4: Apply publication gates**

  Inspect every changed file, branch, effective owner identity, authorship-marker absence, and freshly fetched remote HEAD. Never disable Git TLS verification. Commit/push without force only if all gates pass; otherwise leave the candidate uncommitted and report the exact blocker.
