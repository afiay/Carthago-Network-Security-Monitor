# Dashboard analytics refresh cadence design

## Intent

Finish the WPF dispatcher hardening by preventing continuous analytics notifications from causing immediate full-dashboard layout follow-ups. Incident, anomaly, and baseline state must remain current without competing indefinitely with the bounded traffic UI drain.

## Goals

- Accumulate all analytics update kinds without losing the final update.
- Allow at most one production dashboard analytics refresh per two seconds after the previous refresh completes.
- Keep at most one timer/callback scheduled and one refresh executing.
- Perform one snapshot reload/layout/header pass for all accumulated kinds.
- Cancel pending work safely during window shutdown.
- Preserve capture, parsing, detection, alert delivery, durable journal/outbox, queue capacity, and drop accounting.

## Non-goals and anti-goals

- No rule, parser, capture, TLS-security, or queue-semantics changes.
- No dashboard redesign or broad incremental-view refactor.
- No larger queue, hidden degraded state, or lower acceptance threshold.
- Do not use a pure debounce that can postpone rendering forever under continuous traffic.

## Approaches considered

1. **Bounded one-shot trailing timer — selected.** A two-second production `DispatcherTimer` window starts for the first pending notification. All additional kinds accumulate. The timer drains one combined refresh, and updates arriving during rendering schedule one new full interval. This directly bounds layout frequency while guaranteeing a trailing refresh. The interval was increased from the initially tested 500 ms after runtime evidence showed that two layouts per second still competed with delivery.
2. **Incremental widget updates.** This could remove most full layouts, but the current layout method coordinates many dependent collections and selections. It is substantially broader and carries more UI-regression risk than the evidence requires.
3. **Dispatcher priority only.** Lowering refresh priority does not bound work creation and can make final analytics state starve indefinitely while capture remains busy.

## State and scheduling design

`DashboardAnalyticsRefreshCoalescer` becomes a lock-protected state machine with pending flags, scheduled/executing/canceled states, a `TimeProvider`, and a configurable minimum interval. The default constructor uses a two-second production interval and `TimeProvider.System`; an internal constructor accepts an interval and manual provider for deterministic boundary tests.

- `Request(kind)` ORs valid flags and returns `true` only when the caller must arm a timer.
- `GetDelayUntilNextRefresh()` reports the remaining interval.
- `TryBeginRefresh(out kind, out retryAfter)` refuses early or overlapping execution, atomically drains the pending kinds when due, and reports any remaining delay.
- `CompleteRefresh()` records the completion timestamp and returns `true` only if work accumulated during execution needs one trailing timer.
- `Cancel()` rejects future requests and clears pending/scheduled work without invalidating an already executing callback's `finally` path.

`MainWindow` owns a `DispatcherPriority.Background` one-shot timer. A request posts only a small timer-arm callback. The tick stops the timer, asks the coordinator to begin, reloads the requested bounded snapshots, performs one layout/header pass, then arms one full trailing interval only when required. A `None` batch never causes layout. Cleanup closes the callback gate, stops and detaches the timer, cancels the coordinator, then unsubscribes analytics events.

The timer remains at `Background`, matching the UI drain, so neither path is permanently demoted. The two-second cadence caps analytics-driven layouts at one every two seconds. Cached dashboard content appears immediately on navigation and a bounded asynchronous refresh follows; this explicitly favors lossless capture delivery over sub-second dashboard presentation.

Runtime profiling also showed that the hidden Live Traffic `DataGrid` was processing a collection Reset for every delivered batch. `BoundedTrafficRows` therefore continues retaining the same newest-first 200 records while suppressing collection invalidation when Live Traffic is hidden. Opening Live Traffic emits one Reset. Similarly, analytics snapshots continue updating while Overview is hidden, but full dashboard presentation rebuilds occur only while it is visible; navigation requests a bounded asynchronous refresh. Global preference notifications retain their lightweight state/source/header updates while a shared presentation gate skips hidden layout. These are WPF presentation changes only and do not alter capture batching, queue capacity, record order, drop accounting, detection, or alert delivery.

## Tests

Deterministic tests with a manual `TimeProvider` cover the generic 500 ms boundary, the two-second production default, continuous bursts, combined kinds, a final trailing update, non-overlap, concurrent requests, cancellation, and invalid flags. Bounded-row tests prove hidden updates preserve newest-first capacity without notifications and one explicit Reset exposes the current rows. A presentation-gate regression proves a collapsed Overview skips preference-driven layout while a visible Overview rebuilds it. Existing focused UI-drain, shutdown, analytics, and sink tests remain in the verification filter. Runtime telemetry remains the authority for actual WPF dispatcher/render behavior.

## Validation and release gates

Run focused tests, `verify-local.ps1`, and a minimum five-minute run on the same Npcap Wi-Fi source with Norton WireGuard active. Target approximately 78 captured records/second, record the complete requested telemetry, and retain the earlier slower candidate as history rather than a comparable baseline. Redis TLS failures are diagnosed separately and security validation is never weakened. No commit or push occurs unless every acceptance, remote-head, and owner-identity gate passes.
