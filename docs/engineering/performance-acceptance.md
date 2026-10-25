# Carthago Windows Reliability and Performance Acceptance

## Scope

Unit tests validate contracts and calculation logic. This procedure measures the actual WPF,
ETW/Npcap, enrichment, detection, and dashboard process under sustained **authorized** lab traffic.
It must be repeated against the same capture source, traffic rate, rules, machine, and duration
before comparing releases.

## Preconditions

1. Complete the pending Git merge and pass `dotnet build DOTNET.sln --configuration Release`.
2. Run `dotnet test DOTNET.sln --configuration Release --no-build` with zero failures.
3. Copy production analytics data to a safe operator-managed location *before* crash/restart
   experiments; do not conduct intentional crashes against the only copy of security evidence.
4. Pick an authorized GNS3 or other controlled local network traffic source. Disable real
   external feeds for a deterministic replay, then separately validate the production setup.

## Baseline recovery exercise

1. Start monitoring and record at least one baseline observation and security incident.
2. Note the incident ID, its status, related evidence and the baseline's observation count.
3. Close normally, restart Carthago, and confirm the records and status are unchanged.
4. Repeat using an isolated, non-production test database with a simulated abrupt shutdown.
5. Confirm a damaged database is preserved under a distinct recovery filename and never
   silently deleted if the recovery rename fails.
6. Record any error message, missing record, changed identity, or duplicate baseline host ID.

## Capture-to-display exercise

1. Start an ETW capture with permissions required by the local security policy.
2. Confirm the dashboard moves from Starting to Waiting for traffic to Flowing with traffic.
3. Verify `Captured` and `Displayed` increase while the traffic table receives rows.
4. If UI records are dropped, confirm a degraded message names the count for this session.
5. Stop and start the session. Confirm no stale records from the previous session appear.
6. Repeat with Npcap if installed. Do not interpret an idle capture as a failed capture.

## Sustained load profile

1. In PowerShell, capture the Carthago PID with `Get-Process Carthago` and note the process ID.
2. Observe CPU time, working set and private bytes over a minimum 15-minute run:

   ```powershell
   Get-Process Carthago | Select-Object Id, CPU, WorkingSet64, PrivateMemorySize64
   ```

3. Keep a consistent traffic pattern and save before/after capture counters, including dropped
   UI records and parsing errors, for each separate test window.
4. For instrumentation, call `TrafficCaptureService.GetPerformanceCounterSnapshot()` at the
   beginning and end of a same-session interval, then pass both objects to
   `PerformanceMetricSummary.Between(before, after)`. The result provides events/sec, UI
   records/sec, queue-drop ratio, CPU core equivalents, allocation bytes and memory delta.
5. Repeat for an idle baseline, typical load and constrained UI/high traffic load. Report the
   load generator, event source, and any enrichment/network dependencies.

## Acceptance evidence

- Build warnings/errors, test successes/failures and test version/commit.
- Capture source, duration, received/displayed/dropped counters and diagnosed reason.
- Mean CPU core equivalents, managed allocation delta and working set before/after.
- Qualitative memory trend: stable, bounded growth, or unbounded growth.
- Detection replay confusion matrix, precision/recall/F1 and dataset version.
- Recovery test outcome: restored, preserved for recovery, or failed visibly.

An interval throughput number is not a capacity claim. Establish limits only after repeats and
tail-latency, CPU, memory, and loss budgets are agreed for target hardware.
