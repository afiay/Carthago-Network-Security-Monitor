# Opt-in CARTHAGO UI pipeline diagnostics (Windows PowerShell 5.1)

To diagnose `UI_DELIVERY_STALLED` without changing rules, alert delivery or capture settings, close CARTHAGO and open a PowerShell terminal in the repository root:

```powershell
$env:CARTHAGO_UI_DIAG_PATH = Join-Path $env:TEMP 'carthago-ui-diag.csv'
dotnet run --project .\Carthago\Carthago.csproj -c Release
```

In a **second** terminal:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\watch-ui-pipeline.ps1 -Samples 60 -IntervalSeconds 2
```

Collect during steady VPN traffic, including a visible degraded-state interval. CSV is append-only and stores **aggregate numbers only**, no packet contents, addresses or rule evidence. Diagnostics are disabled by default and require the environment variable at app startup. Delete the file manually when no longer needed, or choose a new output path for each run. The old diagnostic process cannot instrument an already-running CARTHAGO instance.

Fields: queue depth at sample time; total captured/delivered/dropped records and completed batches; oldest record's time in queue at the start of the latest batch; last/max dispatcher scheduling delay; total per-record subscriber execution time in the most recent batch; and canceled-session records intentionally skipped by the UI drain.

Measurements describe the UI delivery path. They do not measure rule recall, network packet loss, or alert delivery. Do not treat `captured - delivered` as an exact current queue depth; capture and UI counters can include different filter/session phases.

**Release gate:** source candidate until Windows build/tests and a captured degraded interval are inspected. The capture channel capacity, drop policy, rule evaluation, alert dispatch, and selected device remain unchanged.
