# Named WPF operation profile — diagnostic-only candidate

Evidence from two VPN captures showed dispatcher scheduling delays up to 27 seconds and 25.8 seconds, with oldest UI queue waits reaching 73 and 139 seconds respectively. Coalescing anomaly refresh callbacks alone did not clear the stall.

## Opt-in reproduction

Before launching CARTHAGO on Windows, set both environment variables in the launch terminal:

```powershell
$env:CARTHAGO_UI_DIAG_PATH = Join-Path $env:TEMP 'carthago-ui-pipeline-next.csv'
$env:CARTHAGO_UI_PROFILE_PATH = Join-Path $env:TEMP 'carthago-ui-operations.csv'
dotnet run --project .\Carthago\Carthago.csproj -c Release
```

After 2–3 minutes of active capture:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\summarize-ui-operations.ps1
```

Both output files are append-only and contain aggregate counters/timings, not network payloads or source/destination IPs. Choose new output names for separate experiments. Instrumentation is disabled unless the corresponding environment variable is set at application startup.

## Profiled synchronous paths

TrafficTick, TrafficChart, ProtocolChart, TalkerChart, SeverityChart, KpiUpdate, TrafficGridBatch, DashboardAnomalies, DashboardLayout, MonitoringHeader, MonitoringHealth, MapOverlaySchedule.

These timings isolate synchronous source operations and do not automatically include deferred WPF layout/render passes, asynchronous WebView2 drawing, or every third-party UI callback. Use them together with queue/dispatcher timing before deciding the next fix. Detection rules, alert delivery, and capture settings are unchanged.
