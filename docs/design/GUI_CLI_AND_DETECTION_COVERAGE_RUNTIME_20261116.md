# Interactive dashboard CLI and observed detection coverage (2026-11-16)

## GUI CLI scope

The Overview **Carthago CLI** panel is a functional, **in-process, read-only command console**, not a Windows shell or an unrestricted process launcher.

- Run a supported command with Enter or **Run**. See **help**, **clear**, **Cancel** and **--json**.
- The GUI executes the existing `Carthago.Cli.CliApplication.RunAsync` code and uses the desktop's own `CliLiveQueryHost` and `CliInvestigationHost`. The initial `engine status` and `rules summary` handlers produce the same bounded read-response schema as the CLI host.
- No extra `--enable-cli-ipc` listener or external executable is launched by the GUI panel. The external PowerShell CLI retains its separate opt-in IPC behavior.
- Supported queries: `engine status`, `rules summary`, `rules list --live`, `rules show R123 --live`, `rules validate`, `sensors list`, `sensors health`, `alerts/incidents/events/hosts list --live`, `capture doctor` and `capture interfaces`. `rules list` and `sensors list` accept bounded `--offset`/`--limit`.
- Commands that start monitoring, mutate a service, stop a monitor, write settings, issue probe authorizations, access arbitrary files or launch a system shell **cannot** be submitted from this GUI terminal. The input is a restricted CARTHAGO command parser, not arbitrary PowerShell.
- Output includes CLI stdout, stderr and its exit code, with a 20-second cancellation budget, bounded per-command output and bounded transcript retention. The terminal does not alter the authoritative evidence journal.

## Detection Coverage KPI

The Overview **Detection Coverage** KPI consumes `RuleCatalog.HealthSnapshots()`, the same catalog/run-state producer used by the Detection Coverage Center.

- Value is `evaluated-currently-alert-mode / currently-alert-mode`. Each numerator rule has **at least one local process evaluation** (`RuntimeStats.Evaluations > 0`) and is **currently** in `RuleMode.Alert`. The numerator is not a count of detections, matched rules, passing accuracy tests, or rules evaluated *while* in that mode.
- Caption states the total registered rules and surfaces any catalog-validation error count.
- A background refresh starts when Overview initializes and repeats at most every 60 seconds while Overview is visible, without blocking the UI thread. Failed or empty catalog reads show **—** rather than an invented zero.
- The Coverage Center retains detailed per-rule statuses including observed telemetry and catalog findings. Rule quality, positive/negative replay completeness, real-world recall and precision **cannot** be inferred from this KPI.

## Validation on Windows

```powershell
git pull --ff-only origin feature/carthago-reliability-hardening

dotnet build .\Carthago\Carthago.csproj -c Release

dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~GuiCliCommandPolicyTests|FullyQualifiedName~DetectionCoverageKpiProjectionTests|FullyQualifiedName~GuiCliInProcessIntegrationTests"
```

Launch the GUI, enter `help`, `rules summary`, `rules list --live --offset 0 --limit 10`, `sensors health --json` and `alerts list --live`. Verify live output, cancellation and that `monitor stop` / `service stop` are rejected. Observe the Detection Coverage metric both before and after a bounded local rule evaluation, then inspect the detailed Coverage Center; do not interpret this as detector qualification.

**Implementation status:** source changes and unit tests committed. Windows build, full test suite and GUI runtime qualification remain pending owner-run evidence. Do not promote to production ready from source review alone.
