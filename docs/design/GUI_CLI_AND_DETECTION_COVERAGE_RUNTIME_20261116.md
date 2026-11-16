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

## Windows assembly identity and qualification update (2026-11-16)

The first combined GUI+CLI Windows test run restored and built successfully, but two CLI integration tests failed to load `Carthago.Cli.CliApplication`: WPF `Carthago` and CLI `carthago` differ only in case, and MSBuild reported MSB3243 before `TypeLoadException`. A distinct `PackageId` fixed NuGet restore, **not** the compiled assembly collision. CLI now declares `<AssemblyName>Carthago.Cli</AssemblyName>` in addition to `<PackageId>Carthago.Cli</PackageId>`. The original `RootNamespace` and public CLI command syntax are unchanged.

Build outputs have a distinct `Carthago.Cli.dll` (and platform apphost when generated), rather than `carthago.dll`. Any direct binary-path consumers must use the new artifact path. `dotnet run --project .\\Carthago.Cli\\Carthago.Cli.csproj -- --help` remains supported. The GUI continues to call the CLI assembly in-process, without spawning a shell.

A new regression test asserts the GUI and CLI assembly identities are different under case-insensitive comparison. Windows re-run of the failing tests and full app smoke test are still required before declaring the integration verified. Previous evidence: Release GUI build passed; 22 of 24 focused tests passed, 2 CLI load tests failed. Do not treat that pre-fix run as acceptance.

## Windows build and focused integration evidence

Owner-run Windows .NET 9.0.321, targeting .NET 8, on 2026-11-16:
- `dotnet build .\\Carthago\\Carthago.csproj -c Release`: **PASS** (35.6s).
- Focused `GuiCliCommandPolicyTests | GuiCliInProcessIntegrationTests | DetectionCoverageKpiProjectionTests`: **25/25 passed**, **0 failed**, **0 skipped**.
- Nine remaining `xUnit1026` warnings refer to unused parameters in unrelated rule-quality tests; no assembly identity conflict remains in this run.
- This evidence verifies compile-time integration and unit/in-process CLI contracts, **not** that the WPF terminal has rendered and accepted a command in a live desktop session.

Subsequent follow-up source changes:
- The KPI now displays `—` (rather than `0/0`) if there are no alert-mode rules, while preserving registered/catalog-error context.
- Re-entering Overview triggers a background coverage refresh immediately instead of waiting for the 60-second periodic tick.
- The GUI read-only CLI allowlist now includes `--version` and `capabilities` (and their optional `--json` variants). It still rejects service/monitor mutation and shell commands.
- Regression tests cover the zero denominator, the complete alert-mode runtime-ratio case, and actual in-process version output.

**After these additional commits, the original 25/25 pass is a previous checkpoint, not verification of the latest HEAD.** Run the focused filter again and complete the manual GUI smoke steps below.

## GUI operational acceptance checks

1. On the target Windows host, run the Release GUI (use the normal app startup or `dotnet run --project .\\Carthago\\Carthago.csproj -c Release`).
2. In the Overview terminal enter `help`, `--version`, `capabilities`, `rules summary` and `rules list --live --offset 0 --limit 10`. Confirm real output, a completion/exit status, no UI freeze, and bounded history.
3. Run `sensors health --json` and `alerts list --live`. The sensor journal report must explicitly say health is not assessed; missing data must be labeled unavailable rather than zero.
4. Verify `service stop`, `monitor stop` and `powershell` are rejected without side effects. Verify Run, Enter, Clear, Cancel and closing the GUI during an in-flight command.
5. Open Detection Coverage Center and compare the actual registered and alert-mode counts to Overview's reported numerator/denominator. The KPI measures the number of alert-mode rules evaluated at least once in this process; it is **not** a detection-quality acceptance rate.
6. Navigate away and back to Overview and confirm the coverage refresh begins promptly. With no alert-mode rules, the KPI must display `—` (not `0/0`).
7. Capture a reproducible screenshot and console log / test TRX of failures; do not claim WPF operational acceptance until the live GUI checks pass.

## Validation on Windows

```powershell
git pull --ff-only origin feature/carthago-reliability-hardening

dotnet build .\Carthago\Carthago.csproj -c Release

dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~GuiCliCommandPolicyTests|FullyQualifiedName~DetectionCoverageKpiProjectionTests|FullyQualifiedName~GuiCliInProcessIntegrationTests"
```

Launch the GUI, enter `help`, `rules summary`, `rules list --live --offset 0 --limit 10`, `sensors health --json` and `alerts list --live`. Verify live output, cancellation and that `monitor stop` / `service stop` are rejected. Observe the Detection Coverage metric both before and after a bounded local rule evaluation, then inspect the detailed Coverage Center; do not interpret this as detector qualification.

**Implementation status:** source changes and unit tests committed. Windows build, full test suite and GUI runtime qualification remain pending owner-run evidence. Do not promote to production ready from source review alone.
