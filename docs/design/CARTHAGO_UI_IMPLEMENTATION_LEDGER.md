# CARTHAGO UI implementation ledger

**GA UI-01 — 2026-10-30 — SOURCE CANDIDATE, UNVERIFIED.** No builds, xUnit, replays, runner jobs, screenshots of running software, or production capture were executed. The reference is a *concept image*, not an implemented or tested screen.

## Authoritative reference

- Approved image: ChatGPT Library file `libfile_b0a34361560c8191b641e432b3e6b15c` (generated 2026-10-30), visual composition 1648×928. Inspect the image before every UI design run; do not approximate it from prose if unavailable.
- Visual language: deep navy/graphite, cyan active navigation and chart, restrained red/amber incident severity, quiet panel borders, readable dense tables, no fake telemetry.
- Branch: `feature/carthago-reliability-hardening` ONLY. No independent UI branch or PR. Rule-hardening owns rule/source/test/evidence paths; design owns UI files and `docs/design/**` only.

## GA UI-01 source-only change

- **Theme:** `Carthago/Views/Theme.xaml` — align shared surface, border, text and cyan accent tokens with approved screenshot; refine KPI card geometry and selected-navigation rail/text. Preserve existing named resource keys, keyboard focus, severity semantics and WPF controls.
- **Sidebar:** `Carthago/Views/Sidebar.xaml` — update wordmark treatment; rename Dashboard's visible label to **Overview** without changing its event or navigation key; move existing **Live Traffic** button plus its original filter expander directly below Overview; preserve all remaining navigation, filters, handlers, and compact-mode x:Names. Remove the hard-coded **400** anomaly badge, which was not bound to live state. No fabricated counts.
- The existing dashboard and incident data pipelines are unchanged. The screenshot's sample incidents, IPs, percentages, throughput, sensors, and CLI output are not inserted into production UI.
- Base remote HEAD at audit: `a4d62afab66bf97458efd251eb6b9c4990522867` (R361–R370 candidate). **Publication commit:** this document is included in the same UI-only commit; consult the branch history for its exact SHA. Static source inspection only, no compilation claim.

## GA UI-02 — Security Overview header and truthful monitoring state

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED · Base HEAD:** `4c9c5a89ce4d13f2d6632306fa76c664f9bcfd18`. This ledger and the XAML are published in the same UI-only commit; obtain its exact publication SHA from Git history. **No build, tests, replay, CI, Windows runner, live capture, or running-UI screenshot executed.**

- **Scope:** `Carthago/Views/MainWindow.xaml` only, plus this design ledger. Introduce a dashboard-only `Security Overview` heading immediately before the KPI strip. Preserve the global capture command bar, device selection, actions, navigation and their existing event handlers.
- **Live status contract:** both the dashboard indicator and status label bind to the existing `MonitoringStatusBadge.BorderBrush` and `CaptureStatusText.Text` (updated by `UpdateMonitoringHeader` in `MainWindow.Dashboard.cs`). The global command bar's previously hard-coded green indicator is also bound to the same runtime border brush. Thus **PAUSED / MONITORING / DEGRADED / ERROR / OFFLINE** never show a fabricated always-green dot. No new polling, capture producers, or state mutation.
- **Reference fidelity:** dashboard-scoped prominent title, restrained cyan/navy visual system from GA UI-01, compact status indicator and status text; the screenshot's illustrative `Monitoring active` claim is **not** hard-coded. The global operational toolbar remains intentionally separate from the mockup header for functional compatibility.
- **Responsive:** existing Wide (≥1440), Standard (1100–1439), Compact (<1100) mode resolver and command-bar positioning remain unchanged; the header's `Grid` separates title and live state without adding a fixed-width fake search field. Very narrow windows still require visual validation.
- **Static divergence review:** pre/post source inspection confirmed the exact original XAML anchors, unchanged `x:Name` for all capture controls, no new Click handlers, no modifications to `MainWindow.Dashboard.cs` or responsive code, no rule/test/engine paths. New `ElementName` bindings reference names that already exist in the same window namescope. Binding resolution and rendered layout remain unverified.
- **Metric provenance audit for next GA:** `BuildSocKpis` currently emits up to five preference-controlled metrics: Active Incidents and High Risk Hosts from correlated incidents, New Anomalies from anomaly snapshots, Threat Feed Hits from anomaly classification, and Baseline Confidence from baseline status. `UpdateKpis` already derives throughput from `_mbpsSeries`, but it currently updates a hidden legacy text control rather than the SOC KPI collection. No verified sensor-inventory denominator or validated detection-coverage denominator exists in this UI source audit. Do not substitute baseline confidence for coverage, and do not invent 8/8 sensors or 96% coverage.
- **Acceptance deferred:** pinned-SHA WPF compilation, UI status transitions (Paused→Monitoring→Degraded/Error), wide/standard/compact screenshots, accessibility/contrast and regression tests when owner authorizes testing. No executed scenario counts.

**Next UI GA:** KPI strip provenance and layout. Reuse real throughput and incident producers, preserve existing preference-controlled metrics and advanced access, and display unavailable states for unimplemented sensor/coverage contracts. Do not convert five existing metric cards to a false four-card dashboard by dropping data or assigning invented percentages.

**Authoritative WPF references:** [WPF panels and Grid/StackPanel sizing](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/controls/panels-overview); [WPF Ellipse Fill brush](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/graphics-multimedia/how-to-draw-an-ellipse-or-a-circle).

## Visual-reference to real-code map

| Approved visual element | Existing code / evidence | Current disposition and next action |
| --- | --- | --- |
| Dark graphite/navy shell, cyan accents, thin dividers | `Views/Theme.xaml`, `Views/Sidebar.xaml` | GA UI-01 source candidate; static only. |
| CARTHAGO wordmark / left navigation | `Views/Sidebar.xaml` and `Sidebar.xaml.cs` | GA UI-01 wordmark + Overview/Live Traffic; retain other real destinations until their navigation contracts can be reconciled. |
| Security Overview header, monitoring state | `Views/MainWindow.xaml` `SocDashboardWorkspace`, `CommandHeader`, `CaptureStatusText`; `MainWindow.Dashboard.cs` `UpdateMonitoringHeader` | GA UI-02 candidate: dashboard-only title and live text/indicator bound to actual capture status; no fake active state. |
| Four KPI cards (throughput, sensors, incidents, coverage) | `MainWindow.xaml` `DashboardKpiItemsControl`, `MainWindow.Dashboard.cs` `_dashboardKpis`, `MainWindow.DashboardResponsive.cs` | Existing five-column Wide grid; audit metric provenance before changing to four cards. If coverage/sensor data are unavailable, show unavailable rather than fake values. |
| Real-time traffic chart | `MainWindow.xaml` hidden legacy `TrafficPlot` / widget workspace; `MainWindow.Plots.cs` | Preserve ScottPlot; assess safe reuse and real telemetry provenance, no simulated chart. |
| High-priority incidents | `DashboardAnomalyList`, incident snapshot in `MainWindow.Dashboard.cs` | Real incident pipeline exists; visual grouping and severity badges pending. Never map screenshot sample R343/R102/R275 titles to actual rules. |
| Investigation / evidence inspector | `DashboardSignalPanel`, `DashboardDetailReasonsItems`, `DashboardDetailRulesItems` | Existing details are populated from app state; visual refinement pending. Evidence is not proof of unsupported outcomes. |
| Live events table | Existing raw traffic / detection views and `DataGrid` styles | Proposed dashboard integration; preserve event filtering and avoid duplicating capture engine. |
| Compact terminal companion | No verified embedded cross-platform CLI in current WPF shell | **NOT IMPLEMENTED.** Plan design-only placeholder with honest unavailable state; do not invent CLI output or working commands. |
| Wide ≥1440 / Standard 1100–1439 / Compact <1100 | `Views/ResponsiveLayout.cs`, `MainWindow.Responsive.cs` | Existing breakpoints preserved; 1024–1099 is target Compact band, with graceful behavior below 1024. |
| Windows and Linux GUI + terminal | WPF currently targets `net8.0-windows10.0.19041.0` | Future separate Avalonia/CLI architecture specification only; no migration in rule-hardening phase. |

## Guardrails and outstanding GA

- Do not edit `Engine/**`, `Models/**`, `Services/**`, rules, capture, tests, runners, workflows, `docs/RULE_HARDENING_PROGRESS.md` or rule evidence. No builds/tests until owner explicitly authorizes.
- Preserve all sidebar `x:Name` identifiers and Click handlers, filters, Cisco tools, view navigation, ScottPlot/WebView2, and WPF window startup.
- Source-only changes may have visual or runtime issues; validate with owner-authorized pinned-SHA Windows build and screenshot review later.
- **Next UI GA:** dashboard KPI strip provenance and responsive presentation, with real throughput/incident bindings and explicit unavailable sensor/coverage states; preserve existing preference-controlled metrics.
