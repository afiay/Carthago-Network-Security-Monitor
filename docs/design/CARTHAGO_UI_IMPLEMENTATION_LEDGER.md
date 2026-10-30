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

## GA UI-03 — Four-card KPI provenance and adaptive presentation

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** UI source commit:
`eed18e04c5fed95ed31731753451da1acaf1aec3` (parent `f80fede814c2905588f715f8091b77c30896faf7`). The design-ledger commit is its
direct descendant; publication uses one non-forced expected-HEAD ref update.
**No WPF build, xUnit, UI screenshot, replay, CI, runner or production capture executed.**

### Approved-reference mapping and actual data provenance

| Reference card | Source / display contract | Limits and false-positive / misleading-display controls |
| --- | --- | --- |
| Network Throughput | `MainWindow.Core.cs` local capture `_bytesBucket` → 1-second `_mbpsSeries`, formatted using existing `FormatThroughput`; `UpdateMonitoringHeader` updates visible card at the existing 5-second cadence | **Observed local capture only**, not total network traffic. Paused/error/offline show `—`; monitoring with no sample shows `—` / awaiting; degraded labels observed values as degraded. No invented 942 Mbps or 12% delta. |
| Active Sensors | `—` / **Inventory unavailable** | No validated inventory/health numerator and denominator in the audited WPF contracts. Never invent 8/8 or online status. |
| Open Incidents | `_sinkHost.Analytics.GetRecentIncidents(150)` snapshot filtered by existing `ActiveIncidents()` (not Resolved) | **Bounded recent snapshot, not a global incident total**; demo-mode data can be included, explicitly noted when demo is enabled. No invented incident score, timestamp, or risk-rule mapping. |
| Detection Coverage | `—` / **No validated denominator** | No validated active-rule denominator or observed rule execution coverage; never substitute baseline confidence or hard-code 96%. |

**Additional metrics:** The original preference-controlled `_dashboardKpis` collection
remains intact below the four reference-aligned cards, retaining Active Incidents,
High Risk Hosts, New Anomalies (15m), Threat Feed Hits, and Baseline Confidence
according to existing `DashboardPreferences` toggles. The shared KPI template
and container style are reused by both strips; no duplicate template implementation.
`SocKpiVm` implements `INotifyPropertyChanged` only for the two live fields
(`Value`, `TrendText`), so status refreshes do not replace the card collection.

**Adaptive layout:** Wide ≥1440 = four cards per row; Standard 1100–1439 = two;
Compact <1100 = two. The prior additional-metric panel templates (5/3/2)
and shell navigation breakpoints are unchanged. Layout below 1024 remains
**source-only, visually unverified**, with a minimum 640px window.

### Owned paths and static divergence review

- `Carthago/Views/MainWindow.xaml` — reusable KPI `DataTemplate` / item style, four reference-aligned cards and labeled additional-metric row.
- `Carthago/Views/MainWindow.Dashboard.cs` — actual analytics/capture provenance, honest missing metrics, observable throughput state.
- `Carthago/Views/MainWindow.DashboardResponsive.cs` — overview KPI adaptive panels without changing existing widget layouts.
- `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` — this contract, evidence limits, scenario inventory and next GA.

Start-of-GA audit: live branch `f80fede814c2905588f715f8091b77c30896faf7`, UI GA UI-01/UI-02
already present; detection GA R371–R380 changed rule/test/docs paths only.
End-of-GA source review: exactly three `Carthago/Views/**` files changed,
existing `DashboardKpiItemsControl`, handlers, capture controls, WPF
partials, Cisco views, ScottPlot/WebView2, preferences and rule sources
retained. One shared card template and one shared item-container style;
all three overview panel resource keys match responsive code.
These are **static inspections, not proof of XAML parsing, compilation, bindings
or layout**.

### Acceptance scenario inventory — DEFERRED, UNEXECUTED

No UI test files were authored because the UI stream cannot modify tests;
the following are **planned manual/integration checks**, not passed cases:
1. Monitoring with a positive local capture sample: correct formatted value, no network-wide claim.
2. Monitoring before the first 1-second sample: `—` and awaiting label.
3. Monitoring with a sampled zero: observed `0 bps`, distinct from unavailable.
4. Paused with stale nonzero series: `—`, never stale throughput.
5. Degraded capture: current local sample explicitly labeled degraded.
6. Error/offline: `—` and unavailable state; no always-green indicator.
7. Incident snapshot: resolved excluded, count bounded to the latest 150.
8. Debug/demo scenario: potential demo inclusion disclosed, no invented rule-to-behavior mapping.
9. Preference toggles: original five metrics appear/disappear as before; no deletion.
10. Missing inventory and coverage producer: `—` with explanatory captions.
11. Wide/Standard/Compact and <1024 widths: no clipped cards, keyboard navigation or unreadable typography.
12. Monitoring/incident changes: data bindings update without blocking UI thread or breaking focus.

**Risks/open GAs:** XAML resource resolution, `ItemsControl` layout and
scroll behavior, actual 5-second update cadence, no-demo labeling,
high-contrast accessibility, and Windows startup are unverified.
Source-only static review cannot establish zero false positives or field
coverage. Do not run verification until the owner explicitly authorizes it.

**Next independent UI GA:** prioritized incidents list and selected-incident
investigation panel (existing `DashboardAnomalyList`, `DashboardSignalPanel`
and real evidence models). Do not edit engine/rules/tests or fabricate
incident proof.

## GA UI-04 — Prioritized incident triage and evidence provenance

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Live feature-branch HEAD
at the start of this GA: `55e6a1e0547a5369197aecea495091f535e97a1a` (the detection stream had already
published R381–R390). The UI-only source commit is `b7978f9889d33360d0b3ad3b6c6848035ba6c824`,
followed by static source-correction commit `08e16e12dd740ca4f5be9608001c6469ab417742`. This ledger
is committed as their direct descendant; the **final published ledger commit**
is the remote feature-branch HEAD after the expected-SHA update. No build,
xUnit, UI screenshot, replay, holdout, CI, Windows runner, or capture executed.

### Approved reference and implemented contracts

| Reference element | UI implementation | Evidence boundary |
| --- | --- | --- |
| Recent high-priority incidents | Existing `DashboardAnomalyList` now shows up to **four unresolved correlated incidents** first, sorted by `RiskScore` then `UpdatedUtc`; then up to **two anomaly signals**. When there are no unresolved incidents, retain the previous five-signal fallback. | `_dashboardIncidentSnapshot` is a **bounded recent 150-item analytics snapshot**; `_dashboardAnomalySnapshot` is bounded to 160. Not a global incident inventory, full chronology, confirmed compromise, or externally verified outcome. |
| Severity and risk | Severity badge and accent use original incident/anomaly severity; circular numeric badge uses existing incident risk or normalized anomaly score. `INCIDENT` / `SIGNAL` labels distinguish provenance. | **Local risk score, not a confidence percentage**. Never use demo R343/R102/R275 mappings or screenshot IPs as actual facts. |
| Selected incident investigation | Reuses `DashboardSignalPanel`, `DashboardAnomalyList_SelectionChanged`, `CreateDashboardSignalDetailModel`, and the existing incident/anomaly detail dialog/navigation. The selected queue entry carries separate `IncidentId` and `AnomalyId` so a signal ID cannot be mistaken for an incident ID. | For an anomaly, only explicit `Incident.RelatedAnomalies` linkage can identify a related incident; **same-source-IP coincidence no longer claims correlation** in this UI path. |
| Evidence provenance | New `DashboardDetailEvidenceSummaryText` shows only the selected incident's count of **reported** `Evidence` entries and `RelatedEvents` count. Existing reasons/tags/related-rule IDs remain visible. | No raw evidence payload is newly displayed, no chain-of-custody or successful detection is asserted, and an unlinked signal shows an honest unavailable message. Open the existing incident workspace for original context. |
| Queue usability | Source-only selection highlighting and keyboard-focus border; old unbound search/category/linked-only controls replaced with truthful noninteractive ordering caption. | No fake search/filter behavior. Existing named controls and Click handlers remain. Demo mode warns that snapshot items **may include demo data**; no individual event is falsely labeled as live. |

The screenshot's dedicated real-time chart, confidence percentages, incident timestamps,
evidence-chain chronology and export actions remain **visual reference only** where no
verified UI producer or authorization contract was established. The existing detail
dialog and navigation were reused rather than introducing a new evidence exporter.

### Static divergence review and ownership

- Owned paths changed: `Carthago/Views/MainWindow.xaml`,
  `Carthago/Views/MainWindow.Dashboard.cs`, and this
  `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. No engine, rules,
  model, services, tests, workflow, runner, project, or rule-doc changes.
- Compared against live HEAD `55e6a1e0547a5369197aecea495091f535e97a1a`; prior UI GA UI-01/02/03
  remained intact. The independent R381–R390 detection stream had published
  only its owned paths. The remote HEAD must be rechecked before publication.
- Static inspection confirmed XAML element nesting and 1,011 tag tokens, existing
  `DashboardAnomalyList` / `DashboardSignalPanel` names, existing
  selection/navigation handlers, separate incident/anomaly identifiers,
  and source-only evidence counts. **This is not a XAML compile or binding pass.**
- Selection across snapshot refreshes preserves the prior visible item when
  present; a disappeared item falls back to the first current priority entry.
  Existing widget preferences, capture controls, Cisco/network tools,
  ScottPlot, WebView2 and global status UI were not modified.
- The UI's `FindRelatedIncident` now requires explicit anomaly linkage.
  This prevents a host-IP-only false association in the dashboard but may
  show fewer related incidents when the analytics producer lacks linkage;
  that limitation is intentional and should be evaluated at test time.

### Planned acceptance scenarios — NOT AUTHORED AS TESTS, UNEXECUTED

1. Four unresolved incidents with mixed risk/severity: descending risk, then update time.
2. Resolved incident among recent 150: excluded from triage; KPI behavior unchanged.
3. No unresolved incidents and five signals: five-signal fallback remains visible.
4. Four incidents and two signals: six typed rows, no mixed-ID navigation.
5. Select a correlated incident: detail title/source/destination/reasons/rules match its snapshot.
6. Select an unlinked anomaly: no incident evidence or host-IP-only correlation claim.
7. Select an explicitly linked anomaly: related incident only via `RelatedAnomalies`.
8. Reported evidence count zero/nonzero: truthful count and no new raw evidence.
9. Demo mode on/off: global provenance warning present only when demo is enabled.
10. Snapshot update/remove selected entry: selection remains stable or falls back without stale detail.
11. Keyboard focus and selection contrast in Wide/Standard/Compact and below 1024.
12. Existing Full Detail, Investigate Host, Related Incident, navigation and widget preference regressions.

**Outstanding quality GAs:** owner-authorized pinned-SHA Windows WPF compilation,
rendered screenshot comparison, UI thread/event reentrancy checks, keyboard
accessibility, text truncation, risk-color semantics, incident/anomaly provenance,
and demo/production separation. None executed. This source candidate does not
establish commercial quality, field accuracy, or certification.

**Next UI GA UI-05:** live events presentation using existing real event producers
and filters, with honest empty/unavailable states. Do not duplicate capture
or change shared telemetry contracts.

## Visual-reference to real-code map

| Approved visual element | Existing code / evidence | Current disposition and next action |
| --- | --- | --- |
| Dark graphite/navy shell, cyan accents, thin dividers | `Views/Theme.xaml`, `Views/Sidebar.xaml` | GA UI-01 source candidate; static only. |
| CARTHAGO wordmark / left navigation | `Views/Sidebar.xaml` and `Sidebar.xaml.cs` | GA UI-01 wordmark + Overview/Live Traffic; retain other real destinations until their navigation contracts can be reconciled. |
| Security Overview header, monitoring state | `Views/MainWindow.xaml` `SocDashboardWorkspace`, `CommandHeader`, `CaptureStatusText`; `MainWindow.Dashboard.cs` `UpdateMonitoringHeader` | GA UI-02 candidate: dashboard-only title and live text/indicator bound to actual capture status; no fake active state. |
| Four KPI cards (throughput, sensors, incidents, coverage) | `MainWindow.xaml` `DashboardOverviewKpiItemsControl`, `MainWindow.Dashboard.cs` `_dashboardOverviewKpis`, `MainWindow.DashboardResponsive.cs` | **GA UI-03 SOURCE CANDIDATE — UNVERIFIED:** observed local throughput and bounded unresolved incidents; sensors/coverage explicitly unavailable. Original preference-controlled five metrics retained in `DashboardKpiItemsControl`. |
| Real-time traffic chart | `MainWindow.xaml` hidden legacy `TrafficPlot` / widget workspace; `MainWindow.Plots.cs` | Preserve ScottPlot; assess safe reuse and real telemetry provenance, no simulated chart. |
| High-priority incidents | `DashboardAnomalyList`, `MainWindow.Dashboard.cs` `BuildSocAnomalyItems` | **GA UI-04 CANDIDATE — UNVERIFIED:** up to four unresolved incidents by risk then two anomaly signals (five-signal fallback); typed provenance, selected-row focus. No demo rule mapping. |
| Investigation / evidence inspector | `DashboardSignalPanel`, `DashboardDetailReasonsItems`, `DashboardDetailRulesItems`, `DashboardDetailEvidenceSummaryText` | **GA UI-04 CANDIDATE — UNVERIFIED:** direct incident selection and reported evidence/event counts only; no raw payload or verified chain-of-custody claim. |
| Live events table | `MainWindow.xaml` `DashboardLiveEventsGrid`; `MainWindow.DashboardEvents.cs` UI-only projection of `_alerts` | **GA UI-05 SOURCE CANDIDATE — UNVERIFIED:** 80 most recently received local detections, severity/protocol/rule/endpoint filters, count-only evidence, delivery state and honest empty/paused/demo labels. |
| Compact terminal companion | `MainWindow.xaml` `DashboardCliCompanionPanel`; `MainWindow.DashboardResponsive.cs` | **GA UI-06 SOURCE CANDIDATE — UNVERIFIED:** visual-only terminal card, explicit **UNAVAILABLE** state, no command input/output/runner; 408px right-aligned on Wide, stretched on Standard/Compact. |
| Wide ≥1440 / Standard 1100–1439 / Compact <1100 | `Views/ResponsiveLayout.cs`, `MainWindow.Responsive.cs` | Existing breakpoints preserved; 1024–1099 is target Compact band, with graceful behavior below 1024. |
| Windows and Linux GUI + terminal | WPF currently targets `net8.0-windows10.0.19041.0` | Future separate Avalonia/CLI architecture specification only; no migration in rule-hardening phase. |

## Guardrails and outstanding GA

- Do not edit `Engine/**`, `Models/**`, `Services/**`, rules, capture, tests, runners, workflows, `docs/RULE_HARDENING_PROGRESS.md` or rule evidence. No builds/tests until owner explicitly authorizes.
- Preserve all sidebar `x:Name` identifiers and Click handlers, filters, Cisco tools, view navigation, ScottPlot/WebView2, and WPF window startup.
- Source-only changes may have visual or runtime issues; validate with owner-authorized pinned-SHA Windows build and screenshot review later.
- **Next UI GA UI-07:** responsive/accessibility and visual-consistency audit, including the outstanding traffic-chart provenance mapping. GA UI-01–06 remain SOURCE CANDIDATES — UNVERIFIED until owner-authorized Windows verification.

## GA UI-05 — Recent local detection events

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Audited live feature HEAD
`44d96037a5ecc5445e87b665a79ea4e1f2f07e4b` before editing; UI-04 remains intact and the independent detection
R391–R400 batch modified only its own rule/test/docs paths. Source changes
are a new UI-only `Views/MainWindow.DashboardEvents.cs` partial plus
`Views/MainWindow.xaml` and lifecycle hooks in
`Views/MainWindow.Dashboard.cs`. No build, xUnit, rendered screenshot,
replay, holdout, CI, runner or capture executed. Source implementation
commit: **deaa4be863bb415a248b792bb5d684feff0e192f**; final ledger publication is the descendant
expected-HEAD-protected feature commit.

### Approved reference mapping and observed producer

| Screenshot element | UI implementation | Contract and limitation |
| --- | --- | --- |
| Lower full-width Live Events table | `DashboardLiveEventsPanel` beneath the existing triage/summary cards; native read-only `DataGrid` with Event time, Source, Destination, Rule, Severity, Protocol, Evidence and Delivery. | Rows are **real `DetectionEvent` objects already received by the existing `TrafficCaptureService.DetectionEventRaised` pipeline**, projected from `MainWindow.Core.cs`'s bounded `_alerts` collection; not a new capture or cloud audit producer. |
| Severity, protocol, rule and endpoint search | Local filters on an independent 80-row display projection; Clear filters and All detections navigation reuse existing handlers. | No modification of the `AlertsGrid`'s existing collection view/filter, BPF, rule engine, alert handling or saved preferences. |
| Freshness / availability | `_alerts.CollectionChanged` marks projection dirty; one-second UI timer coalesces changes while dashboard visible. Capture status from `CaptureStatusText` distinguishes monitoring/degraded from not-monitoring. | Rows persist after capture pauses; not presented as newly generated. No real-time guarantees or historical journal completeness. Up to 500 in-memory detections retained, up to 80 filtered rows shown; newest **received** first, not verified event chronology. |
| Evidence / event status | Evidence column displays only reported presence or structured item count; Delivery column displays `DetectionEvent.DeliveryStatus`. | No raw `Evidence` or `StructuredEvidence.Items` values, no chain-of-custody, no successful operation, no incident resolution. Timestamp shown as recorded because timezone provenance is not verified. |
| Empty / demo states | Distinguishes no session detections from no filter matches; global demo-mode warning when enabled. | Existing event model has no per-event trusted demo marker; rows are not individually claimed production-only. The reference screenshot's R343/R102/R275 labels, IPs and incident statuses are not copied as facts. |

### Static divergence review and ownership

- Before: live `44d96037a5ecc5445e87b665a79ea4e1f2f07e4b`; after: new source candidate commit and
  descendant ledger commit, both on the **same existing feature branch**.
  No changes to `Engine/**`, `Models/**`, `Services/**`, detection rules,
  capture/provenance, tests, workflows, project configuration or rule docs.
- Reviewed original `MainWindow.xaml`, `MainWindow.Dashboard.cs`,
  `MainWindow.Core.cs`, `MainWindow.DataEvents.cs`,
  `MainWindow.Filters.cs`, `MainWindow.Navigation.cs`,
  `MainWindow.DashboardResponsive.cs`, `DetectionEvent.cs` and
  `Carthago.csproj` before editing. Existing UI-01–04 cards, incident
  triage/investigation, responsive grid and all advanced views are retained.
- One `DataGrid` projection is separate from `AlertsGrid.ItemsSource`,
  preventing filter interference. UI timer and collection event are
  unsubscribed in the existing dashboard cleanup path. A new UI-only
  partial is automatically included by the SDK project; no project edits.
- **Source-only review**, not proof of XAML parsing, binding, rendering,
  accessibility, thread behavior, memory footprint or event correctness.

### Planned manual/integration acceptance GAs — NOT EXECUTED

1. No events since startup: explicit no-local-detections empty state.
2. Nonmatching filters with retained events: no-match state, not no-events claim.
3. Multiple severities/protocols: exact severity/protocol selection.
4. Rule substring and endpoint search: case-insensitive matching, no payload search.
5. Clear filters: restored retained order, no change to Advanced Alerts filters.
6. 500 retained / 80 displayed: no extra retained rows or unbounded projection.
7. Burst of detection events: coalesced UI update without noticeable freezes.
8. Pause/degraded/offline transitions: truthful retained-event and capture status.
9. Missing timestamp/source/destination/evidence: placeholders without fabricated fields.
10. Sensitive structured evidence and raw evidence: only count/presence, never content.
11. Demo-mode toggle: global warning without unproven per-event labeling.
12. Wide/Standard/Compact/below-1024: grid horizontal scrolling, keyboard and screen-reader access.
13. Existing All detections navigation and sidebar filters continue unchanged.
14. Window close: no dangling UI timer or collection-event callback.

**Outstanding GAs:** owner-authorized pinned-SHA Windows WPF build, UI
render/screenshot comparison, row filtering/selection, lifecycle,
accessibility, capture-mode transitions and privacy regression. No
test pass or accuracy claim is established.

**Next independent UI GA UI-06:** compact CLI companion **visual-only**
with truthful unavailable state; first inspect existing CLI entrypoints
and document future Windows/Linux CLI + Avalonia architecture without
creating adapters or inventing working commands.

## GA UI-06 — Compact CLI companion, visual only

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Live feature HEAD at start:
`75caad103da26d1a3c2e1f5b207185ed76188b3f`, including the
independent R401–R410 rule candidate and UI-05. UI source commit:
`f61bd16d4609e88c51ebaa099050d6eb018e9188`. The design ledger and
[future CLI/Avalonia specification](CARTHAGO_CLI_AVALONIA_FUTURE_ARCHITECTURE.md)
are committed as its descendant. Final publication SHA is the feature ref
after the single expected-HEAD non-forced update; a Git commit cannot contain
its own SHA. **No builds, tests, replays, CI, Windows runner or capture executed.**

### Reference mapping, evidence and limitations

| Approved reference | UI-owned source | Honest behavior / divergence |
| --- | --- | --- |
| Dark navy terminal-style card at lower right | `Carthago/Views/MainWindow.xaml` `DashboardCliCompanionPanel` | Existing `PageSurface`, navy inset, cyan monospace glyph and quiet unavailable badge. **No fake prompt, command output, sample IPs, alerts or live terminal session.** |
| Terminal connection / command status | Static, explicit `UNAVAILABLE` and `No CLI session connected` labels | Source audit found **no production CLI executable or command dispatcher**. `Carthago/Carthago.csproj` is a Windows WPF `WinExe`; `Carthago/Tests/Program.cs` is a test harness, `Carthago.Benchmarks/Program.cs` is a benchmark, and `scripts/*.ps1` are engineering scripts, not an embedded CLI. No adapter or process execution was added. |
| Wide / Standard / Compact layout | `Carthago/Views/MainWindow.DashboardResponsive.cs` | Wide ≥1440: 408px card aligned right. Standard 1100–1439 and Compact <1100: stretch to available width. Below 1024 remains unverified. No existing breakpoints or other panel placement changed. |
| Reference placement directly under investigation panel | Existing WPF dashboard preserves its incident detail layout and full-width Live Events table | **Intentional deviation:** card follows Live Events in the scrollable dashboard, aligned right on Wide. Avoids shrinking the eight-column event table or clipping the existing investigation panel. Revisit only after rendered-layout verification. |

**Source-only divergence review:** Inspected the exact approved Library image
`libfile_b0a34361560c8191b641e432b3e6b15c`, live feature HEAD, prior UI
ledger, `MainWindow.xaml`, `Theme.xaml`, `Sidebar.xaml`,
`MainWindow.Core.cs`, `MainWindow.xaml.cs`, responsive partials, existing
CLI-like repository entrypoints and project targets. The source patch changes
**only** `Carthago/Views/MainWindow.xaml` and
`Carthago/Views/MainWindow.DashboardResponsive.cs`; this ledger and the
separate future architecture spec are the only documentation paths.
Static XAML tag nesting inspection found no mismatch (1,091 tokens);
`DashboardCliCompanionPanel` occurs once. UI-01–05 controls, existing
capture and event handlers, navigation, preferences, Cisco tools,
ScottPlot, WebView2 and detection rules are not modified. Static inspection
is **not** a compile, binding, accessibility or visual-render pass.

### Planned acceptance GAs — NOT AUTHORED AS TESTS, UNEXECUTED

1. Wide ≥1440: right-aligned compact card, no overlap with Live Events or sidebar.
2. Standard 1100–1439: stretched card, legible text and no horizontal clipping.
3. Compact 1024–1099: stretched card, existing scroll and navigation intact.
4. Window below 1024 (down to existing 640px minimum): wrapped labels, no clipping.
5. High-contrast, keyboard traversal and screen reader: unavailable status announced without an interactive fake terminal.
6. Capture active/paused/error and demo toggles: companion remains **unavailable**, never claims capture or CLI connection.
7. No `Process.Start`, shell, command dispatcher, command input, output stream, IPC or telemetry producer introduced.
8. Live Events filtering and all existing incident selection, Cisco/network and settings handlers still function.
9. Reference comparison: navy inset, cyan glyph, restrained unavailable badge; documented location deviation accepted or adjusted.
10. Pinned-SHA Windows WPF compilation, startup, XAML resource resolution and visual screenshots **only after owner authorization**.

**Open GAs:** compile/render verification, keyboard/accessibility, small-window
behavior, actual traffic-chart provenance and screenshot fidelity, CLI design
threat model, and platform-specific support matrix. No tests or runtime
verification have occurred. This source candidate does not imply working
CLI functionality or Windows/Linux GUI support.

**Next UI GA UI-07:** responsiveness, accessibility and visual consistency
review; inspect actual real-time traffic chart binding before changing chart
presentation. Keep the independent ten-rule work and its files untouched.


## GA UI-07 — Narrow-window KPI readability and chart provenance audit

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Audited LIVE branch HEAD
`a806a3b1ed710c3724b4c1d0de1113fc689977eb` after the independent R411–R420 source candidate and UI-06.
Approved visual reference `libfile_b0a34361560c8191b641e432b3e6b15c`
was materialized and visually inspected. The source candidate changes only
`Carthago/Views/MainWindow.xaml`,
`Carthago/Views/MainWindow.Responsive.cs`, and
`Carthago/Views/MainWindow.DashboardResponsive.cs`. This ledger is a
direct descendant of the UI-only source commit. The final publication SHA
is the live feature HEAD after the expected-SHA, non-forced ref update;
it cannot be embedded in its own commit.

### Cohesive responsive/accessibility improvement

- Preserve the approved Wide (≥1440) four-column operational KPI strip,
  Standard (1100–1439) two-column strip, and Compact (1024–1099)
  two-column strip. Below 1024, stack **both** operational and
  preference-controlled KPI strips into one column, down to the existing
  640px minimum window. Existing sidebar, incident triage, command bar,
  Live Events, and CLI companion layouts remain unchanged.
- Keep the existing `ResponsiveLayout.Resolve` thresholds and
  `ApplyDashboardResponsiveLayout` partial contract private to the UI.
  Track only the **1024px crossing** within Compact mode so resize changes
  are applied without rebuilding the panels on every pixel change.
- The shared KPI trend caption now uses `CharacterEllipsis` and exposes
  its full text in a tooltip. This avoids uncontrolled horizontal
  overflow without replacing unavailable values or truncating the
  underlying model. Actual screen-reader behavior and tooltip accessibility
  remain unverified.
- Preserve all existing `SocKpiVm` bindings, card titles, live throughput,
  bounded incident snapshot, honest unavailable sensors/coverage, and
  preference-controlled additional metrics. No invented telemetry,
  event producer, or new control handler.

### Real-time traffic chart provenance (audit only; no chart edits)

- `MainWindow.DataEvents.cs` increments `_ppsBucket` once per
  `TrafficRecordReceived` and adds nonnegative `record.Length` to
  `_bytesBucket`. `MainWindow.Core.cs` samples these once per second,
  appending timestamped packet counts to bounded
  `_trafficXs`/`_trafficYs` (120 seconds) and separately computing
  `_mbpsSeries` from observed local bytes.
- `MainWindow.Plots.cs` `RenderTraffic` draws **packets/second** plus
  optional 10-sample moving average into the existing hidden legacy
  `TrafficPlot` and the Analytics `TrafficPlot_Analytics` ScottPlot
  controls. The Security Overview does **not** currently expose the
  approved screenshot's visible three-series Mbps chart. Do not relabel
  PPS as Mbps or infer inbound/outbound series from an aggregate counter.
- Capture-paused timer ticks can produce zero PPS samples even without
  active capture. A future dashboard chart must distinguish missing/
  paused observation from an observed zero and must reuse actual
  producers and existing ScottPlot controls, not fabricate series.
  No chart XAML, plot logic, model, capture or service code changed.

### Static divergence review and outstanding GAs

Compared original source, UI-01–06 ledger, live rule commit paths, exact
resource keys, partial declarations/call sites, reference visual,
privacy/mode restrictions, and UI-owned changed paths. The source
changes only KPI presentation and same-mode resize invalidation; no
engine/models/services, rules, tests, workflows, Cisco, WebView2,
ScottPlot, shared project/API, or detection ledger edits.
Source-only review is **not** a WPF compile, runtime binding pass,
screenshot verification, accessibility pass, or evidence validation.

**Planned acceptance scenarios — NOT AUTHORED AS TESTS; UNEXECUTED:**
1. Width 1440: four overview cards; optional metrics unchanged.
2. Width 1100: two overview cards per row; existing Standard shell.
3. Width 1099 and 1024: two overview cards per row; existing Compact shell.
4. Width 1023 and 640: one column in both KPI strips, vertical scrolling.
5. Resize 1023→1024→1023: strip switches without duplicate cards or lost bindings.
6. Long trend text: ellipsis and full-text tooltip; no misleading values.
7. Capture paused/error/degraded: truthful unavailable/observed throughput.
8. Keyboard, screen-reader, high-contrast, 125–200% DPI and translated text:
   readable labels without clipping; pending verification.
9. Preference toggles: original optional cards preserved and correctly ordered.
10. Live Events filters, incident selection, Cisco tools, navigation and
    CLI unavailable panel remain unchanged.

**Outstanding quality GAs:** owner-authorized pinned-SHA Windows build,
WPF rendered reference screenshots across width/DPI modes,
keyboard/screen-reader verification, card binding and preference regression,
and real traffic-series capture-state validation. **Tests executed: 0.**
No field accuracy, production readiness, or certification is claimed.

**Next UI GA UI-08:** investigate a reference-aligned **visible real-time
traffic chart** using the existing locally observed PPS series and ScottPlot
without reusing hidden plot controls unsafely, claiming inbound/outbound
traffic, inventing Mbps series, or editing engine/telemetry. If UI-only
reuse is not safely possible, document a precise integration proposal
instead of changing shared contracts. The detection automation remains
independent.

## GA UI-08 — Visible local PPS chart (no new telemetry)

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Audited live feature HEAD
`9d63cc62d619ad1438bed3d8f00b7a2a6d767662`, following GA UI-07 and independent detection GA R421–R430.
Authoritative Library image `libfile_b0a34361560c8191b641e432b3e6b15c`
was visually inspected. UI source commit: `b8f12da58a63e6999c966b1be10fe9b232e97f03`.
This ledger commit is a direct descendant of the UI source commit; its
publication SHA is the live branch HEAD after the protected update.
**No builds, tests, replay, CI, Windows runner or capture executed.**

### Evidence contract and approved-reference mapping

| Reference element | Actual source and presentation | Truthfulness boundary |
| --- | --- | --- |
| Network Traffic (Real-time) chart | Existing `TrafficPlot` ScottPlot WPF instance moved from collapsed `DashboardLegacyInfrastructure` to a visible `DashboardTrafficChartPanel` immediately below the four operational KPI cards. Reuses `InitAllPlots` and `RenderTraffic` without duplicating controls. | Local captured **packets/second (PPS)** only, with the existing 10-sample moving average. Not the reference image's total/inbound/outbound Mbps. No new renderer or producer. |
| Capture health | Existing `CaptureStatusText.Text` and `MonitoringStatusBadge.BorderBrush` ElementName bindings, same as the overview header. | PAUSED/ERROR/OFFLINE/DEGRADED display a caution about stale history and timer-generated zero samples; MONITORING hides the caution. A zero PPS sample does not prove sensor health or packet attribution. |
| Chart window and empty state | `MainWindow.Core.cs` retains a 120-sample timestamp/PPS history sampled every second; `RenderTraffic` draws only when more than one sample exists. | Before two timer ticks, the plot has no line; no invented values, loading progress, or network-wide coverage. The existing timer can append zeros even when capture is inactive; this is a known producer limitation, not fixed or concealed by the UI. |
| Responsive/reference fidelity | One full-width navy card with cyan/blue plot and amber moving-average overlay, placed between KPI strip and additional metrics; WPF Grid width follows the existing scroll viewport. | Reference has a chart left of the incident list with three Mbps series; this GA deliberately does **not** restructure the incident/investigation panels or fabricate unsupported series. Screenshot fidelity remains partial until owner-authorized rendering. |

### Static divergence review and ownership

- **Changed source:** `Carthago/Views/MainWindow.xaml` only. This ledger is the only documentation change. No new XAML control name or duplicate `TrafficPlot`; original Analytics `TrafficPlot_Analytics`, protocol/top-talker/severity plots and spark controls are unchanged.
- Reused existing WPF ScottPlot v5 plotting, original `_trafficXs`/`_trafficYs`, 1-second timer, 120-point bound, existing axes/legend, and existing capture state. No `MainWindow.Plots.cs`, `MainWindow.Core.cs`, capture/model/service/engine/rule, test, project, workflow, or rule-doc edit.
- No additional packet details, addresses, payloads, evidence, or demo telemetry are exposed. Global demo warnings remain intact; no chart value is represented as authenticated evidence.
- No change to rule IDs, modes, thresholds, cooldowns, confidence floors, approvals, privacy/journal controls, preferences, navigation, Cisco tools, WebView2, or CLI unavailable state.
- Source-only XAML anchor/named-control and owned-path review is **not** a compile, binding, visual, accessibility, or runtime verification pass. All new source/documentation remains **UNVERIFIED**.

### Acceptance scenarios — PLANNED, NOT AUTHORED AS TESTS, UNEXECUTED

1. WPF startup resolves the single `TrafficPlot` name and existing ScottPlot v5 styles.
2. Before two timer ticks, chart is empty without invented values.
3. Monitoring with captured packets: displayed PPS equals existing one-second packet bucket.
4. At 11+ samples: optional 10-sample average aligns with the existing PPS history.
5. Paused capture with retained points: PAUSED badge and stale/zero caution remain visible.
6. Error, offline and degraded states: status and caution do not claim current traffic.
7. Monitoring with zero packets: zero is not labeled proof of source health.
8. Existing Analytics plot still renders independently and no duplicate plot is constructed.
9. Wide/Standard/Compact and below-1024 windows: chart remains readable without clipping.
10. Dashboard preferences, incident selection, Live Events filters, Cisco controls, CLI unavailable panel and keyboard navigation remain intact.

**Open quality GAs:** pinned-SHA Windows WPF compilation; actual ScottPlot
visibility/rendering and timestamp axes; capture-state transitions; keyboard
and screen-reader accessibility; high-DPI layout; snapshot comparison with
approved concept; demo/real provenance review. **Tests executed: 0.**
No field accuracy, validation, production readiness, or certification is claimed.

**Next UI GA UI-09:** audit the visible chart and overview accessibility/
density at narrow widths; prefer source-only, UI-owned improvements. Do not
add inbound/outbound Mbps without trusted producers or alter detection work.

**Reference:** [WPF DataTrigger](https://learn.microsoft.com/en-us/dotnet/api/system.windows.datatrigger).

## GA UI-09 — Narrow-window PPS chart header and capture-status readability

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Start live feature HEAD:
`3172fdd340ce34b851511278a5fafadbe2437018` (after independent
R431–R440 candidate); UI source commit:
`965fbf47a97834c32c048576de25176fd5138f41`.
Publication is the protected feature ref after this ledger commit; the
commit cannot embed its own final SHA. **Tests authored: 0; executed: 0.
No builds, replay, holdouts, CI, runner jobs or capture.**

### Approved reference, original source and evidence boundary

The exact approved Library image
`libfile_b0a34361560c8191b641e432b3e6b15c` was visually inspected.
The screenshot places a dark navy traffic card above incidents with a compact
heading and capture state. Existing UI-08 already exposes the original
`TrafficPlot` ScottPlot WPF instance with actual local **PPS** and optional
10-sample average over the bounded 120-point history. This GA **does not**
add another chart, change plotting, introduce telemetry or infer inbound,
outbound or Mbps series. The chart remains full-width above incidents, rather
than the reference's side-by-side composition; this deviation is intentional
until authorized rendered-layout verification.

| Chart element | UI-only change | Evidence and accessibility limit |
| --- | --- | --- |
| Heading and sample-window subtitle | `MainWindow.xaml` gives the existing chart-header grid an unused second row and allows the PPS title to wrap. | Existing title, units and real capture-history description are unchanged; actual high-DPI/text-scale rendering is unverified. |
| Current capture status | Existing status label is named `DashboardTrafficChartCaptureStatus` and repositioned below the title **only below 1024px** using the existing `narrowKpis` responsive transition. | The label remains bound to `CaptureStatusText` and its color to `MonitoringStatusBadge`; no new status or proof of capture health is inferred. |
| Wide/Standard/Compact | ≥1024px retains title-left/status-right; 640–1023px places status in the second row with 6px top spacing. | Wide ≥1440, Standard 1100–1439 and Compact 1024–1099 remain unchanged; UI-07's below-1024 KPI behavior is reused. |
| Chart and caution | Existing `TrafficPlot` instance, static accessibility metadata, and non-MONITORING stale-history/zero-sample warning are preserved. | A plotted zero may be timer-generated when capture is inactive; no new screen-reader data table or runtime chart validation is claimed. |

### Static divergence review, ownership and risks

- **Changed paths:** `Carthago/Views/MainWindow.xaml`,
  `Carthago/Views/MainWindow.DashboardResponsive.cs`, and this design ledger.
  The source patch adds no dependency, handler, shared API, data model or
  separate telemetry producer.
- Inspected the original UI-08 chart markup, the responsive partial and its
  existing below-1024 threshold, `MainWindow.Plots.cs`, theme resources,
  UI-01–08 ledger, and the independent R431–R440 changed-path comparison.
  No UI-owned path had changed since UI-08 before this candidate.
- Source-only checks: the named chart-status element occurs once, the
  responsive repositioning call occurs once, the existing `TrafficPlot`
  declaration remains unique, and the XAML replacement preserves the original
  chart/caution binding text. These checks are **not** a WPF parse, compile,
  layout, accessibility, runtime or screenshot pass.
- No changes to `Carthago/Engine/**`, `Models/**`, `Services/**`,
  rules, tests, project, workflows, capture, Cisco, WebView2, ScottPlot
  rendering code, alert/evidence contracts, approvals, confidence floors,
  journal/privacy or detection documentation. Same-branch concurrency is
  reconciled only through a final expected-HEAD protected publication.
- **Residual risk:** the status can still be announced separately from the
  chart by assistive technology, and WPF may render unexpectedly under high
  text scale or minimum-width conditions. Runtime verification remains
  unauthorized.

### Acceptance scenarios — PLANNED, NOT AUTHORED AS TESTS, UNEXECUTED

1. Width 1440: heading and capture status remain side by side.
2. Width 1100: Standard layout preserves original chart header and bindings.
3. Width 1099 and 1024: Compact layout retains the side-by-side status.
4. Width 1023 and 640: status moves to its own row and title wraps without clipping.
5. Resize 1023→1024→1023: status returns to the correct row without duplication.
6. MONITORING, PAUSED, OFFLINE, ERROR and DEGRADED: existing badge text/color and caution remain truthful.
7. No captured packets: no invented series or source-health assertion appears.
8. At 2 and 11+ samples: original PPS and optional moving average remain unchanged.
9. 125–200% DPI, keyboard and screen-reader: status and chart help text remain understandable.
10. Existing Analytics chart, incidents, Live Events, Cisco, preferences and unavailable CLI panel continue functioning.

**Open quality GAs:** pinned-SHA Windows compilation, rendered reference
comparison across widths/DPI, chart keyboard and screen-reader inspection,
capture-state transitions, retained-history semantics, and end-to-end
regression after owner authorization. **No runtime or quality result claimed.**

**Next independent UI GA UI-10:** audit the visible chart's truthful empty/
unavailable communication and accessible text alternative using existing
UI-owned data/bindings only. Do not duplicate UI-08/09 or modify shared
capture/model/engine contracts. Keep the detection automation independent.

**References:** [WPF Grid attached positioning](https://learn.microsoft.com/en-us/dotnet/api/system.windows.controls.grid.setrow);
[WPF responsive layout](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/layout);
[original UI-08 ledger](#ga-ui-08--visible-local-pps-chart-no-new-telemetry).

## GA UI-10 — Truthful local PPS waiting state and accessible text summary

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Started from LIVE
`feature/carthago-reliability-hardening` HEAD
`ecf364be165f6b754b0b683088554c3a14d41099` (after independent detection R441–R450 candidate).
UI source commit: `fc8203ca26c5511bda1936fd7bf00bc305513ccd`. The complete publication is the
expected-HEAD-protected feature ref after the documentation commit; a commit
cannot embed its own SHA. **No builds, tests, replays, CI, runner jobs or
production capture were executed.** Authored automated tests: **0** (UI
ownership excludes test-suite modifications). Planned acceptance scenarios:
**10, unexecuted**.

### Evidence and design contract

The authoritative Library reference
`libfile_b0a34361560c8191b641e432b3e6b15c` was retrieved and
visually inspected before changes. Its dark navy traffic card and restrained
empty-state treatment are the visual guide; its three-series Mbps plot,
incident metrics and timestamps are **demo content**, not telemetry
contracts. The original WPF `TrafficPlot` remains the single visible local
ScottPlot PPS chart, with the existing ten-sample average and 120-point
history. It is still full-width above incidents, not the reference's
side-by-side placement.

| UI element | Source binding | Evidence boundary |
| --- | --- | --- |
| Waiting overlay | `DashboardTrafficChartWaitingPanel` in `MainWindow.xaml`; `MainWindow.Plots.cs` toggles it only while `_trafficYs.Count < 2`, matching the existing `RenderTraffic` minimum line threshold. | No invented samples, capture readiness, progress percentage, or network-wide measurement. Timer ticks can be zeros even without capture. |
| Readable alternative | `DashboardTrafficChartTextSummary` in the chart footer is updated by the **existing** `RenderTraffic` path with the latest local PPS timer value, retained count (maximum 120) and the existing `CaptureStatusText.Text`. | A timer sample is **not** authenticated evidence of active capture. Summary explicitly warns that zeros can occur without active capture. It does not disclose endpoints, payloads, evidence or credentials. |
| Capture unavailable state | Existing capture-status badge and non-MONITORING stale-history caution are retained, alongside the summary. | A PAUSED/ERROR/OFFLINE/DEGRADED chart may contain retained historical points or timer-generated zeros; neither is presented as current traffic. |
| Screen-reader behavior | TextBlock provides a textual companion to the graphical chart; `AutomationProperties.LiveSetting="Off"` avoids deliberate per-second live-region announcements. | Actual screen-reader reading order, keyboard focus, scaling and WPF binding remain **unverified**. This is not a proven accessibility pass. |

### Source-only divergence and concurrency review

- Owned changes: `Carthago/Views/MainWindow.xaml`,
  `Carthago/Views/MainWindow.Plots.cs`, and this ledger. Existing
  `TrafficPlot`, `TrafficPlot_Analytics`, the PPS timer, rolling
  samples, ten-sample moving average, plot style, status bindings and
  responsive breakpoints remain intact.
- Original `RenderTraffic` still renders both ScottPlot instances.
  The only new source action is a bounded display-state update using
  existing `_trafficYs` and `CaptureStatusText` values.
- Inspected the latest remote head, prior UI-01–09 ledger, chart markup,
  plot and timer implementation, and independent R441–R450 changed paths.
  No UI path was changed by the concurrent detection batch.
- No changes to engine, models, services, capture/provenance, rule IDs,
  thresholds, confidence floors, runtime modes, approvals, privacy,
  journal, tests, project, workflows, Cisco, WebView2, CLI, or rule docs.
  Source-only uniqueness and changed-path checks do not constitute a
  compilation, XAML runtime, rendered-layout or accessibility pass.
- **Residual risk:** the UI timer may continue to generate zeros while
  capture is inactive; the latest sample can therefore be zero without
  proving traffic absence. A genuinely capture-qualified sample series
  would require a separate shared-producer integration proposal and
  owner approval; it is not implemented here.

### Acceptance scenarios — PLANNED ONLY, NOT AUTHORED AS TESTS, UNEXECUTED

1. Before the first timer tick: waiting overlay visible; summary says no PPS observation.
2. After exactly one tick: overlay remains; summary identifies the one timer sample.
3. After two ticks: overlay hides; original PPS line is eligible to render.
4. After 120+ ticks: retained count remains bounded to 120; no unbounded UI growth.
5. PAUSED/OFFLINE/ERROR/DEGRADED: original capture badge and caution remain visible; zero is not called a healthy capture.
6. MONITORING with zero packets: summary reports timer PPS zero without claiming sensor health.
7. MONITORING with observed packets: latest summary value matches existing timer PPS history.
8. Ten-plus samples: original ten-sample moving average and Analytics chart remain unchanged.
9. Keyboard, screen reader, high-contrast and 125–200% DPI: textual alternative and overlay remain readable; not verified.
10. Widths 1440, 1100, 1099, 1024, 1023 and 640: original responsive layout, Live Events, incidents, Cisco and CLI unavailable panel remain intact.

**Open quality GAs:** pinned-SHA Windows compilation, WPF named-element
resolution, chart visibility and actual ScottPlot rendering, capture-state
transitions, timer/plot synchronization, screen-reader reading order,
DPI and screenshot comparison with the approved reference, and full
regression when owner authorizes testing. **Tests executed: 0.**

**Next independent UI GA UI-11:** inspect LIVE HEAD and the design reference
for one cohesive accessibility/visual-consistency improvement outside
already-completed chart waiting behavior. Do not add telemetry, working CLI,
or modify the independent rule automation.

**Technical references:** [WPF AutomationProperties.LiveSetting](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.livesetting);
[WPF visibility](https://learn.microsoft.com/en-us/dotnet/api/system.windows.visibility);
[prior GA UI-09](#ga-ui-09--narrow-window-pps-chart-header-and-capture-status-readability).


## GA UI-11 — Accessible incident-triage row semantics

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Started from live
`feature/carthago-reliability-hardening` HEAD
`8bf50590e8b6c432a8748726fae41bef77e10906`, after independent detection GA R451–R460.
UI source commit: `b5504d05a7c3042a4d908211991c7c2baab91bee`.
The documentation commit is a descendant of the source commit; its
publication SHA must be taken from the live remote after the protected
non-forced update. **Automated tests authored: 0; executed: 0.**
No build, replay, CI, runner job, benchmark or production capture.

### Reference, original source and narrow accessibility contract

The exact approved Library image
`libfile_b0a34361560c8191b641e432b3e6b15c` was retrieved and
visually inspected. Its left-hand prioritized incident queue and right-hand
investigation panel remain the visual guide; the screenshot's risk scores,
IP addresses, timestamps and rule labels are demonstration content, not
production facts. This GA changes **only the incident/signal triage list's
accessible descriptions**, not its appearance, sorting, selection, or
incident linkage.

| Surface | Actual source and binding | Truthfulness/accessibility boundary |
| --- | --- | --- |
| Triage list | `DashboardAnomalyList` in `MainWindow.xaml` receives an explicit accessible name and help text explaining arrow-key selection and the existing `SelectionChanged` detail update. | Does not imply that every incident is confirmed, that scores are detection confidence, or that the screen reader has been validated. |
| Triage item | Existing `ListBoxItem` container style binds `AutomationProperties.Name` to `SocAnomalyVm.AccessibilityLabel`. The private UI-only computed property combines the **already displayed** kind, title, severity, local risk score (out of 100), subtitle, and local time. | The computed label introduces no telemetry, new incident identifiers, payload capture, data persistence, or fabricated evidence. It does not turn a signal into a correlated incident. |
| Visual/focus behavior | Existing severity rail, risk badge, item selection border, keyboard-focus border, `DashboardSignalPanel`, and selected-detail handler are unchanged. | Visual focus contrast, spoken ordering, high-DPI clipping and assistive-technology behavior remain unverified. |
| Other dashboard areas | Existing KPI strips, local PPS ScottPlot, 10-sample average/120-point history, Live Events, unavailable CLI companion, sidebar and Cisco tools remain untouched. | The approved reference's inbound/outbound Mbps lines remain demo-only; no new series or producer was introduced. |

### Static divergence, ownership and concurrency review

- **Owned source paths:** `Carthago/Views/MainWindow.xaml`,
  `Carthago/Views/MainWindow.Dashboard.cs`; this ledger is the sole
  documentation path. `SocAnomalyVm` is an existing private nested
  UI-only projection, and its consumers (`BuildSocAnomalyItems`,
  `DashboardAnomalyList`, `DashboardAnomalyList_SelectionChanged`)
  were inspected before editing.
- Compared the original UI-04 triage binding, UI-01–10 ledger, current
  WPF XAML and partials, approved reference, and the live detection
  R451–R460 changed paths. No detection batch changed UI-owned paths
  since UI-10. Existing rule IDs, modes, thresholds, confidence floors,
  approvals, privacy/journal restrictions and evidence contracts are
  unchanged.
- The list name, item binding and private computed property were each
  statically checked for a single insertion. The item label contains only
  values already present in the visible row; it adds no sensitive evidence
  fields. No UI event handler or shared API changed.
- Source-only inspection is **not** XAML parsing, WPF compilation,
  accessibility validation, screenshot comparison or runtime verification.
  Actual UI Automation exposure and possible nested-text duplication
  require owner-authorized Windows testing.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED AS TESTS; UNEXECUTED

1. Keyboard Tab reaches the triage list; arrow keys move between existing incident/signal rows.
2. Selection changes the existing investigation panel without new handlers or focus traps.
3. Screen reader announces the list purpose and non-confidence risk-score caveat.
4. Each incident row announces kind, title, severity, local risk, subtitle and local time.
5. Each anomaly signal remains identified as SIGNAL, never as a confirmed incident.
6. Long titles and endpoint subtitles remain visually truncated with existing full-text tooltips.
7. No rows: list label remains understandable and existing empty-state behavior is unchanged.
8. Risk score zero/100 and mixed severity values remain labeled local risk, not detection confidence.
9. Widths 1440, 1100, 1099, 1024, 1023 and 640, high DPI and high contrast: no new clipping/focus regression.
10. Chart PPS, Live Events filters, CLI unavailable state, navigation, Cisco and rule work remain unchanged.

**Open quality GAs:** pinned-SHA Windows WPF build; screen-reader
inspection of list-item names, focus and reading order; keyboard
navigation; high-contrast and 125–200% DPI; responsive screenshot
comparison; incident selection regression and privacy review after
explicit owner test authorization. **Tests executed: 0.**

**Next independent UI GA UI-12:** inspect the live branch and approved
reference, then consider one focused incident-investigation panel
accessibility/readability improvement. Preserve all previous UI GAs,
actual telemetry boundaries, and the separate detection automation.

**Technical references:**
[WPF AutomationProperties.Name](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.name);
[WPF layout](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/layout).
