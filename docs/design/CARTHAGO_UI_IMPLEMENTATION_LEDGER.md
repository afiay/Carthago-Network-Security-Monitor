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
