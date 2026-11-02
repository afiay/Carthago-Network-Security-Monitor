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

## GA UI-12 — Labeled investigation facts and reported-evidence boundary

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE
`feature/carthago-reliability-hardening` HEAD:
`db6efac2dfbb6e8fa1ab233ee8e68174f12328d4` (independent detection R461–R470 already present).
UI source commit: `1f2c342110080b21632703202c52834306b988f2`.
The documentation/publication commit is the direct descendant of this
source commit and is the final branch HEAD after the expected-HEAD-protected
atomic update. **Tests authored: 0; tests executed: 0.** No build,
replay, holdout, CI, runner, benchmark or production capture.

### Scope, original consumers and reference mapping

The exact approved 1648×928 Library reference
`libfile_b0a34361560c8191b641e432b3e6b15c` was resolved and visually
inspected. Its right-hand Incident Investigation panel is the design guide;
its sample confidence scores, endpoints, timestamps and evidence chain are
**demo-only**, not validated Carthago observations.

This GA makes one focused **accessibility-label association** change to
the existing investigation panel. The six visible field captions are given
stable WPF names, and their existing read-only value TextBlocks reference
them using `AutomationProperties.LabeledBy` with `ElementName` binding:

| Existing caption | New caption name | Existing live value |
| --- | --- | --- |
| Source host | `DashboardDetailSourceLabel` | `DashboardDetailSourceText` |
| Destination | `DashboardDetailDestinationLabel` | `DashboardDetailDestinationText` |
| Protocol / port | `DashboardDetailProtocolLabel` | `DashboardDetailProtocolText` |
| Category | `DashboardDetailCategoryLabel` | `DashboardDetailCategoryText` |
| Detected | `DashboardDetailDetectedLabel` | `DashboardDetailDetectedText` |
| Related incident | `DashboardDetailRelatedIncidentLabel` | `DashboardDetailRelatedIncidentText` |
| Evidence provenance (reported, not verified) | `DashboardDetailEvidenceSummaryLabel` | `DashboardDetailEvidenceSummaryText` |

The original `DashboardAnomalyList_SelectionChanged` →
`UpdateSocSignalDetails` → `CreateDashboardSignalDetailModel` path was
inspected. The seven value TextBlocks retain their original names, text
assignments, truncation and full-value tooltips (where present). No new
value, telemetry, incident correlation, selection handler, automation
announcement, clipboard/export, or evidence producer is introduced.
The evidence text continues to be populated **only** from a directly
selected correlated incident; a selected anomaly signal alone cannot
establish incident evidence. The label explicitly says **reported, not
verified**. WPF UI Automation exposure of labels for non-focusable
TextBlocks and possible spoken duplication remain unverified.

### Source-only divergence and concurrency review

- **Owned files:** `Carthago/Views/MainWindow.xaml` and this ledger.
  No C# code-behind, UI viewmodel, theme, responsive logic or project
  contract changed. The prior UI-01–11 components, sidebar, KPI strips,
  real local PPS ScottPlot, ten-sample average, 120-point history,
  incident queue, Live Events, unavailable CLI and Cisco controls are
  preserved.
- Previous UI-11 HEAD: `d061bdb276629917f1e63c83507f2af8f27f3b47`.
  The current start HEAD includes three intervening independent detection
  commits, changing only `Carthago.Tests/**`, `Carthago/Engine/**`,
  `docs/RULE_BATCH_461-470.md` and
  `docs/RULE_HARDENING_PROGRESS.md`. No overlap with UI-owned paths.
- Static candidate inspection: seven unique caption `x:Name` values,
  seven corresponding `ElementName` associations, no duplicate XAML
  names, no changed `x:Name` of any value control, no new handlers,
  no hard-coded endpoint or score. Existing alert/rule modes, thresholds,
  confidence floors, evidence provenance, privacy and approvals untouched.
- The approved reference's side-by-side panel geometry and dark
  navy/cyan/amber visual language are unchanged; this GA changes
  accessibility metadata only. It does not claim a screenshot match.
- Source inspection is **not** XAML compilation, runtime binding
  verification, UIA tree inspection or an accessibility pass. A named
  label may be announced separately or duplicated by a screen reader;
  verify with Windows assistive technology when testing is authorized.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED AS TESTS; UNEXECUTED

1. Each of the six read-only fact values exposes its corresponding
   existing caption through UI Automation without suppressing the value.
2. Evidence summary exposes its explicit **reported, not verified** caption.
3. Selecting a correlated incident refreshes the seven existing values
   and their label associations without a stale-label announcement.
4. Selecting an anomaly signal does not imply authenticated incident
   evidence, confirmed rule attribution or detection confidence.
5. Empty/no-selection state retains em dashes and honest evidence absence.
6. Very long IPv6, hostname and protocol values remain truncated visually,
   with their existing full-value tooltips and no extra UI overflow.
7. Keyboard selection, investigation buttons and detail dialog navigation
   remain unchanged; no focus trap or added live announcement.
8. High contrast, 125–200% DPI and 1440/1100/1099/1024/1023/640px
   widths preserve the original investigation layout and captions.
9. The existing incident risk ring stays a **local risk score**, never
   represented as a validated detection-confidence percentage.
10. No changes to PPS history, Live Events filters, CLI unavailable
    state, Cisco, privacy-sensitive evidence or detection engineering.

**Open quality GAs:** pinned-SHA Windows WPF compilation, ElementName
resolution, actual UIA Name/LabeledBy exposure, keyboard and screen-reader
reading order, no duplicate spoken captions, DPI/high-contrast rendering,
responsive screenshot comparison, incident selection and evidence/privacy
regression. **Executed tests: 0.**

**Next independent UI GA UI-13:** inspect the live branch, approved image
and current ledger, then choose one bounded UI-owned readability or
accessibility improvement outside the completed investigation label
association. No working CLI, invented telemetry, or shared API changes.

**Technical reference:**
[Microsoft WPF accessible name from a nearby TextBlock](https://learn.microsoft.com/en-us/accessibility-tools-docs/items/wpf/edit_name);
[WPF layout](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/layout).

## GA UI-13 — Live Events accessibility provenance and current grid status

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE
`feature/carthago-reliability-hardening` HEAD:
`a49134b2582875d74431b1768e4a1bc215dc3700` (independent R471–R480 already published).
UI source commit: `8066325a1c375c61b38dcc7740ca922f25add32c`. The docs/publication commit is a direct
descendant and is identified by the protected remote branch ref after
publication. **Automated tests authored: 0; executed: 0.** No builds,
xUnit, replays, holdouts, CI, runners, benchmarks, live capture or running
application screenshots were performed.

### Reference mapping and source contracts

The exact approved 1648×928 Library image
`libfile_b0a34361560c8191b641e432b3e6b15c` was resolved and
visually inspected. Its lower **Live Events** table is the reference for
dense, legible incident-adjacent tabular information, but the image's
endpoints, timestamps, rule IDs, confidence and evidence-chain entries are
**demo-only**. This GA adds **accessibility semantics only** to the existing
read-only `DashboardLiveEventsGrid` in `Carthago/Views/MainWindow.xaml`:

| Existing element | UI-only change | Evidence/accessibility boundary |
| --- | --- | --- |
| `DashboardLiveEventsGrid` | Retains its accessible name; adds `AutomationProperties.HelpText` explaining the 80-row display bound, unverified recorded-event timezone, evidence reported presence/count only, and delivery status versus incident resolution. | The original `DashboardEventRowVm` projection reads local `DetectionEvent` data. No payload, raw evidence, chain-of-custody, transport success or resolution is inferred. |
| `DashboardLiveEventsGrid` | `AutomationProperties.ItemStatus` binds to the **existing** `DashboardLiveEventsStatusText.Text` using `ElementName`. | Reuses the existing displayed count, retained 500 cap, newest-received-first ordering and capture caption. It does not claim a globally complete event history or authenticated capture health. |
| `DashboardLiveEventsStatusText` | Explicit `AutomationProperties.LiveSetting="Off"`. | Existing refreshes may update the text; the GA does not deliberately request repeated live announcements. Actual UIA exposure/announcement behavior is **unverified**. |

The original `InitializeDashboardLiveEvents`, `RefreshDashboardLiveEvents`,
`DashboardLiveEventsFilterChanged`, `DashboardLiveEventsTextChanged`,
`DashboardLiveEventsClearFilters_Click`, and `DashboardLiveEventsOpenDetections_Click`
consumers were read before editing. All existing controls, names, column
bindings, filter handlers, 80-row projection, 500-event retention text,
selection behavior, virtualization and empty-state labels are unchanged.
The UI remains a read-only local detection table, not a confirmed incident
or verified evidence-chain viewer. No demo metrics or unsupported Mbps
series were added.

### Start/end static divergence and concurrency review

- Start HEAD `a49134b2582875d74431b1768e4a1bc215dc3700`
  is three commits ahead of UI-12 publication
  `69c92a8065c3d280129190615f697a0a6c753e34`.
  The intervening R471–R480 changes are confined to
  `Carthago.Tests/**`, `Carthago/Engine/**` and detection docs;
  no UI-owned path overlaps.
- **Owned source file:** `Carthago/Views/MainWindow.xaml`.
  **Owned documentation file:** this ledger. No shared model,
  service, engine, rules, capture, privacy, journal, confidence,
  thresholds, approvals, project, tests, Cisco, WebView2, ScottPlot,
  navigation or CLI code was modified.
- Source-only checks confirm unique `DashboardLiveEventsGrid` and
  `DashboardLiveEventsStatusText` names, a single added `ItemStatus`
  ElementName binding, and preservation of the original `DataGrid`
  column definitions and event handlers. The approved dark navy/cyan
  card geometry and all responsive breakpoints remain unchanged.
- **Residual risks:** WPF ElementName resolution, UI Automation
  `ItemStatus` exposure, screen-reader announcement timing and
  possible duplication of the visible status footer have **not**
  been verified. Static review is not compilation, XAML parsing,
  runtime UIA inspection, accessibility certification or visual validation.
  The recorded event timestamp's timezone is not independently verified.

### Acceptance scenarios — PLANNED ONLY; UNEXECUTED

1. With no local detection events, the existing honest empty message remains visible and grid help does not imply active capture.
2. With one local event, the grid status reflects the same existing displayed/retained counts as the footer.
3. With more than 80 matches, the UIA grid status and visible footer report only the bounded displayed count; no full-history claim.
4. With 500 retained events, the original retention cap and newest-received-first caption remain unchanged.
5. After severity/protocol/rule/endpoint filters, the grid status follows the original filtered count without changing results.
6. When demo mode is enabled, the existing demo provenance warning remains visible and no event is presented as independently validated.
7. Evidence presence/count does not reveal raw evidence or imply chain-of-custody; delivery is not read as incident resolution.
8. MONITORING/DEGRADED/PAUSED/OFFLINE/ERROR state changes retain original capture caveats; a timer zero never proves health.
9. Keyboard, screen reader, UIA inspection, high contrast, 125–200% DPI and 1440/1100/1099/1024/1023/640px widths show no clipping, focus trap or repeated live announcements.
10. Incident selection, local PPS chart/average/history, AlertsGrid filters, CLI unavailable panel, Cisco and detection rule operation remain unchanged.

**Open quality GAs:** owner-authorized pinned-SHA Windows WPF build,
ElementName binding verification, UIA ItemStatus and HelpText inspection,
screen-reader/keyboard review, responsive screenshots, capture/demo
transitions, and regressions. **Tests executed: 0.**

**Next independent UI GA UI-14:** inspect LIVE HEAD, reference and ledger
for one focused Live Events keyboard/focus or narrow-width readability
improvement, only if safe and not already implemented. Preserve all
evidence boundaries and independent detection engineering.

**Technical references:**
[WPF AutomationProperties](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties);
[WPF LiveSetting](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.livesetting);
[WPF UIA ItemStatus](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationelement.automationelementinformation.itemstatus).

## GA UI-14 — Live Events frozen time column for narrow-window readability

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE
`feature/carthago-reliability-hardening` HEAD:
`b5751b666f2a9e8b1fc4fb98b3545cfac6e3a6cf` (independent detection R481–R490 already present).
UI source commit: `a9605edefb6bb8a6ba5113957cef5237fc34b77e`.
The documentation/publication commit descends directly from this source
commit; read the protected remote branch ref for its publication SHA.
**Automated tests authored: 0; executed: 0.** No build, test, replay,
holdout, CI, runner, benchmark or production capture.

### Reference, existing source and one narrow change

The exact approved Library reference
`libfile_b0a34361560c8191b641e432b3e6b15c` was resolved and
visually inspected. Its lower Live Events table has a persistent time
column alongside horizontally dense event facts. The screenshot's event
values, rule IDs, endpoints, evidence chains and Mbps figures are
**demo-only**. This GA does not copy any of those values.

The original `DashboardLiveEventsGrid` in
`Carthago/Views/MainWindow.xaml` is a read-only eight-column WPF
`DataGrid` with automatic horizontal scrolling and virtualization.
At narrow widths, its fixed/minimum column widths exceed the available
viewport. The first **Event time** column is fixed at 144 pixels.
The UI-only change sets `FrozenColumnCount="1"`, preserving the first
column while the other seven columns scroll horizontally. Existing
`AutomationProperties.HelpText` now describes this navigation affordance
and retains the explicit timezone, evidence and delivery caveats.
The table's dark navy/graphite/cyan theme, headers, order, data bindings,
filter controls, empty state, selection, and read-only behavior are
unchanged.

| Surface | Actual source/binding | Evidence and UX boundary |
| --- | --- | --- |
| Frozen first column | Existing `Event time` binding to `DashboardEventRowVm.EventTime` | Displays `DetectionEvent.Timestamp` as recorded; timezone **unverified**. Freezing does not authenticate or correct timestamps. |
| Remaining columns | Existing Source, Destination, Rule, Severity, Protocol, Evidence and Delivery bindings | Same 80-row filtered projection from local detections, 500-event retention, no raw evidence rendering. |
| Grid keyboard/help semantics | Existing DataGrid navigation and horizontal scrollbar; amended HelpText | No new keyboard handler, focus trap, custom automation peer, or assertion that assistive technology has been tested. |
| Capture/demo and status | Existing `DashboardLiveEventsStatusText`, `DashboardLiveEventsProvenanceText` and UI-13 ItemStatus | Counts, capture warnings, demo provenance and delivery-versus-resolution distinction unchanged. |

### Static divergence, ownership and concurrency review

- The previous UI-13 publication HEAD
  `360485f90804f13ae922ef255afcd9561e383939`
  is an ancestor of this GA's starting HEAD. The three intervening
  R481–R490 commits changed only `Carthago/Engine/**`,
  `Carthago.Tests/**` and rule documentation; no UI path overlap.
- **Only source path:** `Carthago/Views/MainWindow.xaml`.
  **Only docs path:** this ledger. The original UI-05
  `DashboardEventRowVm`, `InitializeDashboardLiveEvents`,
  `RefreshDashboardLiveEvents`, filter handlers, capture/demo status
  and row limits were inspected; none were changed.
- Static checks: one `DashboardLiveEventsGrid`, one frozen-column
  declaration, the same eight `DataGridTextColumn` bindings and order,
  original `IsReadOnly=True`, single-row selection, virtualizing panels
  and automatic horizontal/vertical scrollbars. No new named elements,
  event handlers, WPF partials, dependencies or shared contracts.
- No detection rules, rule profiles/modes/thresholds/confidence,
  evidence, journal, privacy, approval controls, telemetry producers,
  Cisco/WebView2/ScottPlot, PPS chart, CLI or automation settings changed.
  This is a source-only review, **not** a WPF compile, layout measurement,
  keyboard test, screen-reader pass or screenshot comparison.
- **Residual risks:** WPF frozen-column behavior under keyboard navigation,
  column reordering, high DPI, tiny viewports and horizontal scrolling is
  unverified. A fixed 144px first column reduces the remaining visible
  width; retain the scrollbar rather than hiding data. Event timestamp
  timezone and capture health remain unverified by this UI change.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED AS TESTS; UNEXECUTED

1. At 1440px, the original eight-column table and theme remain intact.
2. At 1100px and 1099px, horizontal scrolling retains Event time visibility.
3. At 1024px and 1023px, Event time stays visible while Source/Destination scroll.
4. At 640px and 125–200% DPI, the first column does not prevent access to the other seven.
5. Tab and DataGrid arrow-key navigation reach all columns without trapping focus.
6. Screen-reader/UIA inspection announces the grid help and does not falsely imply verified timezone or evidence.
7. User column reordering and keyboard navigation do not silently change the meaning of the frozen column.
8. Empty table, filtered zero matches and 80-row bound preserve the existing messages and row counts.
9. 500 retained events, demo mode and non-monitoring capture status retain original provenance and warning text.
10. PPS chart, incident triage/investigation, unavailable CLI, AlertsGrid filters, Cisco and independent rule work remain unchanged.

**Open quality GAs:** pinned-SHA Windows WPF build, actual frozen-column
layout/scrolling, keyboard and UI Automation inspection, high contrast,
DPI and responsive screenshot comparison, capture/demo and filter
regression after owner authorizes testing. **Tests executed: 0.**

**Next independent UI GA UI-15:** inspect the live branch, approved
reference and ledger for one bounded UI-owned accessibility or visual
consistency improvement outside this frozen-column change. Do not invent
telemetry or modify the independent rule automation.

**Technical reference:**
[Microsoft WPF DataGrid.FrozenColumnCount](https://learn.microsoft.com/en-us/dotnet/api/system.windows.controls.datagrid.frozencolumncount);
[WPF DataGrid overview](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/controls/datagrid).

## GA UI-15 — Live Events keyboard-focus visibility

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE
`feature/carthago-reliability-hardening` HEAD: `67555a84575f7c1d7184d5d07cfc89bc3ba574a9`.
UI source commit: `480568e8b3a2e4e039b3da4db21c87ea7c36c384`. Documentation/publication commit
is the direct descendant of this source commit, confirmed from the
protected remote branch after publication. **Tests authored: 0; executed: 0.**
No builds, xUnit, replays, holdouts, CI, runners, benchmarks, screenshots,
or production capture were performed.

### Approved reference, existing consumers and bounded change

The exact approved Library image
`libfile_b0a34361560c8191b641e432b3e6b15c` was resolved and visually
inspected. Its dark navy/graphite Live Events table uses restrained cyan
navigation emphasis. Its metrics, endpoints, rule IDs, timestamps,
confidence and Mbps series are **demo-only**, not Carthago telemetry.

Source inspection of `Carthago/Views/MainWindow.xaml` and
`Carthago/Views/Theme.xaml` confirmed the existing implicit `DataGridCell`
style and the shared `KeyboardFocusVisual` theme resource, whose outline
uses `KeyboardFocusBrush`. This GA adds a **grid-scoped**
`DataGrid.CellStyle` that inherits the original implicit cell style and
sets `FocusVisualStyle` to that existing resource. WPF focus visuals are
intended to indicate **keyboard** focus, not assert selection, alert
confidence or detection status. No custom focus handler, new UI model,
renderer, telemetry producer, or global DataGrid style was introduced.

| Surface | Actual binding / UI behavior | Boundary |
| --- | --- | --- |
| `DashboardLiveEventsGrid` cells | Existing eight read-only `DashboardEventRowVm` columns and WPF keyboard navigation; only keyboard-focus visual style is scoped to this grid. | No new data, row selection, keyboard command or event handler. Visual focus behavior is unverified. |
| Time and other columns | Existing frozen 144px Event time and seven horizontally scrollable columns. | Recorded timestamp timezone remains unverified; source/destination/rule/evidence/delivery values remain unchanged. |
| Theme and reference | Reuses `KeyboardFocusVisual` and `KeyboardFocusBrush` from `Theme.xaml`; no palette or geometry change. | Dark navy/teal composition preserved by source intent, not by a rendered screenshot. |
| Status and provenance | Existing 80-row display limit, 500-event retention, filtering, ItemStatus, demo and capture warnings. | Evidence is presence/count, not verified custody; delivery is not incident resolution; timer zero is not capture health. |

### Static divergence, ownership and concurrency

- Previous GA UI-14 publication: `316004fc4fe176ee3250add7c530282d3af30396`.
  Live starting HEAD `67555a84575f7c1d7184d5d07cfc89bc3ba574a9` includes independent detection commits;
  compared changed paths against UI ownership before editing. Only
  `Carthago/Views/MainWindow.xaml` and this ledger are changed by UI-15.
- The new cell style inherits the original implicit `DataGridCell` style,
  reuses the existing keyboard focus resource, and leaves row hover,
  selection, read-only behavior, virtualization, column order, filters,
  handlers, event projections, capture state and empty-state text intact.
- No changes to `Engine/**`, `Models/**`, `Services/**`, tests,
  detection rules, thresholds/confidence, privacy, capture, journal,
  approvals, Cisco, WebView2, ScottPlot PPS history, CLI, shared APIs,
  project files, workflows, or the detection automation.
- Source-only checks verify a single new scoped cell style, one original
  `DashboardLiveEventsGrid`, unchanged frozen first column, unchanged
  eight columns and no changed WPF partials. **These checks do not prove
  XAML compilation, keyboard focus rendering, screen-reader accessibility,
  high contrast, or screenshot fidelity.**
- **Residual risk:** WPF focus adorners may clip within recycled cells or
  tight 27px rows; theme focus ring and row selection may visually compete.
  Verify keyboard-only focus versus mouse focus and high-contrast/DPI
  behavior when testing is authorized. No unsupported capture or evidence
  assertion is added.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Tab from Live Events filters into the read-only grid and verify the keyboard focus outline is visible.
2. Move with arrow keys between cells and confirm focus follows the active cell without stale outlines.
3. Click a cell with the mouse and verify no misleading keyboard-only focus indicator is required.
4. Scroll horizontally and ensure the 144px frozen Event time column remains visible with navigable focus.
5. At 1440/1100/1099/1024/1023/640px widths, focus does not obscure cell values or the scrollbar.
6. At 125–200% DPI and high-contrast mode, keyboard focus remains distinguishable from selection and severity.
7. With zero events, the honest empty state remains and no fake focused row is announced.
8. With 80 displayed and 500 retained events, virtualization/recycling does not leave stale focus adorners.
9. Filter severity/protocol/rule/endpoints and confirm counts, evidence and delivery caveats remain truthful.
10. Confirm the PPS chart, incident investigation, unavailable CLI, Cisco, capture state and independent rule behavior remain unchanged.

**Open quality GAs:** pinned-SHA Windows WPF build, keyboard focus and
screen-reader/UIA inspection, high contrast, DPI, responsive screenshots,
filter/virtualization regressions, and reference comparison after explicit
owner test authorization. **Executed tests: 0.**

**Next independent UI GA UI-16:** inspect LIVE HEAD, approved reference and
ledger; choose one new, bounded UI-owned readability/accessibility
improvement outside completed UI-01–15, preserving evidence boundaries.

**Technical references:**
[Microsoft WPF FocusVisualStyle](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/styling-for-focus-in-controls-and-focusvisualstyle);
[WPF DataGrid overview](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/controls/datagrid).

## GA UI-16 — Visible labels for Live Events free-text filters

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE
`feature/carthago-reliability-hardening` HEAD:
`afe874bb3537a80e6de56799d440ef090c0c6d4f` (independent R501–R510 detection candidate already present).
**UI source commit:** `fe17db0d8e915a4f420d2db0b02fd86e37955c53`. The documentation commit descends from
that source commit and is the publication commit when the remote branch is
updated with its exact expected-HEAD lease. **Tests authored: 0; executed: 0.**
No build, WPF runtime, screenshot, xUnit, replay, holdout, CI, runner,
benchmark or production capture was executed.

### Approved reference, source audit and bounded improvement

The exact approved Library image
`libfile_b0a34361560c8191b641e432b3e6b15c` was resolved and
visually inspected. Its lower Live Events filter/search row has clearly
identified controls; the image's IPs, timestamps, rule IDs, confidence,
metrics and Mbps series are **demo-only**. No screenshot values were
introduced.

The original `DashboardLiveEventsGrid` and the existing
`DashboardLiveSeverityFilter`, `DashboardLiveProtocolFilter`,
`DashboardLiveRuleFilter` and `DashboardLiveSearchFilter` controls were
source-audited along with their consumers in
`MainWindow.DashboardEvents.cs`. The two free-text filters previously
had only ToolTip and UI Automation names, leaving blank inputs visually
ambiguous. This GA adds compact, visible **Rule** and **Search** captions
in the existing `WrapPanel`, with each `TextBox` retaining its
`x:Name`, `TextChanged` handler, ToolTip and accessible name.
The captions are associated via `AutomationProperties.LabeledBy`,
reusing the same WPF pattern as GA UI-12. The surrounding horizontal
`StackPanel` containers do not add keyboard-focus targets or modify
filter logic. Entry widths are now 90px (rule) and 182px (search) to
limit additional horizontal density; all input text and existing
filter semantics remain unchanged.

| Surface | Actual binding / behavior | Evidence boundary |
| --- | --- | --- |
| Rule caption and input | `DashboardLiveRuleFilter.Text` still filters exact/partial local rule ID in `RefreshDashboardLiveEvents`. | No claim that a rule ID is a verified malicious behavior; no new parser. |
| Search caption and input | `DashboardLiveSearchFilter.Text` still filters visible event source, destination, rule or protocol. | No evidence payload search, packet inspection or new telemetry. |
| Severity/protocol selectors | Existing selection tags and handlers unchanged. | Only actual local detection-event projection, not confirmed incidents. |
| Live Events grid/status | Existing eight columns, frozen Event time, read-only virtualization, 80 visible rows, 500 retained events, filtering, capture/demo status and evidence/delivery warnings. | Recorded timestamp timezone is unverified; reported evidence count is not custody; delivery is not resolution. |
| Dashboard and reference | Existing dark navy/graphite, muted captions and cyan keyboard-focus treatment reused. | Reference fidelity is source-intent only, not a screenshot comparison. |

### Static divergence, ownership and concurrency review

- Previous GA UI-15 publication HEAD
  `fd8d2e3d11bfefa9f076f6f86607231ebadee235`
  is an ancestor of the starting live HEAD. The intervening R501–R510
  changes affect detection engine/tests/rule docs, not the owned UI paths.
- **Only UI source path:** `Carthago/Views/MainWindow.xaml`.
  **Only documentation path:** this ledger.
  Original filter consumers in `MainWindow.DashboardEvents.cs` were
  read but not edited; both existing `TextChanged` bindings are retained.
- Source-only checks: each existing text-filter `x:Name` occurs once,
  each new label `x:Name` occurs once, the original DataGrid remains
  unique with its frozen time column, and no new event handlers,
  telemetry/model/service contracts or UI view models were introduced.
  Original severity/protocol selectors, capture controls, Cisco,
  WebView2, ScottPlot PPS history, incident investigation, visual-only
  CLI, privacy and rule profiles are untouched.
- **Residual risks:** visible captions modestly increase filter-row
  width and may trigger earlier `WrapPanel` wrapping at narrow widths.
  The 90px rule input may show less of a long value without scrolling.
  WPF `LabeledBy` resolution, keyboard reading order, high contrast,
  DPI and actual visual density remain **unverified**. No accuracy,
  compilation, accessibility or rendering pass is claimed.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. With empty filters, both Rule and Search captions are visible and distinguishable.
2. Tab through severity, protocol, rule, search and clear controls without new focus stops.
3. UIA/screen reader associates Rule and Search captions with the correct inputs.
4. Typing an exact rule ID preserves the original filtered event set.
5. Typing a partial rule ID preserves case/substring behavior and clear/reset.
6. Search source/destination/protocol and confirm evidence payload is not searched.
7. At 1440, 1100, 1099, 1024, 1023 and 640px widths, the filter row wraps without clipping.
8. At 125–200% DPI and high contrast, captions and input text remain legible.
9. Empty, 80 displayed and 500 retained event states preserve truthful counts, capture/demo and delivery caveats.
10. Confirm the frozen Event time, keyboard cell focus, PPS chart, incident panels, unavailable CLI, Cisco and independent rule work are unchanged.

**Open quality GAs:** pinned-SHA Windows WPF build; actual filter,
keyboard/UIA and high-contrast/DPI inspection; responsive screenshots;
event filtering, virtualization, capture/demo and status regressions
after explicit owner test authorization. **Executed tests: 0.**

**Next independent UI GA UI-17:** inspect LIVE HEAD, approved reference,
ledger and original WPF source for one bounded accessibility/readability
improvement outside completed UI-01–16. Keep all telemetry/evidence
boundaries and the independent detection stream intact.

**Technical references:**
[WPF AutomationProperties.LabeledBy](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.labeledby);
[WPF StackPanel](https://learn.microsoft.com/en-us/dotnet/api/system.windows.controls.stackpanel);
[WPF layout](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/layout).

## GA UI-17 — Dashboard KPI value-label associations

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE
`feature/carthago-reliability-hardening` HEAD:
`f72eb891581776b72fd5b8001e266d3597167d06` (independent R511–R520
detection candidate and fixture correction present).
**UI source commit:** `1424122197651913674e1a982056169e31fbec01`.
**Tests authored: 0; executed: 0.** No builds, xUnit, replays,
holdouts, CI, runners, benchmarks, WPF runtime, screenshots or production
capture were executed.

### Approved reference, real producers and bounded improvement

The exact approved Library reference
`libfile_b0a34361560c8191b641e432b3e6b15c` was resolved and
visually inspected. It presents four captioned KPI cards with dark navy
surfaces, muted labels and cyan/teal emphasis. Its Mbps, sensor counts,
coverage percentage, incident counts, rule IDs, addresses and confidence
figures are **demo-only**, not evidence for this implementation.

Source inspection of `MainWindow.xaml`,
`MainWindow.Dashboard.cs` and `MainWindow.DashboardResponsive.cs`
confirmed that `DashboardKpiCardTemplate` is shared by the four
operational overview metrics and preference-controlled additional metrics.
Its title and value were separate visual `TextBlock` elements. This GA
names the existing template title `DashboardKpiCardTitle` and associates
the existing value with it using `AutomationProperties.LabeledBy`.
Both metric collections receive static, neutral accessibility group names.
There is **no** new value formatter, dynamic accessibility announcement,
UI model, handler, telemetry producer or layout change.

| Surface | Actual data and UI behavior | Evidence boundary |
| --- | --- | --- |
| Overview KPI cards | Existing `BuildSocOverviewKpis`: locally observed throughput when available; unavailable sensor inventory and detection coverage; bounded recent correlated incident count. | No invented inventory, coverage denominator, global incident count or verified capture health. Demo mode may contribute to incident snapshot. |
| Additional KPI cards | Existing `BuildSocKpis` and user preferences; existing title/value/delta/trend and icon. | Local snapshots, baseline status and trend glyphs remain exactly as before; no inferred accuracy or validated confidence. |
| Shared value caption | The value `TextBlock` references its same-template title via `AutomationProperties.LabeledBy`. | Intended screen-reader context; actual UI Automation name resolution and reading order remain unverified. |
| Group names | `DashboardOverviewKpiItemsControl`: “Security overview metric cards”; `DashboardKpiItemsControl`: “Additional dashboard metric cards”. | Static labels describe layout only; no new metric or health claim. |
| Visual composition | Existing 102px card, typography, gradient, accents, tooltips and approved Wide/Standard/Compact/narrow panels remain unchanged. | Reference fidelity is source intent only, not a rendered comparison. |

### Static divergence, ownership and concurrency review

- Previous UI GA UI-16 publication: `0e03f6975501c4cad08d13b21968b5f2bf245f32`.
  Live starting HEAD `f72eb891581776b72fd5b8001e266d3597167d06`
  is five commits ahead; its six changed paths are detection engine,
  tests and rule documentation only, with **no overlap** with UI-owned paths.
- **Only source path:** `Carthago/Views/MainWindow.xaml`.
  **Only documentation path:** this ledger. The existing
  `SocKpiVm`, `BuildSocOverviewKpis`, `BuildSocKpis` and
  `UpdateDashboardOverviewThroughput` consumers were inspected but
  not edited.
- Source-only review confirms one title name and one value label
  association inside the shared template, plus one accessible name
  for each existing KPI collection. The original bindings,
  `DashboardKpiCardTemplate`, card geometry, throughput updates,
  status, baseline and all responsive breakpoints are preserved.
  No modifications to engine/models/services, rule profiles,
  thresholds, confidence floors, privacy, journal, approvals,
  tests, capture, Cisco, WebView2, ScottPlot, visual-only CLI,
  shared APIs, project files, workflows or the detection automation.
- **Residual risks:** the WPF `ElementName` binding inside the
  `DataTemplate` may expose a different UIA name/reading order than
  intended; shared-template additional KPI trends include glyphs
  that are not verbalized by this change. Group names may or may not
  be surfaced by the selected screen reader. Validate with Windows
  UI Automation tools when the owner authorizes testing.
  This source review is **not** a compilation, accessibility or
  screenshot-fidelity pass.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Screen reader identifies each of the four overview KPI values with its own visible title, not another card's title.
2. Overview throughput unavailable, paused, monitoring and degraded states preserve original values/captions and truthful capture caveats.
3. Sensor inventory and coverage display “—” with their original unavailable explanations, without invented denominators.
4. Open Incidents reads as a bounded recent correlated count, with demo warning when demo mode is enabled.
5. Additional preference-controlled KPI cards retain their title/value associations when widgets are toggled or reordered.
6. Repeated throughput updates do not trigger unsolicited live announcements or stale accessible values.
7. At 1440, 1100, 1099, 1024, 1023 and 640px widths, titles and values remain legible and associated with the correct cards.
8. At 125–200% DPI and high contrast, the existing cyan/teal accents and muted captions remain readable.
9. Keyboard traversal and UIA reading order do not create extra focus stops or suppress existing title/value/trend content.
10. PPS chart, prioritized incidents, investigation, read-only Live Events, unavailable CLI, Cisco and independent rule work remain unchanged.

**Open quality GAs:** pinned-SHA Windows WPF build; UI Automation
and screen-reader label resolution; high contrast/DPI and responsive
screenshots; capture/demo, preference, incident and chart regressions
after explicit owner test authorization. **Executed tests: 0.**

**Next independent UI GA UI-18:** inspect LIVE HEAD, approved reference,
ledger and actual WPF consumers for one new, bounded accessibility,
readability or visual-consistency improvement outside UI-01–17.

**Technical references:**
[WPF AutomationProperties.LabeledBy](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.labeledby);
[WPF DataTemplate](https://learn.microsoft.com/en-us/dotnet/api/system.windows.datatemplate);
[WPF layout](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/layout).

## GA UI-18 — High-risk host row context and honest related-item counts

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE
`feature/carthago-reliability-hardening` HEAD:
`6b7975c131b6dcfc0817b792bb9ef6524cd18235` (independent R521–R530 detection and protocol GA P0001–P0010
candidates present). Previous UI-17 publication:
`3eefe8873fcfb2156ea8badbf4a8676b7cdbba02`.
**UI source commit:** `1bd422567f31c1c4823b3d334f617e701ee75122`.
**Tests authored: 0; tests executed: 0.** No builds, xUnit, replays,
holdouts, CI, runners, benchmarks, running WPF, screenshots or production
capture. Publication is a single expected-HEAD-protected, non-forced
ref update for this source commit plus its documentation descendant.

### Reference mapping, existing consumers and evidence contract

The exact approved Library image
`libfile_b0a34361560c8191b641e432b3e6b15c` was resolved and
visually inspected. Its compact host/incident visual language is a
design reference only; screenshot addresses, risk/confidence percentages,
rule mappings, Mbps and incident counts are **demonstration data**.

Existing `DashboardHostItemsControl` binds to the private
`_dashboardHostRows` collection populated by `BuildSocHostRows`
in `MainWindow.Dashboard.cs`. The first source is up to five hosts
from locally correlated active incidents, grouped by source address,
with maximum **local risk score** and group count. Only when no
incident hosts are available, the method falls back to grouped local
anomaly signals and their normalized **local risk scores**. In the
fallback, the existing `ActiveIncidents` property actually holds an
**anomaly-signal count**, not an incident count. This GA corrects the
visible column caption from `Inc.` to **Items**, and adds a tooltip
explaining the two sources; it does not change the underlying count.

The existing host display `TextBlock` receives a UI Automation name
from a private `SocHostVm.AccessibilityLabel`, using the already-held
full host identifier, local risk score and count, plus a source-kind
descriptor (correlated incident vs anomaly signal) set in the two
existing UI projection branches. The compact on-screen host display,
full-host tooltip, risk colors, trend glyph, sorting, five-row bound,
navigation action and all event handlers remain unchanged.
`DashboardHostItemsControl` receives a neutral accessibility name
and HelpText explaining the fallback and that local risk is **not
detection confidence**. No new telemetry, capture-health claim,
remote host lookup, logging or external data export is introduced.
UI Automation exposure of an already displayed/tooltip-accessible
host address still warrants privacy and assistive-technology review.

### Owned files, static divergence and concurrency

- `Carthago/Views/MainWindow.xaml` — rename one column caption to
  Items, add its tooltip, name/help for the existing host collection
  and an accessible name binding on its existing host `TextBlock`.
- `Carthago/Views/MainWindow.Dashboard.cs` — add UI-only
  `RelatedItemKind` and computed `AccessibilityLabel` to private
  `SocHostVm`; distinguish the two already-existing projection
  branches without modifying their source data or ranking.
- `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` — source
  provenance, limitations, scenario inventory and next GA.

Start-of-GA compare of UI-17 publication with live HEAD found four
disjoint commits touching detection engine/tests/docs and protocol
intelligence/services/tests/docs, not UI paths. Static source inspection
found one existing host ItemsControl, one host display binding, two
source-kind initializers, no new handler, no changed shared API or
serialized model. The dark navy/graphite, cyan/teal, severity colors,
Wide ≥1440 / Standard 1100–1439 / Compact 1024–1099 and below-1024
layout paths are unchanged. The local PPS ScottPlot, KPI values,
prioritized incidents, investigation, read-only Live Events (80 shown,
500 retained), unavailable visual-only CLI, Cisco/WebView2, privacy,
capture/trust, rules and all independent automation settings are
untouched. Source inspection does **not** prove WPF compilation,
UIA exposure, visual fidelity, focus order or data accuracy.

**Residual risks:** screen readers may announce both the host
accessible name and neighboring score/count TextBlocks; the full host
identifier can contain sensitive local addresses already available in
the UI tooltip. The column's abbreviated source context requires
reading the tooltip/help; no incident-vs-anomaly badge is added.
At narrow widths and high DPI, the slightly longer Items caption may
affect header density. These remain unverified.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Active correlated incident hosts: row name says correlated incidents and reports the existing bounded count.
2. No incident hosts, anomaly fallback present: row name says anomaly signals, never incidents.
3. No incident or anomaly hosts: empty list remains empty; no fabricated host or count.
4. One related item uses singular, two or more use plural, with no source-kind mix-up.
5. Long IPv6/reverse-DNS host: visual compact label and full-host tooltip remain; UIA name exposes the original full host.
6. Risk score is labeled local ranking, never confidence or verified accuracy; original sort and severity brush remain.
7. Screen reader reads the host row context without duplicate/confusing announcements or extra keyboard focus stops.
8. Wide, Standard, Compact and below-1024 widths retain the Items column, navigation and responsive composition.
9. 125–200% DPI and high contrast preserve readable Items caption, cyan/teal theme and truncation behavior.
10. PPS chart, incident investigation, Live Events, unavailable CLI, Cisco, capture/privacy and independent detection/protocol changes remain unchanged.

**Open quality GAs:** pinned-SHA Windows WPF build, actual UI
Automation/screen-reader and keyboard inspection, high-contrast/DPI
and responsive screenshots, incident/anomaly fallback and privacy
regressions after explicit owner test authorization.
**Executed tests: 0.**

**Next independent UI GA UI-19:** inspect live HEAD, exact Library
reference and actual WPF consumers; choose one new cohesive
accessibility/readability/visual-consistency improvement outside
UI-01–18 without changing telemetry, rules or shared contracts.

**Technical references:**
[WPF AutomationProperties.Name](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.name);
[WPF ItemsControl](https://learn.microsoft.com/en-us/dotnet/api/system.windows.controls.itemscontrol);
[WPF layout](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/layout).

## GA UI-19 — Recommended Actions badge semantics

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Starting live HEAD:
`21cfd475d84b31aa17a21221f404ab00b77498fc`; prior UI-18 publication: `1ce64648131319bf8126f6943eb8907752f1ea70`.
**UI source commit:** `cf4045ca7631c4e00553b8b52a2f438434c7de54`. **Tests authored: 0; executed: 0.**
No builds, tests, replays, CI, runners, capture, WPF runtime or screenshots.

### Approved reference, source contract and scope

The exact approved Library image `libfile_b0a34361560c8191b641e432b3e6b15c`
was retrieved and visually inspected. Its dark navy/graphite, cyan/teal
and compact panel layout is a visual guide only. Screenshot IPs, Mbps,
rule IDs, counts and confidence are **demo data**, not telemetry.

The original `DashboardActionItemsControl` uses the private
`BuildSocActionRows` projection. Its existing `CountText` badge was
ambiguous: a 1–4 **list position** for the highest-risk correlated
incident's recommended actions; a normalized **local anomaly risk score**
for the anomaly-only fallback; or a literal zero for a baseline-learning
suggestion. These values are not equivalent counts or confidence.

This GA makes their **visible meanings** explicit: `#1`–`#4` for
suggested-action position, `Risk N` for existing local anomaly risk,
and `—` for a baseline suggestion with no numeric badge. The existing
badge gets a source-specific tooltip and UI Automation name through a
new private UI-only `SocActionVm.BadgeDescription`; the collection gets
a neutral accessible name/help explaining that no suggested action is
executed by the list. No scoring, evidence, incident, capture-health,
rule, service, model, telemetry or command behavior is introduced.

| Original source | Visible badge | Truthful limit |
| --- | --- | --- |
| Highest-risk incident `RecommendedActions`, max four | `#1`–`#4` | List order only, not evidence count, verified priority or confidence. |
| Highest local anomaly signal | `Risk N` | Existing normalized local risk, not validated accuracy or confidence. |
| Neither incident nor anomaly | `—` | Baseline suggestion, not proof of healthy monitoring or zero traffic. |

### Ownership, static divergence and risks

Changed only `Carthago/Views/MainWindow.xaml`, `Carthago/Views/MainWindow.Dashboard.cs` and
`docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. Original XAML badge binding, private VM and
`BuildSocActionRows` consumers were inspected. Existing titles,
subtitles, icon/brush, refresh, ordering, incident/anomaly fallbacks
and action-list bound remain; anomaly risk normalization is reused once
for the same badge/brush. Source-only checks cover unique action-list
and badge binding, original local PPS ScottPlot, KPI and incident
panels, read-only Live Events (80 displayed / 500 retained), visual-only
unavailable CLI, Cisco/WebView2, capture/privacy and Wide ≥1440 /
Standard 1100–1439 / Compact 1024–1099 / below-1024 paths.
Intervening detection R531–R540 and protocol P0011–P0020 commits
were on disjoint engine/services/tests/rule/protocol-doc paths.
No shared API, project, runner, test or detection automation was edited.

**Residual risks:** `Risk N` takes more horizontal width than a bare
number; long action titles may truncate sooner. Actual UI Automation
exposure, screen-reader duplicate reading, tooltip, high contrast,
DPI and responsive visual fidelity remain **unverified**.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. One incident recommendation shows `#1` with list-position context.
2. Four or more recommendations remain bounded to four, `#1`–`#4`.
3. Missing incident recommendations retain the original review fallback.
4. Anomaly-only badge shows `Risk N` matching existing normalized brush.
5. Anomaly risk 0 and 100 are not announced as validated confidence.
6. No incident/anomaly displays `—` and baseline suggestion, not capture health.
7. Tooltip and UIA badge name expose source-specific meaning without duplication.
8. At 1440, 1100, 1099, 1024, 1023 and 640px, badge and action title remain legible.
9. At 125–200% DPI and high contrast, badge color and tooltip remain readable.
10. Original chart, incident selection, Live Events, unavailable CLI, Cisco and independent detection/protocol streams remain unchanged.

**Open quality GAs:** pinned-SHA Windows WPF build, UIA/keyboard,
responsive/high-DPI screenshots, action fallback and risk-score
regression after explicit owner test authorization. **Executed tests: 0.**

**Next UI GA UI-20:** inspect live HEAD, exact Library image, ledger and
WPF consumers for one independent accessibility/readability improvement
outside completed UI-01–19.

**References:** [WPF AutomationProperties.Name](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.name);
[WPF ToolTip](https://learn.microsoft.com/en-us/dotnet/api/system.windows.frameworkelement.tooltip);
[WPF layout](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/layout).

## GA UI-20 — Raw / Advanced shortcut destination clarity

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Starting live HEAD:
`80c89ef6096ee60e95b14b66967ce8323a6ca916`; prior UI-19 publication: `d0cf9e925b65038bd9dfe74b4238533e12f71b1b`.
**UI source commit:** `04ce70a10f370e457dbd5b72bba8c59e7f335667`. **Tests authored: 0; executed: 0.**
No build, test, replay, holdout, CI, runner, capture, benchmark or running-UI screenshot was performed.

### Reference and original navigation contract

The exact approved Library image `libfile_b0a34361560c8191b641e432b3e6b15c` was retrieved and visually inspected. Its dark navy/graphite, cyan/teal and compact operational shortcut language remains the design reference; the screenshot's sample telemetry, Mbps, IPs, incidents and CLI are demo-only.

Source inspection of `MainWindow.Dashboard.cs` and `MainWindow.Navigation.cs` established that the existing **PCAP Explorer** tile calls `DashboardPcapExplorer_Click` → `Nav_LiveTraffic_Click` → `LiveTrafficView`, while **Forensics Workspace** calls `DashboardForensicsWorkspace_Click` → `Nav_Alerts_Click` → `AlertsView`. Neither shortcut opens a separate named workspace. The **Open advanced tools** footer likewise routes to Live Traffic. Those visible labels overpromised a distinct destination.

### UI-only change and evidence limits

The existing Raw / Advanced Shortcuts card now labels those two tiles **Traffic Analysis** (subtitle: Opens Live Traffic) and **Detection Investigation** (subtitle: Opens Detection Events); the footer now reads **Open Live Traffic**. All four existing shortcut tiles and the footer receive explicit, truthful WPF UI Automation names/help describing the current destinations. The original Raw Traffic and Raw Detections tiles retain their visible labels. This is **navigation text and accessibility metadata only**: all five original `Click` handlers, view transitions, filter behavior, tiles, styling, dimensions and keyboard controls remain unchanged. Two pairs of shortcuts intentionally continue to reach the same existing views; no dedicated PCAP Explorer or Forensics Workspace is claimed.

**Owned paths:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. No `MainWindow.Dashboard.cs` or `MainWindow.Navigation.cs` edits. No engine, models, services, rules, capture, telemetry, evidence, privacy, security controls, project, tests, runners, workflows, rule/protocol documentation or automation changes. The real local PPS chart (10-sample average; bounded 120-point history), read-only Live Events (80 displayed / 500 retained), incidents, investigation, KPIs, Cisco/WebView2 and unavailable CLI remain untouched.

**Static divergence/concurrency:** source and consumer handlers read at live HEAD; UI-19 to starting HEAD is the independent P0021–P0030 protocol candidate, on disjoint services/tests/protocol-doc paths. Existing theme and Wide ≥1440 / Standard 1100–1439 / Compact 1024–1099 / below-1024 responsive controls remain unchanged. The revised tile text is potentially longer, so truncation at small widths is a residual visual risk. UI Automation exposure, accessible naming, screen-reader reading order, focus behavior and actual navigation are **not verified**.

### Acceptance scenarios — PLANNED ONLY; UNEXECUTED

1. Raw Traffic tile opens Live Traffic and traffic filters.
2. Raw Detections tile opens Detection Events and detection filters.
3. Traffic Analysis tile visibly describes Live Traffic and opens that existing view.
4. Detection Investigation tile visibly describes Detection Events and opens that existing view.
5. Footer explicitly says Open Live Traffic and opens the existing Live Traffic view.
6. Keyboard focus reaches each original button with no extra tab stops.
7. Screen reader exposes each button's name and truthful HelpText, without decorative glyph ambiguity.
8. At 1440, 1100, 1099, 1024, 1023 and 640px, long tile titles truncate gracefully without clipping controls.
9. At 125–200% DPI and high contrast, cyan focus and dark-surface readability remain usable.
10. Original local PPS, KPIs, incident/investigation, Live Events, unavailable CLI, Cisco, privacy and independent detection/protocol streams remain unaffected.

**Open quality GAs:** pinned-SHA Windows WPF build, actual navigation, keyboard/UIA, high-DPI/high-contrast and responsive screenshot comparison after owner explicitly authorizes tests. **Executed tests: 0.**

**Next independent UI GA UI-21:** inspect live HEAD, exact Library image, ledger and original WPF consumers for one new safe accessibility/readability improvement outside UI-01–20. Do not implement separate PCAP/forensics views or shared contracts.

**References:** [WPF AutomationProperties.Name](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.name);
[WPF AutomationProperties.HelpText](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.helptext);
[WPF layout](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/layout).


## GA UI-21 — Selected risk-score meaning for assistive technology and tooltips

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Starting live HEAD:
`56f4d0eec59fdebb961ba02e7ee999e46b352815` (GA UI-20 published).
**UI source commit:** `bc5a78e13223e3ca6bbc778eebcb3aff78d9b94a`.
**Tests authored: 0; executed: 0.** No builds, tests, replay, holdouts, CI,
GitHub Actions, runners, benchmarks, production capture or running-UI screenshot.
The incoming continuation prompt mentioned UI-20, but live GitHub history and this
ledger confirmed UI-20 complete; this is the next non-duplicative UI GA.

### Approved reference, original consumers and change

The exact approved Library image `libfile_b0a34361560c8191b641e432b3e6b15c`
was retrieved and visually inspected (1648×928). Preserve the reference's
navy/graphite panels, cyan/teal accents, restrained severity palette and compact
investigation risk ring. Screenshot IPs, Mbps lines, rule IDs, confidence and
metrics are **demo-only**, never operational evidence.

Source audit: `DashboardDetailRiskRing`, `DashboardDetailRiskText` and
`DashboardDetailRiskBadgeText` are existing WPF elements in
`MainWindow.xaml`; `UpdateSocSignalDetails` in `MainWindow.Dashboard.cs`
populates them from `CreateDashboardSignalDetailModel`. The selected
anomaly signal's score is normalized locally; the correlated incident branch
uses the incident's existing risk score; with no signal the risk text is
`—` and the badge is `Learning`. These are **local risk ranking
estimates**, not detection confidence, validated accuracy or proof of
healthy capture. An incident may include related anomaly IDs, so the
accessibility description intentionally does **not** infer a signal type
from the model's optional anomaly ID.

**One cohesive improvement:** the existing risk-value TextBlock gets a
neutral initial UI Automation name and explanatory HelpText. On every
existing `UpdateSocSignalDetails` refresh, its accessible name and the
ring's mouse tooltip are updated from the already displayed risk value
and band. The unavailable state says no selected signal and explicitly
rejects interpreting baseline learning as capture health. A present score
is described as a selected local risk estimate, **not** confidence or
verified accuracy. No extra polling, scoring, event handling, focus
targets, models, telemetry, evidence or runtime producers were added.
No new numeric values or demo data were introduced.

### Ownership, static divergence and residual risks

Changed only `Carthago/Views/MainWindow.xaml`,
`Carthago/Views/MainWindow.Dashboard.cs`, and
`docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`.
The prior GA UI-20 source, current WPF partials and risk-value consumers
were inspected before editing. Existing risk score/band formatting, brushes,
selected incident/anomaly fallback, detail dialog, seven previously labeled
investigation fields, incident triage, navigation and action buttons are
preserved. UI-01–20 remain intact. Actual local PPS ScottPlot uses the
existing 10-sample average and bounded 120-point history; read-only
Live Events retain 80 displayed / 500 retained; unavailable CLI, Cisco,
WebView2, capture/privacy and detection/protocol streams remain untouched.
Wide ≥1440, Standard 1100–1439, Compact 1024–1099 and below-1024
layout code and theme resources were not changed.

**Static limitations:** no Windows WPF build or runtime inspection was
authorized. Whether WPF UI Automation exposes the dynamic TextBlock name,
whether screen readers announce it once, whether the tooltip renders in
high contrast, and whether score changes are announced are all **unverified**.
The TextBlock remains non-focusable, and no live announcement is requested.
A risk score of zero may still carry the existing `Learning` band; the
new description does not equate it to no threat or healthy monitoring.

### Acceptance scenarios — PLANNED ONLY; UNEXECUTED

1. With no selected incident/signal, the risk reads `—` / `Learning`
   and accessible text says unavailable rather than zero risk.
2. Baseline learning does not announce or imply verified capture health.
3. Selected anomaly risk score exposes the existing numeric value and band,
   without being called confidence or verified accuracy.
4. Selected correlated incident risk score exposes the existing value and
   band, without assuming its related anomaly IDs define the source.
5. Score zero is not presented as proof of no detections or capture health.
6. Score 50/80 band boundaries preserve original label/color semantics.
7. Selection changes and data refresh update tooltip and accessible name
   together without new events or focus targets.
8. Screen-reader/UIA inspection confirms a discoverable risk-value name,
   no duplicate announcements, and preserved investigation labels.
9. At 1440, 1100, 1099, 1024, 1023 and 640px, 125–200% DPI and
   high contrast, the ring, tooltip and nearby detail controls remain usable.
10. PPS, Live Events, incident navigation, privacy, unavailable CLI,
    Cisco/WebView2 and independent detection/protocol code remain unchanged.

**Open quality GAs:** pinned-SHA Windows WPF build, UIA/keyboard/screen
reader, high-contrast/DPI and responsive screenshot review, selection and
risk-state regression **only after** explicit owner test authorization.
**Executed tests: 0.**

**Next independent UI GA UI-22:** inspect live HEAD, exact approved image,
ledger and WPF consumers for one new cohesive UI-owned accessibility,
readability or visual-consistency improvement outside UI-01–21.

**References:** [WPF AutomationProperties.Name](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.name);
[WPF AutomationProperties.HelpText](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.helptext);
[WPF layout](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/layout).

## GA UI-22 — Local PPS chart accessible current-summary status

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Starting live branch HEAD:
`9bdcea06799b819063f2d1c828631d9dbb408a2d` (GA UI-21 published;
independent protocol P0031–P0040 on disjoint paths).
**UI source commit:** `8b1cfa322b3dcf5ab4327e4729c027d5076dfb81`.
**Tests authored: 0; executed: 0.** No build, test, xUnit, replay,
holdout, CI, GitHub Actions, runner, benchmark, production capture,
WPF runtime or screenshot validation was performed.

### Approved reference and original consumer contract

Retrieved and visually inspected the exact approved Library PNG
`libfile_b0a34361560c8191b641e432b3e6b15c`.
The approved dark navy/graphite surfaces, cyan/teal accents and compact
traffic-card hierarchy remain unchanged. The screenshot's Mbps series,
IPs, rule IDs, scores, timestamps and status are **demo only** and
cannot be represented as actual local observations.

Source audit: `MainWindow.xaml` contains one visible `TrafficPlot`
ScottPlot WPF control and one existing
`DashboardTrafficChartTextSummary` TextBlock. The existing
`RenderTraffic` consumer in `MainWindow.Plots.cs` updates that
TextBlock from local timer PPS, the bounded retained sample count
(maximum 120), and existing `CaptureStatusText.Text`.
`MainWindow.Core.cs` retains the original one-second PPS bucket/history
producer. The chart remains local PPS plus its existing ten-sample
moving average, **not** inbound/outbound Mbps. Timer-generated zeros
and retained history are not proof of active capture.

### One cohesive UI-owned improvement

The existing `TrafficPlot` now binds WPF
`AutomationProperties.ItemStatus` to the **already visible** current
`DashboardTrafficChartTextSummary.Text`; its static help text
explicitly directs assistive-technology users to that summary and
disclaims throughput and capture-health inferences. The plot sets
`AutomationProperties.LiveSetting="Off"` so this change does not
deliberately request a live-region announcement on every timer tick.
No new summary, metric, timer, renderer, series, binding source,
event handler, telemetry producer, score or sample is introduced.
The original waiting overlay and capture-status warning remain
unchanged. This is an accessibility metadata change, not a
claim of successful screen-reader exposure.

**Owned paths:** `Carthago/Views/MainWindow.xaml` and
`docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only.
No `MainWindow.Plots.cs`, `MainWindow.Core.cs`, Models, Services,
Engine, rules, telemetry/capture/trust/privacy, tests, project, shared
API, workflow, runner, rule/protocol docs or automation changes.
No Cisco/WebView2/ScottPlot behavior changes. The left navigation,
KPIs, prioritized incidents, investigation, read-only local Live Events
(80 displayed / 500 retained), and visual-only **UNAVAILABLE** CLI
remain unchanged. Wide >=1440, Standard 1100–1439, Compact 1024–1099
and graceful below 1024 layout code is untouched.

### Static divergence and residual risks

The prior UI-21 source/ledger and live branch were compared before
editing. The sole intervening P0031–P0040 protocol candidate changed
Services/ProtocolIntelligence, protocol tests and docs/protocols,
all disjoint from UI ownership. The original XAML named elements,
plot/text-summary consumer and capture-status provenance were read.
Private source commit comparison shows only three added XAML lines and
one replaced HelpText line; the documentation commit records this
exact source SHA. A final remote HEAD and changed-path lease review
is required before publication.

**Risks:** The WPF/ScottPlot automation peer may not expose ItemStatus;
ElementName binding resolution, screen-reader verbosity, actual
per-second announcement behavior, high contrast, DPI and responsive
visual fidelity remain **UNVERIFIED**. LiveSetting Off is not proof
that every assistive technology will suppress announcements.
The status may describe timer-generated zero samples while capture is
inactive; the existing visible caution and summary remain authoritative.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. No timer sample: existing waiting text is retained and ItemStatus does not invent PPS.
2. One timer sample: waiting overlay remains; accessible status mirrors the existing summary.
3. Two timer samples: existing plot can draw; accessible status still mirrors visible text.
4. After 120+ ticks: retained count remains bounded at 120; no new UI history is created.
5. With ten-plus samples, the original moving-average plot remains unchanged.
6. PAUSED/OFFLINE/ERROR/DEGRADED: retained history and timer zeros are not called live capture.
7. MONITORING with PPS zero: no claim of healthy sensor, throughput or absence of threats.
8. Actual UI Automation inspection checks ItemStatus exposure, binding resolution, and screen-reader reading order without per-second disruptive announcements.
9. At 1440/1100/1099/1024/1023/640px, 125–200% DPI and high contrast, the chart/summary remain readable.
10. Original incident/investigation, Live Events, CLI unavailable, navigation, Cisco/WebView2, privacy and independent detection/protocol streams remain untouched.

**Open quality GAs:** pinned-SHA Windows WPF build, UIA/screen-reader,
keyboard and responsive screenshots, capture-state/plot synchronization
and provenance regression **only after** explicit owner test
authorization. **Executed tests: 0.**

**Next independent UI GA UI-23:** audit live HEAD, exact approved image,
ledger and WPF consumers; choose one new cohesive UI-owned accessibility,
readability or visual-consistency improvement outside UI-01–22.

**References:** [WPF AutomationProperties.ItemStatus](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.itemstatus);
[WPF AutomationProperties.LiveSetting](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.livesetting);
[WPF layout](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/layout).

## GA UI-23 — Prioritized incident queue accessible snapshot status

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Starting live feature HEAD: `27eda628828d9d9cfcf923d386ae45f1311c9c0e`. **UI source commit:** `86f62ade779ea03372b7202b639418df9658ad1d`. **Owned paths:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; executed: 0.** No build, xUnit, replay, holdout, CI, runner, benchmark, capture or running-WPF inspection.

### Approved reference, original consumers and provenance

Retrieved and visually inspected exact approved ChatGPT Library PNG `libfile_b0a34361560c8191b641e432b3e6b15c`. Its navy/graphite, cyan/teal, restrained severity, prioritized incident list, compact layout and approved breakpoints remain untouched. Screenshot metrics, IPs, rule IDs, timestamps, confidence and Mbps series are **demo-only**, not local evidence.

`DashboardAnomalyList` in `MainWindow.xaml` is the existing local incident/anomaly selection list. Its original `DashboardAnomalyList_SelectionChanged` handler in `MainWindow.Dashboard.cs` updates Incident Investigation. `RefreshSocDashboardWorkspace` refreshes the original bounded queue and `DashboardAnomalyFooterText.Text`: no-items state or shown-item count, unresolved correlated-incident count (max 150), anomaly-signal count (max 160), plus an explicit conditional demo-data caveat. The list's existing per-row `SocAnomalyVm.AccessibilityLabel`, keyboard selection and focus-border styling were inspected and preserved. These counts are **bounded local snapshots**, not global history, verified incidents, confidence or capture health.

### One cohesive UI-owned improvement

The existing list now binds `AutomationProperties.ItemStatus` to the **already visible** `DashboardAnomalyFooterText.Text`. Its help text directs assistive-technology users to the current bounded queue summary. `AutomationProperties.LiveSetting="Off"` avoids deliberately requesting announcements on each refresh. No new timer, collection, telemetry, evidence, producer, scoring, handler, selection logic, item, focus target, shared API or visual data is introduced. This is distinct from UI-11's per-row accessibility descriptions and does not repeat UI-01–22.

### Static divergence and residual risks

The live feature HEAD, prior UI-22 source/ledger, intervening protocol changes, WPF XAML, `RefreshSocDashboardWorkspace`, queue selection and row-label consumers were reviewed. Concurrent protocol changes were disjoint. Only the two authorized paths change. No Engine, Models, Services, detection/protocol rules or docs, capture/trust/privacy, tests, project, CI, runner, Cisco/WebView2/ScottPlot, security controls or automation settings change. The actual local PPS chart remains a 10-sample average over bounded 120-point history; KPIs, investigation, Live Events (80 displayed / 500 retained), unavailable visual-only CLI and responsive code are preserved.

**Risks:** WPF ElementName binding resolution, UI Automation ItemStatus exposure, screen-reader reading order, live-announcement behavior, high-contrast, DPI and narrow-window rendering are **UNVERIFIED**. LiveSetting Off is not a guarantee for every assistive technology. The initial footer text before first refresh is inherited unchanged.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Initial queue/footer state does not fabricate a count before refresh.
2. Empty local snapshots expose the existing no-incidents/no-signals message without implying safety.
3. Nonempty snapshots expose the existing displayed-item, unresolved-incident and anomaly-signal counts.
4. Existing max-150 incident/max-160 signal bounds are not misrepresented as global totals.
5. Demo mode retains the existing conditional demo-data caveat in status.
6. Keyboard selection and focus border still update the existing investigation details.
7. Existing per-row accessible kind/title/severity/local-risk/subtitle/time remain unchanged.
8. UI Automation and screen-reader review verify status binding and acceptable announcement frequency.
9. At 1440/1100/1099/1024/1023/640px, 125–200% DPI and high contrast, queue/footer remain readable.
10. Local PPS, KPIs, Live Events, unavailable CLI, Cisco/WebView2, privacy and independent streams remain unaffected.

**Open quality GAs:** pinned-SHA Windows WPF build, UIA/screen reader, keyboard, high-contrast/DPI and responsive screenshots, only after explicit owner test authorization. **Executed tests: 0.**

**Next independent UI GA UI-24:** inspect latest live HEAD, approved reference, ledger and original WPF consumers for one new safe UI-owned accessibility/readability/visual-consistency improvement outside UI-01–23.

**References:** [WPF AutomationProperties.ItemStatus](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.itemstatus); [WPF AutomationProperties.LiveSetting](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.livesetting).

## GA UI-24 — Truthful local capture status in the global footer

**2026-10-30 · SOURCE CANDIDATE — UNVERIFIED.** Starting live feature HEAD: `2ae551a61a542833bda954d8ad3bc524ec94cae2` (independent protocol P0051–P0060 source candidate already present). **UI source commit:** `4ee0df8fcb8ed0c851dc540626bf47beaae97321`. **Owned paths:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; executed: 0.** No dotnet build/test, xUnit, replay, holdout, CI, GitHub Actions, Windows runner, benchmark, capture, or running-WPF inspection.

### Approved reference, original consumers and provenance

Retrieved and visually inspected exact approved ChatGPT Library PNG `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928). Its navy/graphite/cyan/teal design, restrained severity, navigation, card geometry, incident triage and responsive layout are retained. Screenshot IPs, rule IDs, timestamps, confidence, Mbps series and sensor metrics are **DEMO ONLY**; they are not Carthago observations.

Original `MainWindow.xaml` global footer contained an unconditional green indicator with **"All systems operational"**, a hard-coded **"DB: Healthy"** label, and initial **"Telemetry: On"** text. The WPF `UpdateMonitoringHeader` consumer in `MainWindow.Dashboard.cs` already computes a bounded local capture status from the existing capture error, flow state, sink host and control state. It updates `FooterTelemetryStateText.Text` and `Foreground` for Monitoring/Paused/Error/Degraded/Offline and updates `FooterUtcText.Text`. It does **not** establish overall system, database or sensor health. `CaptureStatusText` and `MonitoringStatusBadge` remain separate existing header indicators. No code path was found that substantiates the footer's static global-health/database claims.

### One cohesive UI-owned improvement

The global footer now says **"Local capture state"** rather than **"All systems operational"**. Its small status dot binds to the existing `FooterTelemetryStateText.Foreground` (neutral at startup, then the original capture-state color), rather than being unconditionally green. A tooltip and WPF help text explicitly distinguish capture state from overall system/database/sensor health. The right-hand label now reads **"Capture:"**, retaining the existing `FooterTelemetryStateText` x:Name and original `UpdateMonitoringHeader` updates. Its initial placeholder is neutral **"Unknown"**, not unsupported **"On"**. The hard-coded **"DB: Healthy"** pair is removed, while the existing UTC clock, footer layout and original state producer remain intact.

This change adds **no** capture-health check, database check, telemetry, timer, polling, binding converter, API, action, navigation behavior or security claim. No status logic, consumer, event handler, model, service, engine, rule, protocol, evidence, trust/privacy control or automation setting is modified. The local PPS ScottPlot (ten-sample average, bounded 120-point history), KPIs, prioritized incidents, investigation, read-only Live Events (80 displayed/500 retained), explicitly UNAVAILABLE visual-only CLI, Cisco/WebView2 and responsive thresholds remain untouched.

### Static divergence review and residual risks

Start: live feature HEAD `2ae551a61a542833bda954d8ad3bc524ec94cae2` is a protocol P0051–P0060 commit directly following UI-23 publication HEAD `121ebc81a09e49d4543697ee2216b29259844c38`; the intervening protocol paths are independent of `Carthago/Views/**` and `docs/design/**`. Prior UI-23 source and ledger, the approved image, footer XAML, `MainWindow.Dashboard.cs` `UpdateMonitoringHeader`, header capture badge, and dashboard responsive partial were read. Source candidate changes only the footer XAML. Before publication, recheck remote HEAD, parent/tree, complete changed paths, WPF names/bindings, documentation source SHA and concurrent detection/protocol paths; publish only with a fresh expected-SHA lease.

**Risks:** WPF forward `ElementName` binding to `FooterTelemetryStateText.Foreground`, initialization timing, actual status-color updates, UI Automation help text, high-contrast themes, keyboard/screen-reader output, 125–200% DPI and below-1024 footer layout are **UNVERIFIED**. The footer reflects the existing local capture-state projection, which is **not** a database/sensor/global-health verdict or proof of live packets. No runtime evidence or accessibility score is claimed.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Before first status refresh, footer shows neutral Unknown rather than asserting On/healthy.
2. Monitoring state reuses existing On text/color, without asserting database or sensor health.
3. Paused state reuses existing Paused text/color and the status dot follows it.
4. Offline state reuses existing Offline text/color and avoids an unconditional green dot.
5. Error state reuses existing Error text/color and leaves error provenance in the original header.
6. Degraded state reuses existing Degraded text/color and does not imply healthy capture.
7. Tooltip and UI Automation help text describe the narrow capture-state provenance without exposing secrets.
8. UTC footer time remains updated by the existing consumer; no new timer is introduced.
9. At 1440/1100/1099/1024/1023/640px, 125–200% DPI and high contrast, footer content and focus/reading order remain legible.
10. KPIs, local PPS, incident/investigation, Live Events, unavailable CLI, Cisco/WebView2/ScottPlot, privacy and independent detection/protocol streams remain unchanged.

**Open quality GAs:** pinned-SHA Windows WPF build, actual status transitions, UI Automation/screen reader, keyboard, high contrast/DPI and responsive screenshots only after explicit owner authorization. **Executed tests: 0.**

**Next independent UI GA UI-25:** inspect live HEAD, exact approved image, ledger and WPF consumers for one new cohesive UI-owned accessibility/readability/visual-consistency improvement outside UI-01–24.

**References:** [WPF ElementName binding](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/data/how-to-bind-the-properties-of-two-controls); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF layout](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/layout).

## GA UI-25 — Accessible grouping of incident investigation supporting context

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting live feature HEAD: `98a680fd304af2e093c209b3c7eae3f726aa57bb` (independent P0061–P0070 GRE/VXLAN protocol source candidate present, disjoint paths). **UI source commit:** `ffa81db12a9a18b5707432f1d92a6b6ab62fdf1a`. **Owned paths:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; executed: 0.** No dotnet build/test, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, capture or running-WPF inspection.

### Approved reference, original consumers and provenance

Resolved and visually inspected exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`. It shows a navy/graphite Security Overview, cyan/teal accents, restrained severity, local incident triage and investigation panels. The screenshot's IPs, metrics, rule IDs, timestamps, confidence and inbound/outbound Mbps curves are **DEMO ONLY**, not evidence or Carthago observations. This GA does not alter rendered colors, typography, panel geometry, left navigation or responsive breakpoints (Wide >=1440, Standard 1100–1439, Compact 1024–1099, graceful below 1024).

Original `MainWindow.xaml` investigation detail contains three visually headed `ItemsControl` groups: Reasons, Tags, and Related rule IDs. `MainWindow.Dashboard.cs` binds them to the existing `ObservableCollection<string>` members `_dashboardDetailReasons`, `_dashboardDetailTags`, and `_dashboardDetailRules`. Existing `UpdateSocSignalDetails` and selection consumers replace these bounded collections from the selected local anomaly signal or correlated incident, including no-selection/empty fallbacks; the original `DashboardAnomalyList_SelectionChanged` continues driving the detail view. Reasons, tags and rule links are local reported/derived context, not independent evidence verification, accuracy or capture-health assertions.

### One cohesive UI-owned improvement

Give each existing visible group heading a unique XAML name (`DashboardDetailReasonsLabel`, `DashboardDetailTagsLabel`, `DashboardDetailRulesLabel`) and connect its original `ItemsControl` using WPF `AutomationProperties.LabeledBy`. Add a concise static `AutomationProperties.HelpText` per group to distinguish local triage reasons, selected-signal tags, and reported rule links from independently verified evidence or validated detection accuracy. The existing displayed text, item templates, `ItemsSource` bindings, collection bounds, selection handlers, scroll behavior, focus, keyboard order, data provenance and incident actions remain unchanged. This is group-level accessible context, distinct from UI-12 fact labels, UI-21 risk-ring explanation and UI-23 incident-list status.

**Exact owned paths:** `Carthago/Views/MainWindow.xaml` (source-only UI metadata) and this `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. No WPF code-behind, Controls, ViewModels, Theme, Engine, Models, Services, rules, protocol inspectors, telemetry/capture/trust/privacy, tests, benchmarks, workflows, runners, rule/protocol docs, project, shared APIs, security controls or independent automation settings/schedules are changed. Existing local PPS ScottPlot (ten-sample average, bounded 120-point history), operational KPIs, prioritized incidents, investigation, read-only Live Events (80 displayed/500 retained), explicitly **UNAVAILABLE** visual-only CLI, Cisco/WebView2 and responsive code are preserved.

### Static divergence review and residual risks

Start: live branch HEAD `98a680fd304af2e093c209b3c7eae3f726aa57bb` directly follows GA UI-24 publication `8b12fdbb335a58ffb98a80fd3f2064415bdd22d5`; intervening P0061–P0070 changes affect only `Carthago/Services/ProtocolIntelligence/**`, protocol tests and `docs/protocols/**`. Approved image, UI-01–24 ledger, original XAML headings/ItemsControls and `MainWindow.Dashboard.cs` collection producers/selection consumers were inspected. Source edit is limited to three existing heading names and three associated `LabeledBy`/`HelpText` property pairs. Before publication recheck live remote HEAD and changed paths, exact source and docs blobs, WPF names and references, original consumer contract, privacy and provenance; publish only with expected-SHA lease.

**Risks:** WPF `ElementName` binding resolution inside the visual tree, ItemsControl UI Automation peer naming, screen-reader group reading order or duplicated heading announcements, high contrast, DPI, and narrow-window behavior remain **UNVERIFIED**. Accessible help text describes existing local context but cannot verify evidence. Static review is not a build or runtime accessibility test.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. No selected incident or anomaly: existing no-signal reason and empty tag/rule groups remain; labels do not invent content.
2. Selected anomaly with reasons: original bounded reason text is unchanged and grouped under the visible Reasons heading.
3. Selected anomaly with tags: original tags and wrap layout remain, with group-level source caveat.
4. Selected anomaly with linked rule IDs: original IDs and `No linked rule` fallback remain, without implying validated detection.
5. Selected correlated incident: original incident reasons/tags/related event rule links remain and evidence is not called verified.
6. Changing `DashboardAnomalyList` selection still refreshes the three existing collections and investigation fields without focus/selection regressions.
7. UI Automation inspection checks the three group `LabeledBy` associations and `HelpText` exposure, with no duplicate or misleading announcements.
8. Keyboard navigation and screen-reader reading order remain usable; group metadata does not introduce new tab stops.
9. At 1440/1100/1099/1024/1023/640px, 125–200% DPI and high contrast, original headings, pill wraps and scrolling remain readable.
10. Existing local PPS, KPIs, Live Events, unavailable CLI, Cisco/WebView2/ScottPlot, capture/privacy, and independent detection/protocol streams remain unchanged.

**Open quality GAs:** pinned-SHA Windows WPF build, UI Automation/screen-reader review, keyboard, high-contrast/DPI and responsive screenshots, and provenance regression only after explicit owner authorization. **Executed tests: 0.**

**Next independent UI GA UI-26:** inspect fresh live HEAD, approved image, ledger and WPF consumers for one new cohesive safe UI-owned accessibility/readability/visual-consistency improvement outside UI-01–25.

**References:** [WPF AutomationProperties.LabeledBy](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.labeledby); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF layout](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/layout).

## GA UI-26 — Visible labels for Live Events severity and protocol filters

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE feature HEAD: `3934a509872fd0eedbf26fdcbe35c57f3d0c3fb1` (independent P0071–P0080 Geneve/HSRPv1 protocol candidate present). **UI source commit:** `5e76e01cbfb6313f9ab107e620195d44cfe6a312`. **Exact owned paths:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; executed: 0.** No dotnet build/test, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, capture or running-WPF inspection.

### Approved visual reference, original consumers and provenance

Resolved and visually inspected the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`: dark navy/graphite dashboard, cyan/teal accents, restrained severity, compact controls, left navigation and operational incident triage. Screenshot IPs, rule IDs, confidence, timestamps, sensor metrics and inbound/outbound Mbps lines are **DEMO ONLY**, not Carthago observations. The actual chart remains local PPS with its existing ten-sample average and bounded 120-point history. No screenshot data is copied into source.

The original `MainWindow.xaml` Live Events filter row has two `ComboBox` controls (`DashboardLiveSeverityFilter`, `DashboardLiveProtocolFilter`) with existing `AutomationProperties.Name`, tooltips, selection options and `DashboardLiveEventsFilterChanged` handlers, but no visible captions. GA UI-16 already provided visible Rule and Search labels for the **different free-text** filters. `MainWindow.DashboardEvents.cs` reads the original ComboBox `SelectedItem.Tag` values in `RefreshDashboardLiveEvents`, filters the existing bounded local `_alerts` collection, and preserves the 80-row display/500-event retention, no-match message and capture/evidence caveats. The clear-filters handler resets the original ComboBox selection indices and text boxes. `MainWindow.DashboardResponsive.cs` governs existing width adaptations; it does not depend on the ComboBox parent type. No engine, service, model, shared API, capture or evidence contract is needed.

### One cohesive UI-owned improvement

Add visible compact **Severity** and **Protocol** captions beside the two existing Live Events dropdowns, using the same muted 11px label treatment as the existing Rule/Search captions. Associate each original ComboBox with its new visible TextBlock using WPF `AutomationProperties.LabeledBy`. A horizontal `StackPanel` wraps each dropdown and owns its original outer margin; the dropdown retains its 142px width, 30px height, `x:Name`, tooltip, `AutomationProperties.Name`, options, `SelectedIndex` and `SelectionChanged` handler. This completes the four-filter row's visible identification without redoing GA UI-16's text-box labels or changing filtering semantics.

The change is strictly presentational and accessibility metadata. Existing severity/protocol matching, event provenance, sorting, read-only local Live Events, status and evidence disclaimers, navigation, KPIs, prioritized incidents, investigation, explicitly **UNAVAILABLE** visual-only CLI, Cisco, WebView2 and ScottPlot remain untouched. No telemetry, fabricated capture health, command execution, new tab stops, shared contracts or security-control changes.

### Static divergence review and residual risks

**Start:** live feature HEAD `3934a509872fd0eedbf26fdcbe35c57f3d0c3fb1` follows GA UI-25 publication `984c9bbea00f68d7dc2f6b8b5f0d163880ddcba4` with independent P0071–P0080 changes confined to protocol inspectors, protocol tests and `docs/protocols/**`. The prior UI-01–25 ledger, exact approved image, original XAML filter controls, `MainWindow.DashboardEvents.cs` event/filter/clear consumers, `MainWindow.DashboardResponsive.cs` and UI source commit were inspected. Source change is only the two dropdown wrappers/captions and two `LabeledBy` bindings; documentation is appended in `docs/design/**`. **End review must recheck** live remote HEAD, all concurrent paths, private source/docs commit ancestry, original WPF partials, unique names and label targets, privacy, visual reference and ledger source SHA. Publish the complete two-commit candidate only with one non-forced expected-SHA lease; stop if safe reconciliation is unavailable.

**Risks:** adding two captions increases filter-row width and may wrap the existing `WrapPanel` earlier at Compact, below 1024, high DPI or localization. Actual WPF `ElementName` label resolution, ComboBox UI Automation exposure, screen-reader verbosity, keyboard order, high contrast and visual screenshot comparison are **UNVERIFIED**. Static review does not establish compilation or accessibility success.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. All four filter controls show distinct visible Severity, Protocol, Rule and Search captions without adding interactive tab stops.
2. Severity dropdown retains All severities/Critical/High/Medium/Low/Info selections and existing filtering.
3. Protocol dropdown retains All protocols/TCP/UDP/ICMP selections and existing filtering; other protocols remain accessible under All.
4. Rule ID and endpoint search retain original TextChanged handlers, matching and GA UI-16 captions.
5. Clear filters restores both dropdowns to index zero and clears both text filters without event-handler regressions.
6. Empty and filtered-empty Live Events states keep their existing distinct messages and provenance.
7. UI Automation inspection resolves both new `LabeledBy` references and original accessible names without confusing announcements.
8. Keyboard navigation, focus indication, tooltip display and screen-reader reading order remain usable.
9. At 1440/1100/1099/1024/1023/640px, 125–200% DPI and high contrast, the row wraps gracefully and controls remain visible without clipping.
10. Read-only 80-row grid/500-event retention, frozen Event time, local PPS, incident triage, unavailable CLI, Cisco/WebView2/ScottPlot, privacy and independent detection/protocol streams remain unchanged.

**Open quality GAs:** pinned-SHA Windows WPF build, actual ComboBox filtering and clear interactions, UI Automation/screen reader, keyboard, high-contrast/DPI and responsive screenshots, and provenance regression only after explicit owner authorization. **Executed tests: 0.**

**Next independent UI GA UI-27:** inspect fresh live HEAD, approved image, ledger and WPF consumers for one cohesive safe UI-owned accessibility/readability/visual-consistency improvement outside UI-01–26.

**References:** [WPF AutomationProperties.LabeledBy](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.labeledby); [WPF WrapPanel](https://learn.microsoft.com/en-us/dotnet/api/system.windows.controls.wrappanel); [WPF ComboBox](https://learn.microsoft.com/en-us/dotnet/api/system.windows.controls.combobox).

## GA UI-27 — Truthful navigation for host/finding review buttons

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Start LIVE `feature/carthago-reliability-hardening` HEAD: `0df43e2e4237b93375ddb29a0d25ecb1c48fcbda`; preceding UI-26 publication: `59cbc728164559c05659edfdccc04d7ab2d54707`. **UI source commit:** `b1a6a26b6c0c8b8aebe0317ad1c5b62270922efd`. **Exact owned paths:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; executed: 0.** No builds, xUnit, replays, holdouts, CI, GitHub Actions, runners, benchmarks, production capture or running-UI screenshots.

### Reference, original consumers and provenance

The exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` was resolved and visually inspected at 1648×928. It defines dark navy/graphite surfaces, restrained severity and cyan/teal emphasis; its IP addresses, metrics, rule IDs, timestamps, confidence, Mbps series and terminal output are **DEMO ONLY**. The actual chart remains local PPS with its existing ten-sample average and bounded 120-point history; no demo data, capture-health assertions or additional telemetry are introduced.

The original High-Risk Hosts footer button said **View all high-risk hosts** and the Incident Investigation action said **Investigate Host**, but both invoke the existing `DashboardInvestigateHost_Click` in `MainWindow.Dashboard.cs`. That handler opens the existing correlated incident workspace when `_selectedDashboardIncidentId` is available, otherwise navigates to the existing **Anomalies** view; it does **not** open a complete host inventory or a dedicated host investigation. The five-row host projection, related-item/risk semantics, incident selection, existing button handlers, source/target identifiers, and responsive layout consumers were inspected. The separate GA UI-20 shortcut changes and GA UI-18 host-row count/accessibility changes are not repeated.

### One cohesive UI-owned improvement

Rename the High-Risk Hosts footer action to **Review findings →** and the Incident Investigation action to **Review finding**. Both retain their existing `DashboardInvestigateHost_Click` handlers and button styling, dimensions and placement. Add truthful mouse tooltips and WPF `AutomationProperties.Name` / `HelpText` explaining that the existing destination is the correlated incident workspace when available, otherwise the Anomalies view. The host-panel button explicitly disclaims a complete host inventory; the investigation button does not imply isolation of a host. No new controls, focus stops, navigation destinations, data models, services, detection/protocol rules, telemetry, security controls or shared APIs are introduced.

### Static divergence review and residual risks

**Start:** inspected LIVE HEAD `0df43e2e4237b93375ddb29a0d25ecb1c48fcbda`, recent commits, full design ledger through UI-26, original WPF XAML and the `MainWindow.Dashboard.cs` click handler, `MainWindow.DashboardEvents.cs`, `MainWindow.DashboardResponsive.cs`, existing UI resources and original consumer names. The independent P0081–P0090 STUN/RADIUS candidate is a direct descendant of UI-26 publication and modifies only protocol inspector, protocol test and `docs/protocols/**` paths; no UI overlap. The source candidate changes only the two existing button declarations and preserves their handlers, x:Name (where present), styles, layout, and privacy/evidence boundaries. **End:** review source/docs commit ancestry and changed paths against live HEAD immediately before one expected-SHA publication; any concurrent change requires a fresh disjoint-path reconciliation or STOP.

**Risks:** real WPF tooltip and UI Automation exposure, screen-reader reading order, keyboard focus, narrow-window wrapping, high contrast and 125–200% DPI are unverified. The destination remains conditional on existing incident selection; neither button promises to show all hosts. This is source-only and is not evidence of compilation, UI accessibility conformance, or navigation execution.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. High-Risk Hosts footer visibly reads **Review findings →** and no longer promises a full host inventory.
2. Incident Investigation primary action visibly reads **Review finding**, not a dedicated host investigation.
3. Both buttons retain their original `DashboardInvestigateHost_Click` handler and focus behavior.
4. With an available correlated incident, the existing handler opens its incident workspace without new routing.
5. Without an available incident ID, the existing handler opens the Anomalies view.
6. Mouse tooltips explain both conditional destinations and the absence of host inventory/isolation.
7. UI Automation exposes distinct neutral names and truthful help text; screen-reader behavior is inspected.
8. At 1440/1100/1099/1024/1023/640px, 125–200% DPI and high contrast, labels and tooltips remain legible.
9. Five-row host snapshot, local risk scores, incident triage, investigation actions, keyboard focus and navigation remain unchanged.
10. Read-only 80-row/500-retained Live Events, local PPS ScottPlot, unavailable CLI, Cisco/WebView2, privacy and independent detection/protocol streams remain unchanged.

**Open quality GAs:** pinned-SHA Windows WPF compilation, actual conditional navigation, UI Automation/screen reader, keyboard, high contrast/DPI and responsive screenshots only after the owner's explicit “now it is test time” authorization. **Executed tests: 0.**

**Next independent UI GA UI-28:** inspect live branch, approved image, ledger and original WPF consumers for one cohesive new UI-owned accessibility/readability/visual-consistency improvement outside UI-01–27.

**References:** [WPF Button](https://learn.microsoft.com/en-us/dotnet/api/system.windows.controls.button); [WPF AutomationProperties](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties).

## GA UI-28 — Truthful availability for the unconnected dashboard ellipsis

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE feature HEAD: `50fe4885cf1150d479ed59bfcf72a3e501344c82`; previous UI-27 publication: `fecc45af2eaa7870d1c3fa33b5aad662d9cc7b83`. **Exact UI source commit:** `513236c0eec3df63a345edc13e19a145c5404bd1`. **Owned paths:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; tests executed: 0.** No build, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, capture or running-WPF inspection.

### Approved reference, original consumer audit and provenance

The exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` was resolved and visually inspected. Its navy/graphite surfaces, cyan/teal accents, restrained severity, header command-bar proportions and operational triage design remain authoritative. Screenshot IPs, metrics, timestamps, rule IDs, confidence and Mbps/inbound/outbound lines are DEMO ONLY. Carthago's actual chart remains local PPS with the existing ten-sample average and bounded 120-point history; no demo telemetry or capture-health claims were introduced.

The original `MainWindow.xaml` header contained a visible ellipsis `Button` with tooltip and accessible name **More dashboard actions**, but **no Click handler, Command or menu**. It has no x:Name and no producer/consumer references. The existing `SecondaryButton` theme style has no command or menu trigger and already supports disabled opacity; original `MainWindow.Core.cs` Start/Pause Monitoring and source selection consumers, dashboard settings/navigation partials, responsive code and other visible header controls were reviewed. This control does not offer a working overflow menu. GA UI-20's actual shortcut destinations and GA UI-27's finding-review buttons are separate and untouched.

### One cohesive UI-owned improvement

Keep the original 40×36 ellipsis, placement, `SecondaryButton` theme and dark palette, but mark the nonfunctional overflow affordance `IsEnabled="False"` rather than presenting an apparently actionable menu. Provide `ToolTipService.ShowOnDisabled="True"`, a truthful unavailable tooltip, `AutomationProperties.Name="More dashboard actions unavailable"` and concise `AutomationProperties.HelpText` stating that no menu is implemented. No menu, commands, click handlers, tab stops, shared contracts, monitoring behavior, telemetry, incident logic, security controls or new dependencies are introduced. Existing visible Start/Pause, Test Reputation and Customize actions are unchanged.

### Start/end static divergence review and residual risks

**Start:** inspected the live feature HEAD, the prior UI-27 source/ledger and intervening independent protocol/detection commit paths; inspected the approved reference, original XAML, `Theme.xaml` `SecondaryButton` template, `MainWindow.Core.cs` header consumers and dashboard/navigation/responsive partials. The exact single source edit is limited to the existing unconnected ellipsis declaration; documentation is appended under `docs/design/**`. No `Engine/**`, `Models/**`, `Services/**`, detection/protocol rules, telemetry/capture/trust/privacy, tests, benchmarks, workflows, runners, rule/protocol docs, project, shared APIs, security controls or automation settings/schedules are edited.

**End publication requirement:** recheck live remote HEAD, compare concurrent changed paths, source/docs ancestry, XAML button uniqueness, source provenance and original consumer bindings. Publish both private commits in ONE non-forced expected-SHA-protected `update_ref` on the existing branch only. On any overlapping or uncertain change STOP instead of overwriting. The disabled button may remain visible in UI Automation but might not be announced by every screen reader; disabled tooltip presentation, high contrast, 125–200% DPI, keyboard navigation and visual fidelity are **UNVERIFIED**. Disabled styling uses existing theme opacity and is not proof of accessible contrast.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. The header ellipsis remains in its original 40×36 location and preserves the original dark-theme button style.
2. The ellipsis is disabled and no longer implies an operable menu; no menu or action is invented.
3. Hovering the disabled ellipsis displays the truthful unavailable tooltip via `ToolTipService.ShowOnDisabled`.
4. UI Automation inspection evaluates the unavailable name/help text and disabled state without promising screen-reader support.
5. Keyboard navigation skips the unavailable action and retains usable focus order for existing header controls.
6. Start/Pause Monitoring and capture source selection retain their original handlers and semantics.
7. Test Reputation and Customize retain their original actions; no new overflow navigation is added.
8. At 1440/1100/1099/1024/1023/640px, high contrast and 125–200% DPI, disabled state and tooltip remain readable without clipping.
9. Existing operational KPIs, local PPS chart, prioritized incidents, investigation and read-only Live Events (80 shown/500 retained) are unchanged.
10. Explicitly unavailable visual-only CLI, Cisco/WebView2/ScottPlot, privacy, provenance and independent detection/protocol streams remain untouched.

**Open quality GAs:** pinned-SHA Windows WPF build, actual disabled tooltip and UI Automation/screen-reader inspection, keyboard, high contrast/DPI and responsive screenshots, and provenance review only after the owner says “now it is test time”. **Executed tests: 0.**

**Next independent UI GA UI-29:** inspect fresh live HEAD, approved image, ledger and WPF consumers for one new cohesive UI-owned accessibility/readability/visual-consistency improvement outside UI-01–28.

**References:** [WPF Button.IsEnabled](https://learn.microsoft.com/en-us/dotnet/api/system.windows.uielement.isenabled); [WPF ToolTipService.ShowOnDisabled](https://learn.microsoft.com/en-us/dotnet/api/system.windows.controls.tooltipservice.showondisabled); [WPF AutomationProperties](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties).

## GA UI-29 — Truthful 60-minute host-activity sparkline labels and accessible description

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE feature HEAD: `073e1173610f4dc8863d5c44f4d8ea6c20a501bd`, a direct descendant of GA UI-28 publication `0871d7a795e3f9cd7d6ce780cb02152309fbc72a` with independent P0101–P0110 protocol source/tests/docs already present. **Exact UI source commit:** `1f2a08d89a013d90a49f64d7618c5f3dac083c84`. **Owned paths:** `Carthago/Views/MainWindow.xaml`, `Carthago/Views/MainWindow.Dashboard.cs`, and this `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; executed: 0.** No dotnet build/test, xUnit, replay, holdout, CI, GitHub Actions, Windows runner, benchmark, production capture or running-WPF inspection.

### Approved reference, source audit and provenance

Resolved and visually inspected the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`: dark navy/graphite panels, cyan/teal emphasis, restrained severity, compact four-column host table, left navigation and incident investigation. The image's IPs, timestamps, metrics, rule IDs, confidence, Mbps/inbound/outbound traffic lines and terminal output are **DEMO ONLY**, not observed Carthago data. The actual ScottPlot chart remains local PPS with ten-sample moving average and bounded 120-point history.

In the original High-Risk Hosts projection, `BuildSocHostRows` in `MainWindow.Dashboard.cs` takes at most five host rows from the existing correlated incident snapshot, falling back to anomaly-signal hosts only when no incident hosts are available. `TrendText` is produced by the unchanged `BuildTrendText` helper: eight relative Unicode bars over a 60-minute window, using incident `UpdatedUtc` timestamps or anomaly `CreatedUtc` timestamps. Bars are normalized to the largest time bucket; they are **not** packet throughput, risk-score change, absolute event counts or validated detection confidence. The original XAML labeled the column **Trend** with no explanation and rendered the bar glyphs without a source-specific accessible name. The existing private `SocHostVm` is consumed only by this dashboard's host `ItemsControl`; the original host identifier, risk, Items count, ordering, source-kind fallback and prior GA UI-18 accessibility label remain unchanged.

### One cohesive UI-owned improvement

Change the host-table column caption from **Trend** to **Activity**, with a tooltip explaining the existing 60-minute, eight-bucket relative timestamp presentation and its limitations. Extend the host-list `AutomationProperties.HelpText` to distinguish activity bars from traffic/risk trends. Add a read-only computed `SocHostVm.ActivityAccessibilityLabel` from the already-held host identifier and `RelatedItemKind`, distinguishing **correlated incident last-update timestamps** from **anomaly signal creation timestamps** without adding data sources. Bind that label to the existing sparkline TextBlock's tooltip and `AutomationProperties.Name`. Keep `TrendText` glyphs, `BuildTrendText`, source timestamps, colors, table dimensions, sorting, selection, consumers and telemetry unchanged. No new commands, interactive controls, handlers, collections, shared APIs, capture-health claims or security logic.

### Start/end static divergence review and residual risks

**Start:** reviewed live feature HEAD `073e1173610f4dc8863d5c44f4d8ea6c20a501bd`, the preceding UI-28 ledger/source, exact approved reference, original host XAML, private `SocHostVm` consumers, `BuildSocHostRows`, `BuildTrendText`, dashboard event/responsive partials and source provenance. Since UI-28, independent P0101–P0110 changed only protocol inspector source, protocol tests and `docs/protocols/**`; there is no overlap with the three UI-owned paths. Source candidate changes only the host-table header, host-list help, existing sparkline accessibility/tooltip bindings, and a computed private UI viewmodel label. **End publication requirement:** inspect fresh remote HEAD, compare all intervening paths, verify source/docs ancestry and exact changed files/blobs, naming and privacy before a single non-forced expected-SHA-protected `update_ref`. On overlap or missing safe lease guarantee STOP without publishing.

**Risks:** relative glyph heights are not absolute counts; the all-low-bar appearance can be misunderstood without the tooltip. Full host identifiers already held in local UI are exposed in the tooltip/accessibility name, not persisted or transmitted by this change. Actual WPF binding resolution, UI Automation output, screen-reader verbosity, tooltip placement, high contrast, 125–200% DPI and narrow-width readability are **UNVERIFIED**. Static source review is not compilation, runtime testing or accessibility certification.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. The High-Risk Hosts column visibly reads **Activity**, retaining its existing 84px column and layout.
2. The column tooltip explains eight relative buckets over 60 minutes and explicitly disclaims traffic/risk trends.
3. Incident-host activity uses existing correlated incident `UpdatedUtc` timestamps without changing the projection.
4. Anomaly-only fallback uses existing anomaly `CreatedUtc` timestamps without changing the projection.
5. The accessible sparkline label names the correct source kind and full already-held host identifier, not raw bar glyphs.
6. Screen-reader and UI Automation inspection assess tooltip/name exposure without announcing unsupported confidence or absolute counts.
7. Existing five-row bound, host compaction/tooltip, Items counts, local risk scores, severity colors, ordering and finding navigation remain unchanged.
8. At 1440/1100/1099/1024/1023/640px, 125–200% DPI and high contrast, the Activity caption and bars remain legible and do not clip or misalign.
9. Keyboard focus, navigation, incident investigation, local PPS chart and read-only Live Events (80 displayed/500 retained) remain unchanged.
10. Unavailable visual-only CLI, Cisco/WebView2/ScottPlot, privacy, provenance and independent detection/protocol streams remain untouched.

**Open quality GAs:** pinned-SHA Windows WPF build, actual UI Automation/screen reader and tooltip review, keyboard/high-contrast/DPI/responsive screenshots, and provenance regression **only after the owner explicitly says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-30:** inspect fresh live HEAD, the approved image, ledger and original WPF consumers for one cohesive UI-owned accessibility/readability/visual-consistency improvement outside UI-01–29.

**References:** [WPF AutomationProperties.Name](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.name); [WPF TextBlock](https://learn.microsoft.com/en-us/dotnet/api/system.windows.controls.textblock); [WPF ToolTip](https://learn.microsoft.com/en-us/dotnet/api/system.windows.frameworkelement.tooltip).


## GA UI-30 — Truthful KPI information and inert overflow affordance

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE feature HEAD: `b7ef734a074c81de78b8ea0c9192fa4b92adc78d`; previous UI-29 publication: `11a2a9d68f885b4fef01b7985d35bf84327a6126`. **Exact UI source commit:** `4ca29b0aa34da618b5766de82c8d6245f428af88`. **Owned paths:** `Carthago/Views/MainWindow.xaml`, `Carthago/Views/MainWindow.Dashboard.cs` and this `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; executed: 0.** No dotnet build/test, xUnit, replay, holdout, CI, GitHub Actions, Windows runner, benchmark, production capture or running-WPF inspection.

### Approved reference, original consumers and provenance

Resolved and visually inspected the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`: navy/graphite panels, cyan/teal accents, restrained severity, compact operational KPI cards and left navigation. Its IPs, metrics, rule IDs, timestamps, confidence, inbound/outbound Mbps and terminal content are **DEMO ONLY**. The actual traffic chart remains local PPS with the existing ten-sample moving average and bounded 120-point history; no demo data or capture-health claims were introduced.

Audited the original `DashboardKpiCardTemplate`, both `DashboardOverviewKpiItemsControl` and `DashboardKpiItemsControl`, the private `SocKpiVm`, `BuildSocOverviewKpis`, `BuildSocKpis`, `UpdateDashboardOverviewThroughput`, the responsive partials and existing theme resources. The KPI header's vertical ellipsis was a static `TextBlock` with **no Click, Command, menu, focus action or consumer**, yet suggested a per-card menu. The adjacent static information glyph had no tooltip or source explanation. GA UI-17's value-label association remains intact and is not repeated as a new feature. KPI producers are local, with unavailable sensor inventory and detection-coverage denominators, bounded correlated incident/anomaly snapshots and relative activity indicators.

### One cohesive UI-owned improvement

Remove only the inert KPI-card overflow glyph; retain the existing information glyph, KPI values, title, trend/delta, icons, accent brushes, cards and responsive templates. Bind the existing info glyph's tooltip and WPF AutomationProperties.Name/HelpText to read-only **private UI-only** explanatory properties; bind the same HelpText to the existing value without altering its LabeledBy. The explanation maps all nine existing KPI titles to their actual local sources and caveats: local throughput versus PPS, unavailable sensors/coverage, max-150 recent unresolved correlated incidents, locally ranked hosts, 15-minute anomaly/threat fallback totals, relative timestamp bars and baseline learning. **Threat Feed Hits** remains a legacy visible title; its explanation disclaims independently verified external intelligence. No metric, polling, data source, capture status, telemetry, security, navigation, command, shared API or detection/protocol change.

### Start/end static divergence review and residual risks

**Start:** inspected LIVE HEAD `b7ef734a074c81de78b8ea0c9192fa4b92adc78d` and compared it with UI-29 publication; three independent protocol commits introduced only `Carthago/Services/ProtocolIntelligence/**`, `Carthago.Tests/ProtocolIntelligence/**` and `docs/protocols/**` changes, with no overlap. Reviewed the exact approved image, original XAML and private WPF partial/consumer/viewmodel API, existing theme, responsive panel selection and full ledger through UI-29. **Source scope:** a single shared KPI template's static ellipsis/info/value accessibility attributes and one computed private viewmodel explanation. Existing values, trend calculations, source provenance, privacy, incident/host sorting and all non-UI paths remain untouched.

**End:** static publication review must confirm source/docs ancestry and blobs, only the three owned paths, no concurrent UI overlap, original x:Names/consumer bindings and a single non-forced expected-SHA lease update. If live HEAD moves, reconcile disjoint changes with a fresh lease or STOP. **Residual risks:** a non-focusable `TextBlock` tooltip may not be keyboard-reachable; WPF UI Automation peer exposure and screen-reader behavior are unverified. HelpText on the KPI value provides an additional inspection surface, not proof of accessibility. Tooltip length, high contrast, 125–200% DPI and narrow-window layouts require Windows inspection. This source-only candidate is not evidence of compilation or validated KPI correctness.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Both overview and optional KPI cards no longer show an inert vertical-ellipsis menu glyph.
2. The existing info glyph stays visible without a new menu, command or focus stop.
3. Hover tooltips describe each of the four overview KPI sources and unavailable sensor/coverage values.
4. Hover tooltips describe each of the five optional KPI sources and bounded/recent-fallback semantics.
5. UI Automation inspects the per-card info name/help and value help text; keyboard-only tooltip reachability is assessed rather than assumed.
6. Existing KPI value-label associations, values, icons, accent, trends/deltas and reactive throughput updates remain unchanged.
7. Local throughput is not confused with the PPS chart, inbound/outbound rates or capture-health certification.
8. At 1440/1100/1099/1024/1023/640px, high contrast and 125–200% DPI, headers, tooltips and value labels remain readable.
9. Existing incidents, risk ranking, local PPS chart, investigation and read-only Live Events (80 displayed/500 retained) remain unchanged.
10. Explicitly unavailable visual-only CLI, Cisco/WebView2/ScottPlot, privacy and independent detection/protocol streams remain untouched.

**Open quality GAs:** pinned-SHA Windows WPF build, actual tooltip/UI Automation/screen-reader/keyboard inspection, high-contrast/DPI/responsive screenshots and provenance review only after the owner says “now it is test time.” **Executed tests: 0.**

**Next independent UI GA UI-31:** inspect live feature HEAD, the exact approved image, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–30.

**References:** [WPF ToolTip](https://learn.microsoft.com/en-us/dotnet/api/system.windows.frameworkelement.tooltip); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF DataTemplate](https://learn.microsoft.com/en-us/dotnet/api/system.windows.datatemplate).

## GA UI-31 — Accessible capture-source selector with truthful selection caveat

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE feature HEAD: `9fe13ce3ed1ecf40f2ef242724882f39744ac2df`, following GA UI-30 publication `7c33d95aa8f9f8a88e8247b85744f8b90dd6af28`. **Exact UI source commit:** `2a5a62bb427e18402bf4a883901ad801b4098528`. **Owned paths:** `Carthago/Views/MainWindow.xaml` and this `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; executed: 0.** No dotnet build/test, xUnit, replay, holdout, CI, GitHub Actions, Windows runner, benchmark, production capture or running-WPF inspection.

### Approved reference, original consumers and provenance

Resolved and visually inspected the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1672×941): navy/graphite panels, cyan/teal accents, restrained severity, left navigation and operational status. Its IPs, timestamps, metrics, rule IDs, confidence, inbound/outbound Mbps and terminal output are **DEMO ONLY**, not actual Carthago evidence. The live chart remains local PPS with its existing ten-sample average and bounded 120-point history.

Audited original `MainWindow.xaml` header and `DeviceComboBox`, `MainWindow.Core.cs` (device loading, selection inspection, start/pause and capture-failure consumers), `MainWindow.Responsive.cs` (header-group positioning), `MainWindow.xaml.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Settings.cs`, theme and the ledger through GA UI-30. The existing visible **Capture source** label was an unnamed `TextBlock` with no explicit `AutomationProperties.LabeledBy` association on the adjacent `DeviceComboBox`. Selecting a device does **not** itself establish active or healthy capture; existing Start Monitoring and status consumers determine actual operation. This is a new header selector association, **not** GA UI-17 KPI value labeling or GA UI-26 Live Events filter labeling.

### One cohesive UI-owned improvement

Give the **existing visible** Capture source label the unique name `HeaderCaptureSourceLabel`; set `AutomationProperties.LabeledBy` on the original `DeviceComboBox` to that label. Clarify the selector's existing tooltip and add concise `AutomationProperties.HelpText` that a selected device requires the existing Start Monitoring action and is not evidence of capture health. Keep the original `DeviceComboBox` name, options, item template, sizing, theme, focus behavior, capture-service consumers and all monitoring handlers unchanged. No new status producer, capture control, command, selection handler, data source, shared contract, telemetry, privacy change or security logic.

### Start/end static divergence review and residual risks

**Start:** LIVE HEAD `9fe13ce3ed1ecf40f2ef242724882f39744ac2df` descends from UI-30 publication by three independent protocol commits affecting only `Carthago/Services/ProtocolIntelligence/Iec101Ft12Inspector.cs`, `Carthago.Tests/ProtocolIntelligence/Iec101Ft12InspectorTests.cs` and `docs/protocols/**`; no overlap with the two UI-owned paths. Inspected the approved image, WPF partials, source-selection consumer calls, responsive layout, original label/selector and existing UI Automation labeling patterns. **Source scope:** one existing label name and tooltip/accessibility metadata on the adjacent original ComboBox; no change to `Engine/**`, `Models/**`, `Services/**`, detection/protocol rules, tests, benchmarks, workflows, runners, rule/protocol docs, project, shared APIs, security controls or automations.

**End publication requirement:** recheck live remote HEAD immediately before publication, compare all intervening changes, inspect source/docs ancestry and exact changed paths, verify unique label and original consumer names, and publish both private commits together via ONE non-forced `update_ref` with `expected_sha` lease. On overlap or uncertain lease guarantee STOP without publication. **Residual risks:** WPF `LabeledBy` binding and AutomationPeer exposure, screen-reader label precedence, disabled-selector announcement, tooltip verbosity, keyboard navigation, high contrast, 125–200% DPI and 1440/1100/1099/1024/1023/640px layouts are **UNVERIFIED**. The tooltip describes limitations; it does not measure capture health. Source review does not prove compilation, runtime correctness or accessibility compliance.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. The visible Capture source label retains its original typography and position in the header.
2. `DeviceComboBox` remains the same named ComboBox, with its original item template, width and source options.
3. UI Automation inspection checks that `DeviceComboBox` resolves its `LabeledBy` to the visible Capture source label.
4. Screen-reader inspection checks the selector's accessible label and help text without claiming verified announcement behavior.
5. The selector tooltip explains that choosing a device does not mean capture is running or healthy.
6. Original `LoadDevices`, `StartButton_Click`, `StopButton_Click`, startup capture and capture-failure consumers retain their semantics.
7. When the selector is disabled during monitoring, the source selection and focus state behave as before; no new capture-health inference appears.
8. At 1440/1100/1099/1024/1023/640px, high contrast and 125–200% DPI, the header label, selector and tooltip remain readable without clipping.
9. Existing KPIs, prioritized incidents, investigation, local PPS ScottPlot and read-only Live Events (80 shown/500 retained) remain unchanged.
10. Unavailable visual-only CLI, Cisco/WebView2/ScottPlot, privacy, provenance and independent detection/protocol streams remain untouched.

**Open quality GAs:** pinned-SHA Windows WPF build, real UI Automation/screen-reader and tooltip inspection, keyboard/high-contrast/DPI/responsive screenshots and provenance regression **only after the owner explicitly says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-32:** inspect fresh live HEAD, exact approved image, ledger and WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–31.

**References:** [WPF AutomationProperties.LabeledBy](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.labeledby); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF ComboBox](https://learn.microsoft.com/en-us/dotnet/api/system.windows.controls.combobox).

## GA UI-32 — Truthful lower-widget headers and local source explanations

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE feature HEAD: `0692fc326ed5d1b804000b24e610014b88b76bcf`, following GA UI-31 publication `187823c5e5d291791ac567c8da1766dbf9a0e6a5`. **Exact UI source commit:** `7a62278d22473cbe1a28b04d3d882170a22e92f0`. **Owned paths:** `Carthago/Views/MainWindow.xaml` and this `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; executed: 0.** No dotnet build/test, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, capture or running-WPF inspection.

### Approved reference, existing consumers and provenance

Resolved and visually inspected exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1672×941): navy/graphite surfaces, cyan/teal accents, restrained severity, compact operational layout and left navigation. Screenshot IPs, timestamps, confidence, Mbps lines, rule IDs and terminal output are **DEMO ONLY**, not product telemetry. Real traffic remains local PPS with the existing ten-sample average and bounded 120-point history; the visual-only CLI remains explicitly **UNAVAILABLE**.

Audited `MainWindow.xaml` lower `DashboardSummaryGrid` and all three original headers, `Theme.xaml` (`SocPanelMenuGlyph` and `SocInfoGlyph`), `MainWindow.Dashboard.cs` (`BuildSocHostRows`, `BuildSocActionRows`, original shortcut and finding handlers), `MainWindow.DashboardResponsive.cs` (Wide/Standard/Compact panel positioning), existing host/action ItemsControl bindings, and ledger through UI-31. Each header displayed a static northeast-pointing arrow styled as a panel menu glyph with **no command, click handler, expansion or navigation**. The adjacent information glyphs had no explanatory tooltip. Existing real buttons already navigate to Live Traffic, Detection Events, a selected incident workspace or Anomalies. Local host ranking favors correlated incident hosts and uses anomaly-signal hosts only when none exist; action suggestions are informational and do not perform remediation.

### One cohesive UI-owned improvement

Remove the three misleading static pseudo-launch arrows from **High-Risk Hosts**, **Recommended Actions**, and **Raw / Advanced Shortcuts**. Preserve each heading, the existing muted information glyph and all panel geometry, colors, buttons and list content. Give each existing information glyph a concise, source-specific mouse tooltip and WPF AutomationProperties.Name; give the existing section heading a source-limitation AutomationProperties.HelpText. Hosts disclose incident-first/anomaly-fallback ranking and distinguish local risk from detection confidence; actions disclose informational suggestions and source-dependent badges; shortcuts disclose that existing Live Traffic/Detection Events views open rather than separate PCAP/forensics workspaces. No new focus stops, actions, handlers, collections, telemetry, capture logic, scores, security controls, shared contracts, viewmodels or theme resources.

### Start/end static divergence review and residual risks

**Start:** LIVE HEAD `0692fc326ed5d1b804000b24e610014b88b76bcf` descends from UI-31 publication via independent GA P0131–P0140 commits affecting only `Carthago/Services/ProtocolIntelligence/**`, `Carthago.Tests/ProtocolIntelligence/**` and `docs/protocols/**`; no overlap with the two UI-owned paths. The exact approved image, original WPF source/partials, theme, navigation consumers, layout breakpoints and prior ledger were inspected before editing. **Candidate static review:** `7a62278d22473cbe1a28b04d3d882170a22e92f0` differs from the starting HEAD only in `Carthago/Views/MainWindow.xaml` (three decorative arrows removed, three source-specific header explanations added); original header names and button handlers remain. The three old `SocPanelMenuGlyph` instances are absent in the source candidate; the shared theme style is intentionally untouched.

**End/publication gate:** re-read LIVE remote HEAD immediately before publishing, compare all intervening changes against the starting HEAD, confirm source/docs ancestry and exact blob/path ownership, and publish both commits together via exactly ONE non-forced `update_ref` with `expected_sha` lease. If HEAD moves, reconcile disjoint changes safely with a fresh lease or STOP. No other branch, workflow, runner, rule/protocol file or automation may be changed.

**Residual risks:** non-focusable TextBlock info glyphs have no established keyboard-only tooltip access; WPF UI Automation peer exposure, screen-reader announcement, tooltip wrapping/placement, high contrast, 125–200% DPI and 1440/1100/1099/1024/1023/640px responsive screenshots remain **UNVERIFIED**. Removing right-docked decorative arrows could change header whitespace slightly. Static review is not a build, runtime proof or accessibility certification. No new personal data is stored, transmitted or collected; existing local host identifiers remain within their original UI bindings.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. All three lower widget headers retain their original headings and muted information glyphs but no inert northeast pseudo-launch arrows.
2. High-Risk Hosts information tooltip truthfully describes incident-first host ranking and anomaly fallback without suggesting a complete host inventory.
3. Host heading help text distinguishes local risk ranking from detection confidence.
4. Recommended Actions tooltip/help describe suggestions only, without implying execution or remediation.
5. Recommended Actions badges retain original position/local-risk/no-number semantics and row tooltip behavior.
6. Raw / Advanced Shortcuts tooltip/help describe existing Live Traffic and Detection Events destinations, not separate PCAP/forensics interfaces.
7. All original finding-navigation and four shortcut button click handlers remain connected, with unchanged focus and selection.
8. At 1440/1100/1099/1024/1023/640px, 125–200% DPI and high contrast, headers and hover tooltips remain legible; actual screen-reader and keyboard-only exposure are inspected, not assumed.
9. Original local PPS ScottPlot, operational KPIs, prioritized incidents, investigation and read-only Live Events (80 shown/500 retained) remain unchanged.
10. Visual-only unavailable CLI, Cisco/WebView2/ScottPlot behavior, privacy, provenance and independent detection/protocol streams remain untouched.

**Open quality GAs:** pinned-SHA Windows WPF build, real UI Automation/screen-reader/keyboard/tooltip review, high-contrast/DPI/responsive screenshots and provenance regression **only after the owner explicitly says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-33:** inspect fresh live HEAD, exact approved reference, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–32.

**References:** [WPF ToolTip](https://learn.microsoft.com/en-us/dotnet/api/system.windows.frameworkelement.tooltip); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF TextBlock](https://learn.microsoft.com/en-us/dotnet/api/system.windows.controls.textblock).

## GA UI-33 — Source-specific Live Events Evidence and Delivery header guidance

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE feature HEAD: `7af8ecf2500da620e17ddc21bb3ff213a47083a2`, after GA UI-32 publication `ad1cd1b2e9425c215fd906d0babb697e19c8f7e2`. **Exact UI source commit:** `4242a5fc878b2558e82077bdfcaffdd16730af2b`. **Owned paths:** `Carthago/Views/MainWindow.xaml` and this `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; executed: 0.** No dotnet build/test, xUnit, replay, holdout, CI, GitHub Actions, Windows runner, benchmark, production capture or running-WPF inspection.

### Approved reference and original consumers

Resolved and visually inspected the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1672×941): navy/graphite, cyan/teal, restrained severity, left navigation, compact read-only event table and operational dashboard. Screenshot IPs, timestamps, rule IDs, confidence, Mbps and terminal lines are **DEMO ONLY**. Actual traffic remains local PPS ScottPlot with the existing 10-sample average and 120-point history. CLI remains explicitly **UNAVAILABLE** and visual-only.

Audited the existing `DashboardLiveEventsGrid` XAML, `Theme.xaml` implicit `DataGridColumnHeader` styling, `MainWindow.DashboardEvents.cs` (`DashboardEventRowVm.FromDetection`, refresh and filtering), dashboard initialization, WPF partials/responsive consumers, and ledger through UI-32. The existing `EvidenceSummary` cell displays a structured evidence **item count** if available, otherwise only whether unstructured evidence was reported; neither raw evidence nor sensitive structured items are rendered. `DeliveryStatus` is the detection event's recorded delivery/transport state, **not** incident investigation or resolution. The grid already has a general provenance help text (UI-13), focus visibility (UI-15) and a status line; this GA adds **column-specific guidance at the headers**, not a new data source or repetition of grid-level semantics.

### One cohesive UI-owned change

Keep the existing **Evidence** and **Delivery** column captions, bindings, widths (128/105), order, frozen Event time column, row and column virtualization, read-only state and all filters/handlers. On each of those two `DataGridTextColumn` headers only, add a `HeaderStyle` based on the existing implicit `DataGridColumnHeader` theme, with a mouse tooltip and `AutomationProperties.HelpText` describing the original producer's limitations. Evidence says presence/count only, not raw payload or verified custody; Delivery says detection-event transport state, not investigation, remediation or incident resolution. No changes to event timestamps, evidence collection, delivery state, display limits (80), retention (500), polling, monitoring, telemetry, capture, trust/privacy, scoring, engine, model, service, detection/protocol rules, APIs or security controls. No new action or keyboard focus stop.

### Static divergence and publication guard

**Start:** LIVE HEAD `7af8ecf2500da620e17ddc21bb3ff213a47083a2` descends from UI-32 publication via one independent protocol commit (GA P0141–P0150) affecting only `Carthago/Services/ProtocolIntelligence/**`, `Carthago.Tests/ProtocolIntelligence/**` and `docs/protocols/**`. The approved reference, existing WPF source, dashboard event producer, implicit header theme, responsive partials and all earlier UI GAs were inspected. **Private source candidate:** `4242a5fc878b2558e82077bdfcaffdd16730af2b`, parent `7af8ecf2500da620e17ddc21bb3ff213a47083a2`, changes only `Carthago/Views/MainWindow.xaml` by adding two header styles; original x:Names, bindings, column dimensions, event producer and navigation remain intact.

**End/publication gate:** immediately re-read live remote HEAD and compare all intervening paths, source/docs ancestry and exact Git blobs; check WPF header style names, XAML markup and privacy provenance statically. Publish both private commits **together** through exactly one non-forced expected-SHA-leased `update_ref` on the existing branch. If HEAD moved, reconcile only disjoint paths with a fresh lease; STOP on overlap or uncertain guarantee. Never publish a partial candidate or alter other streams.

**Residual risks:** WPF implicit-style `BasedOn` resource resolution, actual column-header AutomationPeer help-text exposure, screen-reader reading order, hover tooltip availability (including keyboard-only use), high contrast, 125–200% DPI and narrow-window horizontal scrolling are **UNVERIFIED**. Header help text does not certify evidence custody or transport delivery correctness. No additional data is persisted, collected or transmitted; existing displayed event metadata remains unchanged. Static inspection is not compilation, runtime validation or accessibility certification.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Evidence and Delivery retain their original captions, widths (128/105), column order and read-only cell bindings.
2. Evidence header hover explains presence or structured-item count, not raw evidence contents.
3. Evidence header UI Automation HelpText conveys that reported evidence is not a verified chain of custody.
4. Delivery header hover explains event delivery transport status rather than investigation, remediation or resolution.
5. Delivery header UI Automation HelpText carries the same truthful transport-versus-incident distinction.
6. Both header styles inherit existing navy/graphite theme typography, borders, padding and colors.
7. Original event timestamp rendering, filtering, row selection, 80-row display, 500-event retention, virtualization and frozen first column are unchanged.
8. At 1440/1100/1099/1024/1023/640px, 125–200% DPI and high contrast, header captions and tooltips remain legible; inspect horizontal scrolling and actual screen-reader/keyboard behavior.
9. Original prioritized incidents, investigation, local PPS ScottPlot, KPI cards, navigation, Cisco/WebView2 and explicitly unavailable CLI remain untouched.
10. No demo data is mistaken for telemetry, no new evidence/capture-health claim appears, and independent detection/protocol streams and privacy boundaries remain unchanged.

**Open quality GAs:** pinned-SHA Windows WPF build, actual DataGrid header style resolution, UI Automation/screen-reader and tooltip/keyboard inspection, high-contrast/DPI/responsive screenshots and provenance regression **only after owner says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-34:** inspect fresh live HEAD, exact approved image, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–33.

**References:** [WPF DataGridTextColumn.HeaderStyle](https://learn.microsoft.com/en-us/dotnet/api/system.windows.controls.datagridcolumn.headerstyle); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF DataGridColumnHeader](https://learn.microsoft.com/en-us/dotnet/api/system.windows.controls.primitives.datagridcolumnheader).

## GA UI-34 — Expose existing sidebar selection to assistive technology

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE feature HEAD: `380aab8680414dd45a87e14265099851b83c3f2a`, after GA UI-33 publication `6572b2e4d68efc267c2532c48a98a1c5d5f0a28a` and independent GA P0151–P0160 protocol source commit. **Exact UI source commit:** `b7c3bbc2ae3804951ebe051a700acc6e354eba5c`. **Owned paths:** `Carthago/Views/Sidebar.xaml.cs` and this `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; executed: 0.** No build, dotnet test, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, production capture or running-WPF inspection.

### Approved reference, original navigation consumers and provenance

Resolved and visually inspected exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1672×941). It establishes navy/graphite surfaces, cyan/teal accents, restrained severity, left navigation, operational KPIs and compact incident/event layout. Screenshot IPs, rule IDs, confidence, timestamps, Mbps series and terminal lines are **DEMO ONLY**, not live telemetry. The original local PPS ScottPlot (10-sample average, 120-point bounded history), prioritized incidents, investigation, read-only Live Events (80 shown/500 retained) and explicitly **UNAVAILABLE** visual-only CLI are untouched.

Audited `Sidebar.xaml` navigation Button names and existing AutomationProperties.Name labels, `Sidebar.xaml.cs` (`SetActiveNavButton`, `ActivateNav`, click handlers, `IsCompact`), `MainWindow.Navigation.cs`, `MainWindow.xaml.cs` navigation/event wiring, `MainWindow.Responsive.cs`, `MainWindow.DashboardResponsive.cs`, `Theme.xaml` navigation styling, `MainWindow.xaml` and ledger through UI-33. The sidebar already sets the active button's `Tag` to `Active` and applies `SelectionBgBrush`, but does not expose that visual selection via a per-button UI Automation status. The existing MainWindow navigation consumers call `ActivateNav` to keep the sidebar selection in sync. No new navigation state or route is introduced.

### One cohesive UI-owned improvement

In the existing `SetActiveNavButton` loop, mirror the *same* visual selection to WPF `AutomationProperties.ItemStatus` on each original sidebar Button: `Current navigation selection` for the selected button, and an empty status for the others. This reports sidebar selection only, **not** successful route loading, capture health, incident state or any monitoring assertion. Keep the original `Tag`, brush, control names, button labels, click handlers, route mappings, focus order, keyboard behavior, filters, collapsed/compact presentation and responsive breakpoints. Import `System.Windows.Automation` in the UI-owned sidebar partial only. No shared contract, new viewmodel, action, event, telemetry producer, security control or service modification.

### Start/end static divergence review and residual risks

**Start:** LIVE HEAD `380aab8680414dd45a87e14265099851b83c3f2a` is one commit ahead of UI-33 publication, with independent GA P0151–P0160 files only in `Carthago/Services/ProtocolIntelligence/**`, `Carthago.Tests/ProtocolIntelligence/**` and `docs/protocols/**`; no overlap with the two UI-owned paths. The exact approved image, original WPF source/partials, navigation consumers, theme, names, provenance and prior GAs were inspected. **Private source candidate:** `b7c3bbc2ae3804951ebe051a700acc6e354eba5c` has parent `380aab8680414dd45a87e14265099851b83c3f2a` and modifies only `Carthago/Views/Sidebar.xaml.cs` (one import, one attached-property assignment and explanatory comments). No change to the original navigation event wiring or visual selection.

**End/publication gate:** re-read LIVE remote HEAD immediately before publishing, compare intervening detection/protocol and UI paths, confirm commit ancestry and exact source/docs blobs, and publish the complete source/docs chain via exactly **ONE** non-forced `update_ref` with `expected_sha` lease on the existing branch. If HEAD moves, reconcile disjoint changes with a fresh lease or STOP on overlap/uncertain guarantee. No branch, PR, automation, workflow, runner, rule or protocol file may be changed.

**Residual risks:** Windows WPF compilation and actual `AutomationProperties.ItemStatus` peer exposure, screen-reader announcement, active/cleared status on programmatic navigation, compact-mode discoverability, keyboard focus, high contrast, DPI and responsive screenshots remain **UNVERIFIED**. Existing initial `Loaded` selection defaults to Overview and existing click handlers may mark selection before view navigation completes; the added status mirrors that same preexisting visual state and does not certify route success. Static inspection is not an accessibility certification. No new personal information is collected, persisted, transmitted or logged; all event and host data remain in their original bindings.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Initial sidebar Overview selection exposes `Current navigation selection` on its original Button UI Automation peer.
2. Clicking an existing navigation button moves the accessible status to that selected button, preserving the original route/event.
3. Previously selected buttons have an empty ItemStatus rather than stale selection.
4. Programmatic `ActivateNav` transitions update the same status, including dashboard, incidents and detection events.
5. No additional keyboard focus stops, changed button names, click commands, filter handlers or navigation routes.
6. Existing `Tag`, selected background brush, hover and focus styles remain visually identical.
7. Wide (>=1440), Standard (1100–1439), Compact (1024–1099) and below-1024 presentations retain existing navigation and discoverability; inspect 1440/1100/1099/1024/1023/640px, 125–200% DPI and high contrast.
8. Real UI Automation and screen-reader behavior distinguish navigation selection from route-loading success and from capture/monitoring status.
9. Original local PPS chart, KPIs, incident queue, investigation, read-only Live Events, Cisco/WebView2/ScottPlot and explicitly unavailable CLI remain unchanged.
10. No demo telemetry or new privacy/security claim appears, and independent detection/protocol streams remain untouched.

**Open quality GAs:** pinned-SHA Windows WPF build, UI Automation/screen-reader/keyboard review, compact/high-contrast/DPI/responsive screenshots and navigation-provenance regression **only after the owner explicitly says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-35:** inspect fresh LIVE HEAD, exact approved reference, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–34.

**References:** [WPF AutomationProperties.ItemStatus](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.itemstatus); [WPF AutomationProperties.SetItemStatus](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.setitemstatus); [WPF Button](https://learn.microsoft.com/en-us/dotnet/api/system.windows.controls.button).

## GA UI-35 — Truthful last-analysis timestamp and accessible header context

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE feature HEAD: `90d3cc1cac10f8da4462fcaa58ccbf4ae0ac8c9b`, after GA UI-34 publication `bb4eeb68989f4fe38223a181249787661c4fd74c` and the independent GA P0161–P0170 protocol commit. **Exact UI source commit:** `d364b4818e667c5d71ece820acb562267ac73772`. **Owned paths:** `Carthago/Views/MainWindow.xaml`, `Carthago/Views/MainWindow.Dashboard.cs`, and this `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; executed: 0.** No build, dotnet test, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, capture or running-WPF screenshot.

### Approved reference, producer and consumer audit

Resolved and visually inspected the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1672×941): navy/graphite shell, cyan/teal accents, restrained severity, left navigation, operational KPIs, local traffic chart and compact incident/event panels. All screenshot IPs, timestamps, rule IDs, confidence, Mbps series and terminal lines are **DEMO ONLY**; no reference values were inserted. Preserve the local PPS ScottPlot (10-sample average, bounded 120-point history), incident-first triage, investigation, read-only local Live Events (80 displayed/500 retained), unavailable visual-only CLI, Cisco/WebView2 and breakpoints Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024.

Audited `MainWindow.xaml` command-header status, source and analysis groups; `MainWindow.Dashboard.cs` `UpdateMonitoringHeader`, its `_sinkHost?.Analytics.LastAnalysisUtc` producer, existing error/degraded/waiting branches, capture-source/flow tooltip and timer; `MainWindow.xaml.cs`, `MainWindow.Navigation.cs`, `MainWindow.Responsive.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.DashboardEvents.cs`, `Sidebar.xaml(.cs)`, `Theme.xaml` and the UI ledger through UI-34. The prior header displayed a historical `LastAnalysisUtc` timestamp with the suffix **(Live)** even if the current monitoring status was paused or offline. The existing timestamp conversion uses `ToLocalTime()`; it is not a live-capture or capture-health proof. The original diagnostic tooltip comes from the existing capture-source/flow pipeline and remains unchanged.

### One cohesive UI-owned improvement

Keep the existing **Last analysis** caption, status `x:Name`, status text producer, local timestamp conversion, error/degraded/waiting branches, tooltip, capture badge, start/pause controls, header geometry and responsive consumers. Give the existing visible caption the unique name `HeaderLastAnalysisLabel`; associate the original `HeaderLastAnalysisText` with it using `AutomationProperties.LabeledBy`, add truthful `HelpText` explaining recorded analysis versus capture/event-delivery health, and set `AutomationProperties.LiveSetting=Off` to avoid declaring an unsolicited live region on the periodically refreshed status. Change only the historical timestamp suffix from **(Live)** to **(recorded)**. Do not alter `LastAnalysisUtc`, monitoring/capture/flow state calculations, status conditions, diagnostics, telemetry, services, privacy or any security control.

### Static divergence, provenance and publication guard

**Start:** LIVE HEAD `90d3cc1cac10f8da4462fcaa58ccbf4ae0ac8c9b` descends from GA UI-34 publication through one independent P0161–P0170 protocol commit changing only `Carthago/Services/ProtocolIntelligence/**`, `Carthago.Tests/ProtocolIntelligence/**` and `docs/protocols/**`. No overlap with these three UI-owned paths. Source candidate `d364b4818e667c5d71ece820acb562267ac73772` has parent `90d3cc1cac10f8da4462fcaa58ccbf4ae0ac8c9b` and changes only the two WPF UI paths; the existing status updater, source-health tooltip, capture source, event consumers, names and responsive layout remain intact. The reference image, naming, historical timestamp provenance and privacy boundaries were inspected.

**End/publication gate:** re-read LIVE remote HEAD immediately before publication; compare all intervening changes and owned-path blobs, inspect source/docs ancestry and final diff, then publish the complete source/docs chain with exactly one non-forced `update_ref` protected by `expected_sha` on the same existing branch. On disjoint concurrent changes, rebuild both private commits on fresh HEAD with a new lease; STOP on any overlap, missing guarantee or uncertainty. No partial publication, history rewrite, branch/PR creation or independent-stream modification.

**Residual risks:** actual Windows WPF compilation, `AutomationProperties.LabeledBy` resolution, accessible name/value announcements, screen-reader reading order, disabled/paused status, high contrast, keyboard focus, 125–200% DPI and 1440/1100/1099/1024/1023/640px rendering remain **UNVERIFIED**. The historical timestamp may remain visible during paused/offline states; the new suffix disclaims liveness but does not prove accuracy or freshness. The original capture-source/flow diagnostic tooltip remains unchanged; no new host/event data is collected, transmitted, persisted or logged. Static review is not runtime validation or accessibility certification.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Last analysis visible caption and existing status element are unchanged in placement, text source and `x:Name`.
2. Historical `LastAnalysisUtc` displays local date/time with **(recorded)**, never **(Live)**.
3. Paused/offline monitoring with an old analysis timestamp does not claim current traffic or active capture.
4. Error, degraded, starting, idle and waiting branches retain their original status text and conditions.
5. Existing source-health and flow-diagnostic tooltip remains sourced from the original capture pipeline.
6. The status element's UI Automation `LabeledBy` resolves to the unique visible Last analysis caption and its HelpText explains recorded data limitations.
7. Periodic status updates do not create a new assertive or polite live region; screen-reader behavior is inspected on Windows.
8. Wide, Standard, Compact and below-1024 layouts preserve header wrapping and label readability at 125–200% DPI and high contrast.
9. PPS ScottPlot, incident selection/investigation, KPI cards, read-only Live Events, unavailable CLI, Cisco/WebView2 and all navigation remain untouched.
10. No demo telemetry or new capture-health assertion appears; independent detection/protocol paths, privacy and security boundaries are unchanged.

**Open quality GAs:** pinned-SHA Windows WPF build, actual UI Automation/screen-reader/keyboard inspection, paused/offline timestamp review, high-contrast/DPI/responsive screenshots and status-provenance regression **only after the owner explicitly says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-36:** inspect fresh LIVE HEAD, exact approved reference, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–35.

**References:** [WPF AutomationProperties.LabeledBy](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.labeledby); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF AutomationProperties.LiveSetting](https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.automationproperties.livesetting).

## GA UI-36 — Keyboard access to existing KPI information glyphs

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE branch HEAD: `5f271c6b19fa157916639a4ff62404d821427d65`. Prior GA UI-35 publication: `f59c495cbf84d627f165e3b6c35cca2787481cda`; prior UI source: `d364b4818e667c5d71ece820acb562267ac73772`. **Exact GA UI-36 source commit:** `61b9c4ca72bea080a89a551b393b5848b0ef7e63`. **Owned paths:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; executed: 0.** No builds, xUnit, replays, holdouts, CI, GitHub Actions, runners, benchmarks, production capture or running-WPF screenshots.

### Approved reference and original consumer audit

Resolved and visually inspected exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`: dark navy/graphite dashboard, cyan/teal accents, restrained severity, left navigation, KPI strip, incident investigation and event table. All screenshot IPs, rule IDs, Mbps, confidence, timestamps and terminal lines are **DEMO ONLY**. No screenshot telemetry was inserted. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024; local PPS ScottPlot (10-sample average, bounded 120-point history), prioritized incident/anomaly snapshots (150/160), investigation, read-only local Live Events (80 displayed / 500 retained), explicitly **UNAVAILABLE** visual-only CLI, Cisco/WebView2 and all existing capture and security behavior.

Inspected live HEAD and recent commits, ledger through UI-35, `MainWindow.xaml` shared `DashboardKpiCardTemplate` and its two ItemsControl consumers, `MainWindow.Dashboard.cs` `SocKpiVm.InformationText`/`InformationAccessibilityName` and original KPI metric producers, `Theme.xaml` `SocInfoGlyph`/`KeyboardFocusVisual`, `MainWindow.xaml.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.Responsive.cs`, `MainWindow.DashboardResponsive.cs`, and navigation/partials. GA UI-30 already supplies source-specific read-only KPI descriptions to the existing information glyph and KPI value; it does not make the glyph keyboard-focusable. No source or shared contract change is required.

### One cohesive UI-owned improvement

Make only the **existing informational TextBlock** in the shared KPI card template focusable and a tab stop; apply the existing cyan `KeyboardFocusVisual` and WPF `ToolTipService.ShowsToolTipOnKeyboardFocus=True` to expose the already-bound `InformationText` when keyboard-focused. Preserve the original glyph, title, source-specific tooltip and UI Automation Name/HelpText bindings, card geometry, styles, value, trend, colors, layout, ItemsControl data and responsive consumers. The glyph remains **informational only**: no Button, Click, Command, menu, action, live region, metric producer or new data flow. This applies to the existing overview and additional KPI cards through the same template, without duplicating cards or adding controls.

### Static divergence, provenance and publication guard

**Start:** LIVE HEAD `5f271c6b19fa157916639a4ff62404d821427d65` descends from UI-35 publication and includes independent protocol changes. Compare intervening files before publication; do not modify detection/protocol paths. Source candidate `61b9c4ca72bea080a89a551b393b5848b0ef7e63` is a direct child of `5f271c6b19fa157916639a4ff62404d821427d65`, changing only `Carthago/Views/MainWindow.xaml`. The original shared KPI template is the only modified source region; all WPF partials, viewmodel producers, theme keys, control names, monitoring APIs and privacy boundaries are unchanged.

**End/publication gate:** re-read LIVE remote HEAD immediately before publication, compare intervening paths and original consumers, verify private source/docs ancestry, owned path diff and blobs, then publish both commits via **one** non-forced atomic `update_ref` with `expected_sha` lease on the existing branch. On disjoint concurrent changes, rebuild from fresh HEAD; STOP on overlap or missing lease guarantee. Never publish partially or alter independent automations.

**Residual risks:** WPF compilation, TextBlock tab traversal, keyboard-focused tooltip appearance/timing, UI Automation peer announcements, screen-reader behavior, keyboard focus outline clipping, 125–200% DPI, high contrast and responsive screenshots are **UNVERIFIED**. The change introduces one additional focus stop per visible KPI card (up to nine by default); confirm this does not burden keyboard navigation. Tooltip content is an explanation of the existing local source, not capture-health, sensor coverage or detection-accuracy proof. No new host, IP, event or personal data is collected, stored, logged or transmitted.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Tab reaches the existing information glyph in every visible overview and additional KPI card without activating any command.
2. Keyboard focus visibly uses the existing cyan `KeyboardFocusVisual`, without changing unfocused card geometry or colors.
3. Keyboard focus displays the original source-specific `InformationText` tooltip, and Shift+Tab/Tab dismisses or moves it appropriately.
4. Mouse hover continues to display the same original tooltip and does not trigger an action.
5. UI Automation exposes the existing metric-specific `InformationAccessibilityName` and `InformationText` HelpText on the focusable glyph; inspect actual screen-reader behavior.
6. All nine known KPI explanation variants preserve their original source limitations; unavailable sensor/coverage values remain unavailable.
7. Existing KPI value, trend glyph, metric updates, layout preferences, and overview/additional ItemsControl bindings remain unchanged.
8. Wide/Standard/Compact and below-1024 layout at 1440/1100/1099/1024/1023/640px, 125–200% DPI and high contrast keep glyph, focus outline and tooltip readable without clipping.
9. Local PPS ScottPlot, incidents/investigation, read-only Live Events, unavailable CLI, Cisco/WebView2, monitoring controls and navigation remain untouched.
10. No demo telemetry or new capture-health/accuracy claim appears; independent detection/protocol paths, security and privacy boundaries remain unchanged.

**Open quality GAs:** pinned-SHA Windows WPF build, actual tab/focus/tooltip/UI Automation/screen-reader inspection, high-contrast/DPI/responsive screenshots and provenance regression **only after the owner says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-37:** inspect fresh LIVE HEAD, exact approved reference, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–36.

**References:** [WPF ToolTipService.ShowsToolTipOnKeyboardFocus](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice.showstooltiponkeyboardfocus); [WPF KeyboardNavigation.IsTabStop](https://learn.microsoft.com/en-us/dotnet/api/system.windows.input.keyboardnavigation.istabstop); [WPF FocusVisualStyle](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/styling-for-focus-in-controls-and-focusvisualstyle).

## GA UI-37 — Keyboard access to three dashboard summary information glyphs

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE branch HEAD: `de175b4a613f24514714048f1080e37ed37faa56`; prior GA UI-36 source `61b9c4ca72bea080a89a551b393b5848b0ef7e63`, publication `74cbcf62817a987dbbcf5e593c3f222a6fd5fbea`. **Exact GA UI-37 source SHA:** `ded80d734ebc7ef4fa6359389888079425defd19`. **Owned changed paths:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; executed: 0.** No builds, xUnit, replays, holdouts, CI, GitHub Actions, runners, benchmarks, production capture or running-WPF screenshots.

### Approved reference, provenance and original consumers

Resolved and visually inspected exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`: dark navy/graphite surfaces, cyan/teal accents, restrained severity, left navigation, operational KPI cards, traffic chart, incidents, investigation and local events. All screenshot IPs, rule IDs, Mbps, confidence, timestamps and CLI lines are **DEMO ONLY**, not application telemetry or capture-health evidence. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099, graceful below 1024, 10-sample PPS average/120-point bounded ScottPlot history, incident-first ranking, investigation, read-only local Live Events (80 displayed/500 retained), explicitly **UNAVAILABLE** visual-only CLI, Cisco/WebView2, privacy and security boundaries.

Audited live branch HEAD, recent commits, ledger through UI-36, `MainWindow.xaml` dashboard summary panel headings and their original tooltip/AutomationProperties consumers, `MainWindow.Dashboard.cs` local host/action/shortcut producers and navigation handlers, `MainWindow.xaml.cs`, `MainWindow.Navigation.cs`, `MainWindow.Responsive.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.DashboardEvents.cs`, `Sidebar.xaml(.cs)` and `Views/Theme.xaml` `SocInfoGlyph`/`KeyboardFocusVisual`. GA UI-32 already added accurate hover-only source explanations to **High-Risk Hosts**, **Recommended Actions**, and **Raw / Advanced Shortcuts**, but the three information glyphs remained non-focusable. GA UI-36 addressed a separate shared KPI-card glyph, not these summary panels. No viewmodel, shared API or new source contract is required.

### One cohesive UI-owned improvement

On exactly the three existing summary-panel information `TextBlock` glyphs, add `Focusable=True`, `KeyboardNavigation.IsTabStop=True`, the existing `KeyboardFocusVisual`, and `ToolTipService.ShowsToolTipOnKeyboardFocus=True`. Add `AutomationProperties.HelpText` identical to each already-established source-specific tooltip, while retaining its existing `AutomationProperties.Name`. The glyphs remain informational, with no command, menu, Click, route, live region or new data producer. Preserve the original captions, tooltips, glyph text, `SocInfoGlyph` style, geometry, responsive layout, incident/host/action list bindings, existing navigation and capture behavior. No new screenshot data, telemetry, risk calculation, remediation or security assertion.

### Start/end static divergence and publication guard

**Start:** LIVE HEAD `de175b4a613f24514714048f1080e37ed37faa56` descends from UI-36 publication via three independent commits: protocol GA P0181–P0190, DNS wire-name codec and test-source compilation corrections. Comparison against `74cbcf62817a987dbbcf5e593c3f222a6fd5fbea` found only independent `Carthago/Services/**`, `Carthago.Tests/**`, and `docs/protocols/**` paths; no overlap with these two UI-owned paths. The candidate source commit `ded80d734ebc7ef4fa6359389888079425defd19` has parent `de175b4a613f24514714048f1080e37ed37faa56` and changes only `MainWindow.xaml`; original handlers, WPF partials, named controls, resources and privacy boundaries are untouched.

**End/publication gate:** re-read LIVE remote HEAD immediately before publication; compare intervening commits and paths, verify candidate parent/tree, source/docs blobs and owned-path-only diff, and publish complete source/docs ancestry with exactly one non-forced atomic GitHub `update_ref` using `expected_sha` on the existing branch. If the branch advances with disjoint changes, rebuild both private commits from fresh HEAD and obtain a fresh lease; STOP on overlap or missing atomic lease guarantee. Never overwrite independent changes or publish partially.

**Residual risks:** actual Windows WPF compilation, keyboard focus traversal on `TextBlock`, focus-outline rendering, tooltip timing, screen-reader announcements, UI Automation HelpText exposure, high contrast, 125–200% DPI and responsive screenshots remain **UNVERIFIED**. Three additional tab stops may increase keyboard navigation burden. Tooltip focus behavior may vary with WPF version or assistive technology. The informational text describes local ranking, suggestions and existing view destinations; it does not certify detection confidence, host inventory completeness, remediation or capture health. No new host/event data is collected, stored, transmitted or logged.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Tab and Shift+Tab reach the three existing summary information glyphs in predictable order without activating commands.
2. Keyboard focus uses the existing cyan focus visual and remains legible without changing unfocused layout.
3. Keyboard focus exposes the existing High-Risk Hosts local-ranking tooltip; risk remains explicitly distinct from confidence.
4. Keyboard focus exposes the existing Recommended Actions explanation; no remediation executes.
5. Keyboard focus exposes the existing Raw / Advanced Shortcuts destination explanation; no separate PCAP/forensics workspace is claimed.
6. Hover behavior, existing tooltip wording, AutomationProperties.Name and new matching HelpText remain consistent; inspect real screen-reader behavior.
7. All original panel headings, host/action/shortcut bindings, navigation handlers, names, styling and geometry remain unchanged.
8. At 1440/1100/1099/1024/1023/640px, 125–200% DPI and high contrast, tooltips/focus outlines are readable without clipping.
9. Local PPS ScottPlot, KPIs, incident investigation, read-only Live Events, unavailable CLI, Cisco/WebView2, capture controls and navigation are unaffected.
10. No demo telemetry, fabricated health claim, new privacy/security behavior or independent detection/protocol change is introduced.

**Open quality GAs:** pinned-SHA Windows WPF build, actual tab/focus/tooltip/UI Automation/screen-reader inspection, high-contrast/DPI/responsive screenshots and source-provenance review **only after owner says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-38:** inspect fresh LIVE HEAD, approved reference, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–37.

**References:** [WPF keyboard tooltip behavior](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice.showstooltiponkeyboardfocus); [WPF keyboard tab stop](https://learn.microsoft.com/dotnet/api/system.windows.input.keyboardnavigation.istabstop); [WPF focus visuals](https://learn.microsoft.com/dotnet/desktop/wpf/advanced/styling-for-focus-in-controls-and-focusvisualstyle); [WPF UI Automation HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext).

## GA UI-38 — Below-1024 incident investigation fact-card readability

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE branch HEAD: `ba498943d762b962ed3e0c146cbd242ed5504510`; previous GA UI-37 source `ded80d734ebc7ef4fa6359389888079425defd19`, publication `92b4e346f798f439646edbebcb34d278582cf529`. Independent protocol GA P0191–P0200 is present in the starting HEAD. **Exact GA UI-38 source commit:** `b8578005ddcda5982b9debe80747540c6f49c0d3`. **Owned paths:** `Carthago/Views/MainWindow.xaml`, `Carthago/Views/MainWindow.DashboardResponsive.cs`, and this `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; executed: 0.** No build, xUnit, replays, holdouts, CI, GitHub Actions, runners, benchmarks, production capture or running-WPF screenshots.

### Approved reference, source and consumer audit

Resolved and visually inspected the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`: navy/graphite security overview, cyan/teal accents, restrained severity, left navigation, operational KPIs, traffic chart, incident investigation, local events and visual-only CLI. All screenshot IPs, rule IDs, timestamps, Mbps, confidence percentages and terminal lines are **DEMO ONLY**; none are used as application telemetry or capture-health evidence. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024, the local PPS ScottPlot ten-sample average and bounded 120-point history, prioritized incidents/anomalies, investigation, read-only local Live Events (80 displayed / 500 retained), explicitly **UNAVAILABLE** CLI, Cisco/WebView2 and all existing privacy/security boundaries.

Inspected live HEAD, recent commits and ledger through GA UI-37; `MainWindow.xaml` investigation panel, six existing `DetailGridCard` fact cells and their labels/values; `MainWindow.DashboardResponsive.cs` and `MainWindow.Responsive.cs` layout consumers; `ResponsiveLayout.cs` thresholds; `MainWindow.Dashboard.cs` original selected-incident/anomaly fact assignments; `MainWindow.xaml.cs` initialization; `MainWindow.Navigation.cs`, `MainWindow.Core.cs`, `MainWindow.DashboardEvents.cs`, `Sidebar.xaml(.cs)` and `Theme.xaml`. No shared API, new viewmodel, data producer, capture behavior or detection/protocol change is required. GA UI-12/21/25 established fact labels, risk provenance and supporting-context semantics; this change is confined to **narrow-window fact-card layout**, not those behaviors.

### One cohesive UI-owned improvement

Name the existing six-field `UniformGrid` `DashboardDetailFactsGrid` without changing its children, source bindings, original three-column XAML default, labels, values, colors, card styles, margins or tooltips. In the existing `ApplyDashboardResponsiveLayout` method, use the already-computed `narrowKpis` threshold to show **two fact columns below 1024px**, while retaining **three columns at 1024px and above**. The six original fact cards retain order (source host, destination, protocol/port, category, detected, related incident). This gives long hostnames and timestamps more horizontal space in the narrowest view, at the cost of one additional fact row. No change to selected item, incident triage, risk scoring, capture, telemetry, handlers, routes, PPS, Live Events or CLI. The name is unique in the audited source.

### Start/end static divergence, provenance and publication gate

**Start:** `ba498943d762b962ed3e0c146cbd242ed5504510` descends from the prior UI-37 publication `92b4e346f798f439646edbebcb34d278582cf529` via independent protocol P0191–P0200 changes. The GA UI-38 private source commit `b8578005ddcda5982b9debe80747540c6f49c0d3` is a direct child of `ba498943d762b962ed3e0c146cbd242ed5504510` and changes only `Carthago/Views/MainWindow.xaml` (one named grid) and `Carthago/Views/MainWindow.DashboardResponsive.cs` (one existing responsive property assignment). Existing WPF partials, original consumers, resource names, privacy/security boundaries, and independent paths are not edited. Source-only static review confirms these two changed paths and the intended diff; it does **not** establish compilation or runtime behavior.

**End/publication gate:** re-read LIVE remote HEAD immediately before publishing; compare any concurrent detection/protocol/UI changes and paths, review exact candidate parent/tree, source/docs blobs, naming and the full owned-path diff. Publish the complete two-commit source/docs chain via **one** non-forced atomic GitHub `update_ref` using `expected_sha` on the same existing branch. If HEAD moves with disjoint changes, rebuild both private commits from the fresh HEAD and use a fresh lease; STOP on overlap, unavailable lease guarantee or uncertain ownership. Never publish partially, force push, rewrite history, create a branch/PR, or change independent automations.

**Residual risks:** Windows WPF compilation and generated `x:Name` field resolution, actual grid reflow, card height and internal scroll space, tooltip clipping, row margins, keyboard and screen-reader reading order, high contrast, 125–200% DPI, 1440/1100/1099/1024/1023/640px screenshots and rapid resize transitions are **UNVERIFIED**. Existing per-card margins were preserved; the two-column wrap may produce asymmetric horizontal gaps or a taller fact region and must be inspected. The narrower breakpoint follows the existing `narrowKpis` threshold and does not change how capture or incidents work. No new host, IP, event, rule, timestamp, confidence or personal data is collected, stored, transmitted or logged.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. At 1440px Wide and 1100px Standard, the existing six incident fact cards remain in three columns with original order, styling, values and tooltips.
2. At 1099px and 1024px Compact, the same three-column fact layout remains unchanged.
3. At 1023px and 640px, the six fact cards wrap into two columns and three rows without horizontal overflow or clipped headings.
4. Resize across 1023/1024 repeatedly; the existing responsive method restores the correct number of columns without stale presentation.
5. At 125%, 150% and 200% DPI, hostnames, destination, protocol/port, category, detected timestamp and related incident remain readable or expose their original full-value tooltips.
6. The incident investigation panel retains accessible labels and predictable keyboard/screen-reader reading order; no unintended focus stops are introduced.
7. The selected correlated incident/anomaly and its six original values remain identical before and after resizing, including waiting/empty states.
8. The added fact row does not conceal reasons, tags, related rule IDs, recommended actions or the Full detail control; internal scroll behavior remains usable.
9. PPS ScottPlot history/average, KPI cards, prioritized incidents, Live Events 80/500 retention, visual-only unavailable CLI, Cisco/WebView2, sidebar and capture controls remain unchanged.
10. No screenshot demo values, fabricated telemetry, capture-health assertions, privacy/security changes, shared API changes or independent detection/protocol modifications appear.

**Open quality GAs:** pinned-SHA Windows WPF build, actual responsive/keyboard/screen-reader/high-contrast/DPI inspection and screenshots **only after the owner explicitly says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-39:** inspect fresh LIVE HEAD, exact approved reference, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–38.

**References:** [WPF UniformGrid](https://learn.microsoft.com/en-us/dotnet/api/system.windows.controls.primitives.uniformgrid); [WPF responsive layout and panels](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/panels-overview); [WPF accessibility](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/accessibility).

## GA UI-39 — Full-text hover for truncated investigation heading and summary

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `208f1ccb943b7434098f95e7516d2c3b69b95b42`. Previous GA UI-38 source `b8578005ddcda5982b9debe80747540c6f49c0d3`, publication `588780d08dc730be0001ff164c11133dd1853cd7`. Independent GA P0201–P0210 protocol work was already present in the starting HEAD. **Exact GA UI-39 source SHA:** `6d7f6101cf5205c97b9617053e1bc1669cb85a57`. **Authorized changed paths:** `Carthago/Views/MainWindow.xaml` and this `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; executed: 0.** No build, test, replay, holdout, CI, GitHub Actions, runner, benchmark, capture, running WPF inspection or screenshot.

### Approved reference, WPF consumer audit and scope

Resolved and **visually inspected** exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`: dark navy/graphite dashboard, cyan/teal accents, restrained severity, left navigation, operational KPIs, local traffic chart, incident investigation, read-only Live Events and visual-only CLI. Screenshot IPs, metrics, timestamps, rule IDs, confidence and inbound/outbound Mbps lines are **DEMO ONLY**; none are used as observed telemetry, detection accuracy or capture-health evidence.

Audited the live remote HEAD and the ledger through UI-38, `MainWindow.xaml` investigation header/facts and existing WPF partials `MainWindow.Dashboard.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.xaml.cs`, `MainWindow.DashboardEvents.cs` and `Theme.xaml`. The existing investigation `DashboardDetailTitleText` and `DashboardDetailSubtitleText` are programmatically populated from the current local incident/anomaly/empty-state projection by `MainWindow.Dashboard.cs`. Both already wrap but are bounded by `MaxHeight` (54px and 36px) with `TextTrimming="CharacterEllipsis"`; neither previously exposed the full value by hover. The six fact values already have self-text tooltips; UI-38 changed only their responsive columns, not these heading/summary fields. No shared API or viewmodel change is necessary.

### One cohesive UI-owned improvement

Add `ToolTip="{Binding Text, RelativeSource={RelativeSource Self}}"` to the **existing two investigation header TextBlocks only**. Hover can expose the same full currently displayed title/summary value when the bounded visual text is truncated. The self-text bindings track the original `Text` dependency property, including selected incident, selected anomaly and waiting states, without caching, copying, transforming or persisting values. Retain existing `x:Name`, text, wrapping, trimming, maximum heights, margins, colors, layout, selection, labels and code-behind assignments. No new focus stop, command, navigation, evidence payload, telemetry or capture-state claim. Tooltip presentation and accessibility remain **UNVERIFIED** until owner-authorized Windows inspection.

Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024; local PPS ScottPlot ten-sample average and bounded 120-point history; prioritized incidents, six-field investigation, read-only local Live Events (80 displayed/500 retained), explicitly **UNAVAILABLE** visual-only CLI, Cisco/WebView2 and privacy/security boundaries. No demo values introduced.

### Start/end static divergence, provenance and publication guard

**Start:** LIVE HEAD `208f1ccb943b7434098f95e7516d2c3b69b95b42` is one independent protocol commit after UI-38 publication `588780d08dc730be0001ff164c11133dd1853cd7`. GitHub comparison shows the intervening paths only in `Carthago/Services/ProtocolIntelligence/IgrpPacketInspector.cs`, `Carthago.Tests/ProtocolIntelligence/IgrpPacketInspectorTests.cs` and `docs/protocols/**`; no UI ownership overlap. The private source commit `6d7f6101cf5205c97b9617053e1bc1669cb85a57` has parent `208f1ccb943b7434098f95e7516d2c3b69b95b42`, modifies only `Carthago/Views/MainWindow.xaml`, and changes exactly two TextBlock opening tags. Original WPF partial consumers, route handlers, names, responsive logic, data producers, security/privacy and independent streams are read-only.

**End/publication gate:** immediately before publication re-read LIVE remote HEAD, compare concurrent commits and changed paths against `208f1ccb943b7434098f95e7516d2c3b69b95b42`, review private source/docs commit ancestry, source SHA in ledger, exact two owned paths, original consumer names and bindings, and approved reference fidelity. Publish both prepared commits together via exactly one non-forced atomic GitHub `update_ref` with `expected_sha` on the existing branch. If moved, reconcile disjoint paths against fresh HEAD with new private commits and lease; STOP on conflict or unavailable guarantee. Never publish partially, force push, create branch/PR, rewrite history or modify independent automations.

**Residual risks:** WPF compilation and tooltip binding resolution, full text availability on hover, tooltip delay/placement and clipping near window edges, dynamic title/summary updates while hovering, keyboard-only access (TextBlocks remain non-focusable), screen-reader exposure, high contrast, 125–200% DPI, 1440/1100/1099/1024/1023/640px layouts and screenshots remain **UNVERIFIED**. Hover is not a substitute for keyboard or screen-reader review. The text is the same locally selected incident/anomaly projection already shown in the UI; no raw evidence, new host/event data, personal data, external request or security claim is introduced.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Hover over a long incident title; the tooltip shows its complete existing title even when the 54px header is trimmed.
2. Hover over a long anomaly description; the tooltip shows the complete existing summary even when the 36px subtitle is trimmed.
3. Change the selected incident/anomaly and confirm both tooltip texts track the new original `Text` values without stale content.
4. In waiting/empty states, both tooltips reflect the original waiting text and introduce no synthetic events or monitoring claims.
5. At Wide 1440px and Standard 1100px, headings retain original geometry, wrapping, typography, severity treatment and selection.
6. At Compact 1099/1024px and below-1024 1023/640px, tooltip placement remains legible without obscuring investigation controls.
7. At 125%, 150% and 200% DPI and high contrast, long titles and summaries remain accessible by hover; inspect keyboard/screen-reader limitations separately.
8. Existing six fact cards, responsive two/three columns, fact tooltips, reasons, tags, rules, actions and Full detail control remain unchanged.
9. Local PPS ScottPlot, KPIs, Live Events 80/500, visual-only unavailable CLI, Cisco/WebView2, navigation and capture controls remain unchanged.
10. No fabricated screenshot data, telemetry, capture-health assertion, privacy/security change, shared API modification or independent detection/protocol file change occurs.

**Open quality GAs:** pinned-SHA Windows WPF build and actual tooltip/keyboard/screen-reader/high-contrast/DPI/responsive screenshot inspection **only after owner explicitly says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-40:** inspect fresh LIVE HEAD, approved reference, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–39.

**Reference:** [Microsoft WPF ToolTip property](https://learn.microsoft.com/en-us/dotnet/api/system.windows.frameworkelement.tooltip); [WPF accessibility](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/accessibility).

## GA UI-40 — Live Events filter and reset accessibility context

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE branch HEAD: `19113199f4aa12e3fa884d689984ff564cdeea54`; prior GA UI-39 source `6d7f6101cf5205c97b9617053e1bc1669cb85a57`, publication `acc73a5b092d54d9eab76eec7cc20523aaab0e82`. Independent protocol GA P0211–P0220 documentation was present at the start. **Exact GA UI-40 source SHA:** `ca932d39a1dc34687e5d62a9a44aada43f78961b`. **Owned paths:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; executed: 0.** No dotnet build/test, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, production capture, running-WPF inspection or screenshot.

### Approved reference, original consumers and provenance

Resolved and **visually inspected** the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`: navy/graphite security overview, cyan/teal accents, restrained severity, left navigation, operational KPIs, traffic chart, prioritized incidents, investigation, read-only local Live Events and visual-only CLI. All screenshot IPs, rule IDs, metrics, timestamps, confidence, Mbps lines and CLI text are **DEMO ONLY**, not observed telemetry or capture-health evidence.

Reviewed LIVE HEAD, recent commits, this ledger through UI-39, `MainWindow.xaml` Live Events filter row, `MainWindow.DashboardEvents.cs` filter/reset handlers and original `_alerts` projection, `MainWindow.xaml.cs`, `MainWindow.Filters.cs`, `MainWindow.Dashboard.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.GridInteractions.cs` and `Theme.xaml`. The four controls already have visible labels (UI-16 and UI-26), existing tooltips, automation names, bindings and event handlers. UI-33 covered Evidence/Delivery **column headers**, not these filter controls. Original filtering operates on locally retained `_alerts` (500 max) and shows at most 80 rows; the reset button clears only the four dashboard filters. No shared API, new viewmodel or producer is needed.

### One cohesive UI-owned improvement

Add explicit `AutomationProperties.HelpText` to the **existing** Severity and Protocol ComboBoxes, Rule and Search TextBoxes, and Clear filters Button. Explain the existing retained-local-event scope, that protocol All includes other protocols, rule filtering does not alter rule execution, metadata search excludes raw evidence and archived records, and reset does not delete retained events or reset other views. Reuse original captions, `AutomationProperties.Name`/`LabeledBy`, tooltips, selected options, widths, colors, margins, focus/tab order, `SelectionChanged`, `TextChanged` and `Click` handlers. No new focus stops, filtering conditions, data collection, capture-health assertions, commands or security behavior.

Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024; real local PPS ScottPlot ten-sample average and bounded 120-point history; KPIs, prioritized incidents/investigation, read-only Live Events (80 displayed/500 retained), explicitly **UNAVAILABLE** visual-only CLI, Cisco/WebView2, trust/privacy and independent detection/protocol streams.

### Start/end static divergence and publication gate

**Start:** `19113199f4aa12e3fa884d689984ff564cdeea54` descends from UI-39 publication `acc73a5b092d54d9eab76eec7cc20523aaab0e82` by one independent protocol-docs commit; GitHub comparison shows only `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md` and `docs/protocols/PROTOCOL_GA_P0211-P0220.md`, no UI-owned overlap. Prepared private source commit `ca932d39a1dc34687e5d62a9a44aada43f78961b` is a direct child of `19113199f4aa12e3fa884d689984ff564cdeea54` and changes only `Carthago/Views/MainWindow.xaml`, adding five static WPF help-text attributes. Original consumers, APIs, capture/detection behavior, theme and responsive logic are unchanged.

**End/publication gate:** immediately re-read LIVE branch HEAD and compare concurrent detection/protocol/UI paths against `19113199f4aa12e3fa884d689984ff564cdeea54`; verify source/docs ancestry, source SHA, exact owned paths, WPF names/consumers, privacy and approved reference. Publish the **complete** two-commit chain with **one** non-forced atomic GitHub `update_ref` and `expected_sha` lease on the existing branch. If HEAD moves disjointly, reconstruct both private commits on the fresh HEAD with a new lease; STOP on conflict or unavailable lease guarantee. Never overwrite independent work or publish partially.

**Residual risks:** Windows WPF compilation, UI Automation HelpText exposure, actual screen-reader phrasing, keyboard focus order, tooltip behavior, filter semantics in a running app, high contrast, 125–200% DPI and 1440/1100/1099/1024/1023/640px screenshots remain **UNVERIFIED**. The static help text is descriptive and does not prove actual event delivery, monitoring health, rule coverage or accuracy. No new event, host, IP, rule, evidence payload or personal data is collected, logged, stored or transmitted.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Keyboard Tab/Shift+Tab reaches the original four filter controls and Clear filters button in the original order without added focus stops.
2. UI Automation exposes the Severity filter's existing visible label and new retained-local-event HelpText.
3. Protocol filter HelpText accurately describes the All option, including protocols outside TCP/UDP/ICMP.
4. Rule filter HelpText explains exact/partial ID filtering without suggesting rule activation or rule evaluation changes.
5. Search filter HelpText explains source/destination/rule/protocol metadata only, not evidence payload or archived-event search.
6. Clear filters HelpText and original handler preserve retained detection rows and other views' independent filters.
7. Original ComboBox selections, TextBox text, filtering, empty/no-match messages, row order and 80/500 bounds remain unchanged.
8. Wide 1440, Standard 1100, Compact 1099/1024 and below-1024 1023/640px, 125–200% DPI and high contrast preserve labels, controls and focus outlines.
9. Local PPS ScottPlot, KPIs, incident selection/investigation, unavailable CLI, Cisco/WebView2, sidebar and capture controls remain unaffected.
10. No fabricated demo telemetry, capture-health proof, privacy/security change, shared API change or independent detection/protocol file modification occurs.

**Open quality GAs:** pinned-SHA Windows WPF build, real keyboard/screen-reader/UI Automation/filter/tooltip inspection, high-contrast/DPI/responsive screenshots and source-provenance review **only after the owner explicitly says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-41:** inspect fresh LIVE HEAD, exact approved image, ledger and WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–40.

**Reference:** [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF accessibility](https://learn.microsoft.com/dotnet/desktop/wpf/advanced/accessibility).

## GA UI-41 — Live Events recorded-time header provenance

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE branch HEAD: `1b725bff495ed4675e38755780ca51923bae3a67`; prior GA UI-40 source `ca932d39a1dc34687e5d62a9a44aada43f78961b`, publication `72ab688179bbb20c8ee8ab46b5862154ef465e59`. Independent protocol documentation GA P0221–P0230 was present before this UI work. **Exact GA UI-41 source SHA:** `6232c8f1a63f60bcd661a74f6c945585dd7b9da3`. **Owned paths:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; executed: 0.** No dotnet build/test, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, production capture, running-WPF inspection or screenshot.

### Approved reference and audited original consumers

Resolved and **visually inspected** exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`: navy/graphite security overview, cyan/teal accents, restrained severity, left navigation, operational KPIs, traffic chart, prioritized incidents, investigation, read-only local Live Events and visual-only CLI. Its IPs, metrics, rule IDs, timestamps, confidence, Mbps lines and CLI text are **DEMO ONLY**; no screenshot value is observed telemetry or evidence of capture health.

Audited LIVE remote branch HEAD, recent commits, this ledger through UI-40, `MainWindow.xaml` Live Events grid, `MainWindow.DashboardEvents.cs` event projection and original filters, `MainWindow.Dashboard.cs`, `MainWindow.xaml.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.GridInteractions.cs` and `Theme.xaml`. Original `DashboardEventRowVm.FromDetection` formats `DetectionEvent.Timestamp` with `yyyy-MM-dd HH:mm:ss` without conversion and explicitly avoids asserting its timezone; a default timestamp displays `—`. The read-only `DashboardLiveEventsGrid` already states the timezone caveat at grid level and in provenance text, but its visible **Event time** column header had no contextual tooltip or header-level Automation HelpText. GA UI-33 addressed Evidence/Delivery headers; UI-40 addressed filters; neither changed this header. No shared API or viewmodel change is necessary.

### One cohesive UI-owned improvement

Add `DataGridTextColumn.HeaderStyle` only to the original **Event time** column, based on the existing theme's `DataGridColumnHeader` style, with a tooltip and `AutomationProperties.HelpText` explaining that the value is the recorded detection-event timestamp as supplied, timezone **unverified**, and does not establish active capture or successful delivery. Keep the original `Header="Event time"`, `Binding="{Binding EventTime}"`, width 144, frozen-first-column behavior, column order, formatting, keyboard behavior, filters, row virtualization, 80 displayed/500 retained, evidence/privacy boundaries, status/provenance captions and event producers unchanged. No new focus stops, controls, events, data conversions, telemetry, time-zone claims, capture-health claims or network calls.

Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024; local PPS ScottPlot ten-sample average and bounded 120-point history; operational KPIs, prioritized incidents, investigation, read-only Live Events, explicitly **UNAVAILABLE** visual-only CLI, Cisco/WebView2, trust/privacy and independent detection/protocol streams.

### Start/end static divergence, publication guard and risks

**Start:** LIVE HEAD `1b725bff495ed4675e38755780ca51923bae3a67` descends from GA UI-40 publication `72ab688179bbb20c8ee8ab46b5862154ef465e59` by one independent protocol-documentation commit. Comparison shows only `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md` and `docs/protocols/PROTOCOL_GA_P0221-P0230.md`; no UI-owned overlap. Prepared private source commit `6232c8f1a63f60bcd661a74f6c945585dd7b9da3` has parent `1b725bff495ed4675e38755780ca51923bae3a67` and changes only `Carthago/Views/MainWindow.xaml`. Original XAML names, WPF partial consumers, filters, responsive rules, theme resource keys, shared APIs, privacy and security remain untouched.

**End/publication gate:** immediately before publication re-read LIVE remote HEAD and compare any concurrent detection/protocol/UI paths against `1b725bff495ed4675e38755780ca51923bae3a67`; verify private source/docs commit ancestry, exact source SHA in this ledger, two owned paths, original names/consumers and reference fidelity. Publish complete source/docs chain via **one** non-forced atomic GitHub `update_ref` with `expected_sha` on the existing branch. If remote moves disjointly, reconstruct both private commits on fresh HEAD with fresh lease; STOP on conflict or missing guarantee. No partial publication, force push, new branch, PR, history rewrite or independent automation change.

**Residual risks:** WPF compilation, DataGrid header style lookup, tooltip presentation, actual UI Automation HelpText exposure, keyboard-only header discovery, screen-reader announcements, high contrast, 125–200% DPI, horizontal scrolling/frozen column and responsive 1440/1100/1099/1024/1023/640px screenshots remain **UNVERIFIED**. Tooltips may not be discoverable by keyboard alone. Text is static explanatory metadata; it does not prove event timing accuracy, active capture, delivery health or detection quality. No new IP, host, event, evidence payload, personal data or external transmission.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Hover Event time column header: tooltip explains recorded timestamp, unverified timezone and no capture/delivery inference.
2. UI Automation inspection exposes the Event time header's contextual HelpText without replacing the visible caption.
3. Original timestamp formatting `yyyy-MM-dd HH:mm:ss` and default `—` remain unchanged; no timezone conversion occurs.
4. Frozen first 144px column remains visible while horizontally scrolling all seven remaining columns.
5. Original DataGrid header theme, typography, foreground, border and column geometry remain unchanged.
6. Original row selection, keyboard cell focus, read-only virtualization, event order and 80/500 bounds remain unchanged.
7. At 1440/1100/1099/1024/1023/640px and 125–200% DPI/high contrast, tooltip and header remain readable; inspect screen-reader/keyboard limitations.
8. Evidence/Delivery header explanations, Severity/Protocol/Rule/Search filters and Clear filters behavior remain unchanged.
9. Local PPS ScottPlot, KPIs, incident investigation, unavailable CLI, Cisco/WebView2, sidebar and monitoring/capture controls remain unchanged.
10. No fabricated demo telemetry, capture-health assertion, privacy/security change, shared API change or independent detection/protocol file modification occurs.

**Open quality GAs:** pinned-SHA Windows WPF build and actual keyboard/screen-reader/UI Automation/tooltip/high-contrast/DPI/responsive screenshot inspection **only after the owner explicitly says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-42:** inspect fresh LIVE HEAD, approved reference, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–41.

**Reference:** [Microsoft WPF DataGridColumn.HeaderStyle](https://learn.microsoft.com/dotnet/api/system.windows.controls.datagridcolumn.headerstyle); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext).

## GA UI-42 — Live Events endpoint-header provenance

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE branch HEAD: `f23268539fe8aa798cf3d77d19a4acd54f82602c`; prior GA UI-41 source `6232c8f1a63f60bcd661a74f6c945585dd7b9da3`, publication `f1a94e19b0d943cd6c7d722c480995ec02f7d820`. **Exact GA UI-42 source SHA:** `5461f49f1d2026dde6a49c0f21f7ce0dd51353f1`. **Owned paths:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; executed: 0.** No dotnet build/test, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, production capture, running-WPF inspection or screenshot.

### Approved reference, live audit and original consumers

Resolved and **visually inspected** exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (navy/graphite, cyan/teal, restrained severity, left navigation, operational KPIs, traffic chart, prioritized incidents, investigation, read-only local Live Events and explicitly unavailable visual-only CLI). Screenshot IPs, rule IDs, confidence, timestamps, throughput and CLI text are **DEMO ONLY**, not observed telemetry, independently verified endpoint identities or capture-health evidence.

Audited LIVE remote HEAD, recent commits, this ledger through GA UI-41, `MainWindow.xaml` Live Events grid and original column/header theme, `MainWindow.DashboardEvents.cs` and `DashboardEventRowVm.FromDetection`, `MainWindow.Core.cs`, `MainWindow.xaml.cs`, `MainWindow.Filters.cs`, `MainWindow.GridInteractions.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs` and `Theme.xaml`. The existing view-only projection maps `DetectionEvent.SourceIp` and `DetectionEvent.DestinationIp` to the Source and Destination strings, displaying an em dash for missing/blank values. No source-validation, packet-attribution or connection-success claim is implied by these display fields. UI-33 covered Evidence/Delivery header provenance; UI-41 covered Event time; UI-40 covered filters. GA UI-42 does not repeat these.

### One cohesive UI-owned improvement

Add source-specific `DataGridTextColumn.HeaderStyle` tooltip and `AutomationProperties.HelpText` to the existing **Source** and **Destination** headers, inheriting the original `DataGridColumnHeader` theme. Clarify that both values are **reported local detection-event endpoint metadata**. Source is not independently verified host identity or packet attribution; Destination is not evidence of reachability or successful connection. Preserve original `Header`, `Binding`, `Width="*"`, `MinWidth="120"`, column positions, frozen Event time, selection, focus behavior, horizontal scrolling, filters, read-only virtualization, 80 displayed / 500 retained, original event projection and privacy boundaries. No new focus stops, event handlers, source transforms, network calls, telemetry, capture-health claims, detection logic, shared APIs or security controls.

Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099, graceful below 1024; local PPS ScottPlot ten-sample average and bounded 120-point history; KPIs, prioritized incidents/investigation, unavailable visual-only CLI and Cisco/WebView2 behavior.

### Start/end static divergence and publication guard

**Start:** `f23268539fe8aa798cf3d77d19a4acd54f82602c` descends from GA UI-41 publication `f1a94e19b0d943cd6c7d722c480995ec02f7d820`. Independent changes already present at the start (compared with prior UI publication): `Carthago.Tests/ProtocolIntelligence/BfcpHeaderInspectorTests.cs`, `Carthago/Services/ProtocolIntelligence/BfcpHeaderInspector.cs`, `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md`, `docs/protocols/PROTOCOL_GA_P0231-P0240.md`. These were read-only inputs, not changed by this GA. WPF partial consumers, names, event data projection, theme keys, privacy and approved visual reference were reviewed before source modification. The prepared source commit `5461f49f1d2026dde6a49c0f21f7ce0dd51353f1` is a direct child of `f23268539fe8aa798cf3d77d19a4acd54f82602c` and changes only `Carthago/Views/MainWindow.xaml`.

**End/publication gate:** re-read LIVE remote HEAD immediately before publication and compare any concurrent detection/protocol/UI changes against `f23268539fe8aa798cf3d77d19a4acd54f82602c`. Verify private source/docs commit ancestry, exact source SHA, the two owned paths, original WPF names/consumers, header theme and privacy/reference fidelity. Publish complete source/docs chain with **one** non-forced atomic GitHub `update_ref` and `expected_sha` lease on the existing branch. If remote moves disjointly, reconstruct both private commits on fresh HEAD with a fresh lease; STOP on conflict or missing guarantee. Never overwrite unrelated changes or publish partially.

**Residual risks:** Windows WPF compilation, DataGrid header style resolution, tooltip presentation, actual UI Automation HelpText exposure, keyboard-only header discovery, screen-reader announcements, high contrast, 125–200% DPI, horizontal scrolling/frozen column and responsive 1440/1100/1099/1024/1023/640px screenshots remain **UNVERIFIED**. Header tooltip discoverability by keyboard is not established. Descriptions are UI metadata only and do not prove endpoint identity, network reachability, capture health or detection accuracy. No new IP, host, event, evidence payload, personal data or external transmission.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Hover Source header: tooltip describes reported local event metadata and does not imply verified host identity or packet attribution.
2. Hover Destination header: tooltip does not imply endpoint reachability or successful connection.
3. UI Automation exposes Source and Destination contextual HelpText without replacing visible captions.
4. Original Source/Destination cell bindings and em-dash fallback remain unchanged, including missing/blank values.
5. Both columns retain star widths, 120px minima, order and the original DataGridColumnHeader theme.
6. Frozen Event time column, horizontal scrolling, row selection, keyboard cell navigation, virtualization and 80/500 bounds remain unchanged.
7. At 1440/1100/1099/1024/1023/640px, 125–200% DPI and high contrast, inspect headers, tooltip readability and keyboard/screen-reader limitations.
8. Existing Event time, Evidence, Delivery header guidance, four filters, Clear filters, status and provenance captions remain unchanged.
9. Local PPS ScottPlot, KPIs, incident investigation, unavailable CLI, Cisco/WebView2, sidebar and monitoring/capture controls remain unaffected.
10. No demo telemetry, endpoint verification claim, capture-health assertion, privacy/security change, shared API change or independent detection/protocol file modification occurs.

**Open quality GAs:** pinned-SHA Windows WPF build, keyboard/screen-reader/UI Automation/tooltip inspection and high-contrast/DPI/responsive screenshots **only after the owner explicitly says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-43:** inspect fresh LIVE HEAD, approved reference, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–42.

**References:** [WPF DataGridColumn.HeaderStyle](https://learn.microsoft.com/dotnet/api/system.windows.controls.datagridcolumn.headerstyle); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext).

## GA UI-43 — Live Events classification-header provenance

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE branch HEAD: `595377c8f93e4ea74b69f78df23d4fa38b4bc114`; prior GA UI-42 source `5461f49f1d2026dde6a49c0f21f7ce0dd51353f1`, documentation/publication `d473bf336cc29ffee00eb21fabc73ce1624b9a52`. Independent GA P0241–P0250 GVCP protocol changes were already present at the starting HEAD. **Exact GA UI-43 source SHA:** `01cb70212b174dac2b56d0f8b019dcf1b4cdb323`. **Owned paths:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; tests executed: 0.** No dotnet build/test, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, production capture, running-WPF inspection or screenshot.

### Approved design reference and source/consumer audit

Resolved and **visually inspected** the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`: navy/graphite dashboard, cyan/teal accents, restrained severity, left navigation, operational KPIs, traffic chart, prioritized incidents, investigation, read-only Live Events and visual-only CLI. Image IPs, metrics, rule IDs, timestamps, confidence, Mbps lines and CLI content are **DEMO ONLY**, never observed telemetry, verified traffic, capture health or protocol evidence.

Audited the LIVE branch, recent commits, this ledger through GA UI-42, `MainWindow.xaml`, `MainWindow.DashboardEvents.cs`, `MainWindow.Dashboard.cs`, `MainWindow.Core.cs`, `MainWindow.xaml.cs`, `MainWindow.Filters.cs`, `MainWindow.GridInteractions.cs`, `MainWindow.DashboardResponsive.cs` and `Theme.xaml`. The original `DashboardEventRowVm.FromDetection` projects `DetectionEvent.RuleId`, `DetectionEvent.Severity.ToString()` and `DetectionEvent.Protocol` into the read-only grid, with an em dash for absent rule/protocol text. The existing theme supplies the implicit `DataGridColumnHeader` style. Earlier UI-33/41/42 documented Evidence/Delivery, Event time and Source/Destination header provenance; UI-40 documented filter HelpText. Rule/Severity/Protocol headers still had no corresponding header-level context. No model, engine, service, detection, protocol, shared API or viewmodel change is necessary.

### One cohesive UI-owned improvement

Add distinct, source-accurate `DataGridTextColumn.HeaderStyle` tooltip and `AutomationProperties.HelpText` to the existing **Rule**, **Severity** and **Protocol** headers, each inheriting the original implicit `DataGridColumnHeader` style. **Rule** means the rule ID reported on the detection event, not proof of evaluation accuracy or current enablement. **Severity** is the event's reported classification, not verified impact or incident priority. **Protocol** is the event's reported protocol label, not independent packet inspection or protocol-decoder verification.

Keep original `Header` captions, `Binding` expressions, widths (76/85/80), order, frozen Event time, existing tooltips on other headers, row selection, keyboard order, virtualization, horizontal scrolling, filtering, 80 displayed/500 retained bounds, status/provenance labels and privacy boundary. No new focus stops, handlers, transformations, event values, external calls, data collection, telemetry, capture-health claims or security changes. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099, graceful below 1024, local PPS ScottPlot ten-sample average and bounded 120-point history, prioritized incidents, investigation, unavailable visual-only CLI and Cisco/WebView2 behavior.

### Start/end static divergence and publication guard

**Start:** `595377c8f93e4ea74b69f78df23d4fa38b4bc114` is one independent protocol commit ahead of GA UI-42 publication `d473bf336cc29ffee00eb21fabc73ce1624b9a52`. The pre-existing disjoint changes were `Carthago.Tests/ProtocolIntelligence/GvcpCommandInspectorTests.cs`, `Carthago/Services/ProtocolIntelligence/GvcpCommandInspector.cs`, `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md` and `docs/protocols/PROTOCOL_GA_P0241-P0250.md`; none is modified here. Prepared private source commit `01cb70212b174dac2b56d0f8b019dcf1b4cdb323` descends directly from the starting HEAD and modifies only `Carthago/Views/MainWindow.xaml`. Original XAML names, WPF partial consumers, UI theme, event projections, privacy, trust and approved reference remain unchanged.

**End/publication gate:** immediately before publication, re-read LIVE remote HEAD and compare concurrent detection/protocol/UI paths with the starting HEAD; inspect private source/docs commit ancestry and changed paths, exact source SHA, original bindings, style inheritance, naming, privacy and reference fidelity. Publish the **complete** two-commit source/docs candidate via **one** non-forced atomic GitHub `update_ref` with `expected_sha` lease on the existing branch. If HEAD moved on disjoint paths, reconstruct both private commits on fresh HEAD and use a fresh lease; STOP on conflict or missing guarantee. No force push, history rewrite, new branch, PR, partial publication or independent automation change.

**Residual risks:** Windows compilation, WPF DataGrid header style resolution, tooltip rendering, UI Automation HelpText exposure, keyboard-only header discovery, screen-reader announcements, high-contrast rendering, 125–200% DPI, horizontal scrolling and 1440/1100/1099/1024/1023/640px screenshots are **UNVERIFIED**. Header tooltips may be undiscoverable by keyboard alone. These static descriptions do not verify rule accuracy, enabled state, event severity, packet attribution, protocol decoding, capture health or detection quality. No new IPs, evidence payloads, personal data or external transmission.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Hover Rule header: tooltip distinguishes reported rule ID from rule accuracy, execution or enablement.
2. Hover Severity header: tooltip distinguishes event classification from verified impact or incident priority.
3. Hover Protocol header: tooltip distinguishes event protocol label from independently verified packet decoding.
4. UI Automation inspection exposes all three contextual HelpText values without replacing visible captions.
5. Rule/Severity/Protocol retain their original bindings, 76/85/80 widths, order, em-dash fallback where applicable and theme styling.
6. Frozen Event time, horizontal scrolling, read-only row selection, keyboard cell navigation, virtualization and 80/500 bounds remain unchanged.
7. At 1440/1100/1099/1024/1023/640px and 125–200% DPI/high contrast, inspect header readability, tooltip visibility and keyboard/screen-reader limitations.
8. Earlier Event time, Source/Destination, Evidence/Delivery header guidance, four filters, Clear filters, provenance and status captions remain unchanged.
9. Local PPS ScottPlot, KPIs, incident investigation, unavailable CLI, Cisco/WebView2, sidebar and monitoring/capture controls remain unaffected.
10. No demo telemetry, verified rule/protocol/impact claim, capture-health assertion, privacy/security change, shared API change or independent detection/protocol file modification occurs.

**Open quality GAs:** pinned-SHA Windows WPF build and actual keyboard/screen-reader/UI Automation/tooltip/high-contrast/DPI/responsive screenshot inspection **only after the owner explicitly says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-44:** inspect fresh LIVE HEAD, approved reference, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–43.

**References:** [WPF DataGridColumn.HeaderStyle](https://learn.microsoft.com/dotnet/api/system.windows.controls.datagridcolumn.headerstyle); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext).

## GA UI-44 — Investigation fact-card gutter consistency below 1024px

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `f2105a9002004a670781a4b39d071314fd677acb`; previous GA UI-43 source `01cb70212b174dac2b56d0f8b019dcf1b4cdb323`, publication `eb80cef02b46aec19c4000e9324325fd2022b309`. Independent GA P0251–P0260 MPTCP inspector source/test/documentation changes were present at the starting HEAD and remain untouched. **Exact GA UI-44 source SHA:** `169f73e26687652d45a0aa7b828daf13bfc3f665`. **Owned paths:** `Carthago/Views/MainWindow.xaml`, `Carthago/Views/MainWindow.DashboardResponsive.cs` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; tests executed: 0.** No build, dotnet test, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, production capture or running-WPF screenshot.

### Approved reference, source/consumer audit and reason for change

Resolved and **visually inspected** the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`: navy/graphite operational dashboard, cyan/teal accents, restrained severity, left navigation, KPIs, traffic chart, prioritized incidents, investigation, read-only local Live Events and visual-only unavailable CLI. Its IPs, Mbps lines, rule IDs, timestamps, confidence and metrics are **DEMO ONLY**, not actual capture, detection, telemetry or system-health evidence.

Inspected LIVE HEAD/recent commits, this ledger through GA UI-43, `MainWindow.xaml` six investigation fact cards, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs` threshold/consumer, `MainWindow.Dashboard.cs` original fact assignments, `MainWindow.Core.cs`, `MainWindow.xaml.cs`, `MainWindow.DashboardEvents.cs`, `Theme.xaml` `DetailGridCard`, and the existing WPF partial names. GA UI-38 intentionally changed six facts from three to two columns below 1024px, retaining original per-card margins and documenting the risk of **asymmetric two-column gutters**. At three columns, the six margins align by row; at two columns, the old right-edge margins no longer align with each row. GA UI-44 addresses only that identified visual consistency gap. It does not repeat the column-count change or any UI-01–43 behavior.

### One cohesive UI-owned improvement

Name only three existing `Border` fact cards: `DashboardDetailDestinationCard`, `DashboardDetailProtocolCard` and `DashboardDetailCategoryCard`. Within the existing `ApplyDashboardResponsiveLayout`, use the **existing** `narrowKpis` threshold to assign their margins for a consistent two-column row gutter below 1024px: source/destination (8px/0px right), protocol/category (8px/0px right), detected/related incident (existing 8px/0px right); first two rows retain 6px bottom margins and the last row retains zero. At/above 1024px the three named cards explicitly retain their **original** margins (destination `Thickness(0,0,8,6)`, protocol `Thickness(0,0,0,6)`, category `Thickness(0,0,8,0)`; WPF ordering is left/top/right/bottom). Original fact order, labels, text, bindings, tooltips, theme, border/padding, layout height and responsive thresholds remain.

No new focus stops, event handlers, navigation, values, telemetry, model, service, protocol, detection, capture, trust/privacy/security, shared API, tests, data collection or external calls. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024; local PPS ScottPlot 10-sample average/bounded 120-point history; prioritized incidents, investigation, read-only Live Events 80 displayed/500 retained, explicitly UNAVAILABLE visual-only CLI, Cisco/WebView2 and original privacy boundaries.

### Start/end static divergence, provenance and publication guard

**Start:** LIVE `f2105a9002004a670781a4b39d071314fd677acb` is one independent protocol commit after GA UI-43 publication `eb80cef02b46aec19c4000e9324325fd2022b309`. Its disjoint paths are `Carthago.Tests/ProtocolIntelligence/MptcpCapableSynInspectorTests.cs`, `Carthago/Services/ProtocolIntelligence/MptcpCapableSynInspector.cs`, `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md` and `docs/protocols/PROTOCOL_GA_P0251-P0260.md`. No independent file was edited. Private source commit `169f73e26687652d45a0aa7b828daf13bfc3f665` descends directly from `f2105a9002004a670781a4b39d071314fd677acb` and modifies only `Carthago/Views/MainWindow.xaml` (three new names) and `Carthago/Views/MainWindow.DashboardResponsive.cs` (three margin assignments). The source diff contains no other modifications. Original partial consumers, names, data values, navigation, privacy and reference fidelity remain unchanged.

**End/publication gate:** immediately before publication, re-read LIVE remote HEAD and compare concurrent detection/protocol/UI changes against `f2105a9002004a670781a4b39d071314fd677acb`. Verify private source/docs ancestry, exact owned-path diff, unique named elements, three-column original margins, two-column consistent gutters, approved reference and privacy boundaries. Publish the complete two-commit candidate through **one** non-forced atomic GitHub `update_ref` with `expected_sha` on the same existing branch. If the HEAD moves on disjoint paths, reconstruct both commits from the fresh HEAD and obtain a fresh lease; STOP on conflict or missing guarantee. No partial publication, branch/PR creation, force push, history rewrite or independent automation changes.

**Residual risks:** Windows compilation and generated WPF named-field resolution, actual responsive card reflow, text truncation, height/scroll constraints caused by the third row, visual alignment at window thresholds, keyboard/screen-reader order, high contrast, 125–200% DPI, rapid resize transitions and 1440/1100/1099/1024/1023/640px screenshots are **UNVERIFIED**. The extra row below 1024 remains; this GA addresses gutters only. No screenshot-derived values or evidence payloads are introduced.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. At 1440px Wide and 1100px Standard, six fact cards retain the original three-column order and 8px inter-card gutters.
2. At 1099px and 1024px Compact, three columns and all six original margins remain.
3. At 1023px and 640px, two columns show three rows, each with a consistent 8px inter-card gutter and no extra trailing right margin.
4. Below 1024px, first and second fact rows retain 6px bottom gutters and the third row has no bottom gutter.
5. Resize across 1024px repeatedly; the existing layout switches two/three columns and margins together without stale spacing.
6. Selected incident, selected anomaly and waiting states preserve all six fact values, labels, truncation and original self-text tooltips.
7. Investigation details, reasons, tags, related rule IDs, action buttons, evidence provenance and original scrolling remain unaffected.
8. Inspect 1440/1100/1099/1024/1023/640px at 125–200% DPI, high contrast, keyboard traversal and screen-reader reading order.
9. KPIs, local PPS ScottPlot, Live Events 80/500 read-only bounds, unavailable CLI, sidebar, Cisco/WebView2 and capture controls remain unaffected.
10. Verify no demo IP/metrics/timestamps/confidence, new telemetry, trust/security/privacy claims, shared API change or independent detection/protocol modification.

**Open quality GAs:** pinned-SHA Windows WPF compilation, actual responsive screenshot, accessibility, DPI/high-contrast and keyboard/screen-reader inspection **only when the owner explicitly says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-45:** inspect fresh LIVE HEAD, approved reference, ledger and WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–44.

**References:** [WPF UniformGrid](https://learn.microsoft.com/dotnet/api/system.windows.controls.primitives.uniformgrid); [WPF FrameworkElement.Margin](https://learn.microsoft.com/dotnet/api/system.windows.frameworkelement.margin).

## GA UI-45 — Keyboard-accessible guidance for the two triage-panel information glyphs

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `10a7826a9a5ed66f381960e853d02b81e4859b6f`; prior GA UI-44 source `169f73e26687652d45a0aa7b828daf13bfc3f665`, publication `5c87b8489f4821eda1c815f7880e46a3ddaa911a`. Independent GA P0261–P0270 PCP MAP inspector source/test/protocol documentation was already present at starting HEAD and is not modified. **Exact GA UI-45 source SHA:** `8007eabb294e18ab3131257d13ed3c88b49e5d1d`. **Owned paths:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; tests executed: 0.** No dotnet build/test, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, capture, running-WPF inspection or screenshot.

### Approved reference and original consumer audit

Resolved and **visually inspected** the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`. Preserve navy/graphite, cyan/teal, restrained severity, left navigation, operational KPIs, traffic visualization, prioritized incident queue, investigation, read-only Live Events and the explicitly **UNAVAILABLE** visual-only CLI. Image IPs, rule IDs, timestamps, confidence, Mbps and metrics are **DEMO ONLY**; none is observed traffic, capture-health or detection-quality evidence.

Inspected LIVE branch, recent commits, ledger through GA UI-44, `MainWindow.xaml`, `MainWindow.Dashboard.cs` original `DashboardAnomalyList` selection/`UpdateSocSignalDetails` consumers, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.DashboardEvents.cs` and `Theme.xaml` `SocInfoGlyph`/`KeyboardFocusVisual` resources. The existing **Recent High-Priority Incidents** and **Incident Investigation** heading glyphs were visual-only `TextBlock` elements without hover explanations, keyboard focus or accessibility names. The adjacent visible explanatory subtitles, existing list item accessibility labels, incident selection, local risk estimate and prior GA UI-36/37 keyboard-focus pattern provide source-consistent guidance without requiring a shared contract.

### One cohesive UI-owned improvement

Give the **two existing triage heading information glyphs** source-specific hover tooltips, keyboard focus and WPF UI Automation metadata. Add `Focusable=True`, `KeyboardNavigation.IsTabStop=True`, existing `KeyboardFocusVisual`, `ToolTipService.ShowsToolTipOnKeyboardFocus=True`, distinct `AutomationProperties.Name` and `AutomationProperties.HelpText`. Queue guidance explains unresolved correlated incidents before anomaly signals, and that local risk estimates are not detection confidence or verified impact. Investigation guidance explains selected incident/anomaly provenance and that risk is not detection confidence, verified impact or proof of capture health.

Original heading captions, glyph text, theme, margins, selection events, queue ranking, data bindings, local risk computation, detail updates, navigation and responsive behavior remain unchanged. No new buttons, commands, handlers, data producers, telemetry, models, services, detection/protocol code, capture, privacy/security/trust controls, shared APIs, external calls or synthetic data. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099, graceful below 1024, local PPS ScottPlot ten-sample average and bounded 120-point history, read-only Live Events 80 displayed/500 retained, unavailable CLI and Cisco/WebView2.

### Start/end static divergence and publication guard

**Start:** `10a7826a9a5ed66f381960e853d02b81e4859b6f` is one independent protocol documentation commit after GA UI-44 publication. Disjoint paths: `Carthago.Tests/ProtocolIntelligence/PcpMapInspectorTests.cs`, `Carthago/Services/ProtocolIntelligence/PcpMapInspector.cs`, `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md`, `docs/protocols/PROTOCOL_GA_P0261-P0270.md`. The private GA UI-45 source commit `8007eabb294e18ab3131257d13ed3c88b49e5d1d` descends from the starting HEAD, modifies only `Carthago/Views/MainWindow.xaml`, and adds metadata/focus/tooltip attributes to exactly two existing glyphs. Existing WPF partial consumers, theme keys, names, incident selection, demo-only provenance and privacy boundary remain unchanged.

**End/publication gate:** immediately before publishing, re-read LIVE remote HEAD and compare concurrent detection/protocol/UI changes with the starting HEAD; verify private source/docs ancestry, exact owned-path diff, original WPF names and consumers, privacy, reference fidelity and source SHA. Publish the complete source/docs candidate via **one** non-forced atomic GitHub `update_ref` with `expected_sha` lease on the same branch. If HEAD moved on disjoint paths, rebuild both commits on the fresh HEAD and use a fresh lease; STOP on conflict or missing guarantee. No partial publication, new branch, PR, force push, history rewrite or independent automation change.

**Residual risks:** Windows compilation, WPF tooltip-on-keyboard-focus behavior, actual keyboard tab order and extra focus stops, UI Automation name/HelpText exposure, screen-reader announcements, focus outline, high contrast, 125–200% DPI, 1440/1100/1099/1024/1023/640px rendering and screenshots remain **UNVERIFIED**. Two additional keyboard stops may increase traversal effort; actual accessibility improvement is not yet demonstrated. Static guidance does not verify incident severity, risk quality, protocol decoding, capture health or event delivery.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Hover the Recent High-Priority Incidents information glyph: local queue ordering and risk-estimate caveat appear.
2. Hover the Incident Investigation information glyph: selected incident/anomaly and capture-health caveat appear.
3. Keyboard Tab reaches both information glyphs in logical panel order with the existing cyan focus visual.
4. Keyboard focus can reveal each original glyph's tooltip without activating any command or changing selection.
5. UI Automation exposes distinct names and HelpText for both glyphs without claiming risk is confidence.
6. Existing `DashboardAnomalyList` selection and `UpdateSocSignalDetails` still update investigation identically.
7. Existing queue rows, risk badges, incident details, original glyph text, colors, panel geometry and theme remain unchanged.
8. Inspect 1440/1100/1099/1024/1023/640px at 125–200% DPI, high contrast, keyboard traversal and screen-reader reading order.
9. Local PPS ScottPlot, KPIs, read-only Live Events 80/500, unavailable CLI, sidebar, Cisco/WebView2 and monitoring/capture controls remain unaffected.
10. Verify no screenshot demo values, new telemetry, verified impact/capture claim, security/privacy/shared API change or independent detection/protocol file edit.

**Open quality GAs:** pinned-SHA Windows WPF compilation, actual tooltip/focus/screen-reader/UI Automation inspection, high-contrast/DPI and responsive screenshots **only when the owner explicitly says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-46:** inspect fresh LIVE HEAD, approved reference, ledger and WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–45.

**References:** [WPF FrameworkElement.Focusable](https://learn.microsoft.com/dotnet/api/system.windows.uielement.focusable); [WPF ToolTipService.ShowsToolTipOnKeyboardFocus](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice.showstooltiponkeyboardfocus); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext).

## GA UI-46 — Full current Source/Destination cell text on hover in read-only Live Events

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `b7b70589d5d027614d686be3f2484da46ac051ad`; prior GA UI-45 source `8007eabb294e18ab3131257d13ed3c88b49e5d1d`, publication `974e3f01cf786b84e8a08b57e20d9b2144b678b7`. One independent protocol documentation commit (P0271–P0280) was already present at the starting HEAD and affects only `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md` and `docs/protocols/PROTOCOL_GA_P0271-P0280.md`. **Exact GA UI-46 source SHA:** `e290ce617f672246099f6dc55a7a18f26940257f`. **Owned paths:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; tests executed: 0.** No build, dotnet test, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, capture, running-WPF inspection or screenshot.

### Approved reference, source consumers and reason for change

Resolved and **visually inspected** exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`. Preserve navy/graphite, cyan/teal, restrained severity, left navigation, operational KPIs, local PPS ScottPlot, prioritized incidents, investigation, read-only local Live Events and explicitly **UNAVAILABLE** visual-only CLI. Screenshot IPs, Mbps, rule IDs, timestamps, confidence and other metrics are **DEMO ONLY**, not observed telemetry or proof of monitoring/capture health.

Audited the LIVE branch and recent protocol-only divergence, this ledger through GA UI-45, `MainWindow.xaml` and its original WPF partial consumers `MainWindow.DashboardEvents.cs`, `MainWindow.Dashboard.cs`, `MainWindow.Responsive.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.xaml.cs` and `Theme.xaml`. The `DashboardLiveEventsGrid` is an existing read-only WPF `DataGrid` bound to `DashboardEventRowVm` projections of the retained local `DetectionEvent` collection. Its Source/Destination columns use `Source`/`Destination` strings derived from `SourceIp`/`DestinationIp` with an em-dash fallback; long values (notably IPv6) can be visually clipped at the existing 120px minimum width. GA UI-42 explains the **header** provenance but does not expose the complete **cell** text on hover. The existing `Theme.xaml` implicit TextBlock style supplies foreground and character-ellipsis trimming, while the framework `DataGridTextColumn.DefaultElementStyle` supplies 2px horizontal TextBlock margins.

### One cohesive UI-owned improvement

Add one scoped `DashboardLiveEndpointCellText` TextBlock style in `MainWindow.xaml` Window.Resources, based on the existing implicit TextBlock theme. Preserve the framework's original `Margin=2,0,2,0`; bind `ToolTip` to the generated TextBlock's **own current Text** using `RelativeSource Self`. Apply that same style only to the existing **Source** and **Destination** `DataGridTextColumn.ElementStyle` properties. The tooltip exposes exactly the already-present displayed endpoint string, including the em dash when absent; it introduces no new lookup, source field, packet attribution or unredacted evidence.

Original `DashboardEventRowVm`, row projection, source/destination bindings, header tooltips/HelpText, columns/widths/order, frozen Event time, DataGrid cell focus visual, row virtualization, selection, keyboard navigation, four filters, reset, read-only status and **80 displayed / 500 retained** bounds remain unchanged. Preserve local PPS ScottPlot ten-sample moving average/bounded 120-point history, Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024, unavailable CLI, Cisco/WebView2 and privacy/security boundaries. No new focus stops, handlers, commands, telemetry, model, engine, service, detection/protocol inspector, capture/trust/privacy/security control, shared API, external call or synthetic data.

### Start/end static divergence and publication guard

**Start:** `b7b70589d5d027614d686be3f2484da46ac051ad` is one protocol-documentation commit after GA UI-45 publication. Disjoint protocol paths listed above are not edited. The private source commit `e290ce617f672246099f6dc55a7a18f26940257f` descends directly from `b7b70589d5d027614d686be3f2484da46ac051ad` and modifies only `Carthago/Views/MainWindow.xaml`: one scoped style and two `ElementStyle` references. `Theme.xaml`, the DataGrid's existing `CellStyle`, partial consumers, names, data producers, labels, header semantics, route mappings, responsive thresholds and privacy boundaries remain untouched.

**End/publication gate:** immediately before publishing, re-read LIVE remote HEAD and compare all concurrent detection/protocol/UI changes with `b7b70589d5d027614d686be3f2484da46ac051ad`; verify source/docs private ancestry, exact two owned paths, style name and two references, original TextBlock theme/margin, data bindings, approved reference and privacy. Publish the **complete** source/docs candidate via **one** non-forced atomic GitHub `update_ref` with `expected_sha` lease on the same existing branch. If HEAD moved on disjoint paths, reconstruct both commits from fresh HEAD and use a fresh lease; STOP on conflict or missing guarantee. Never publish partially, force push, rewrite history, create a branch/PR or change independent automations.

**Residual risks:** Windows compilation, WPF resource resolution, tooltip self-binding, hover presentation for IPv6/long values, tooltip overflow, actual truncation behavior, virtualized/recycled cell updates, keyboard-only tooltip discovery, UI Automation and screen-reader reading order, high contrast, 125–200% DPI, horizontal scrolling and responsive screenshots are **UNVERIFIED**. A hover-only tooltip does not itself prove keyboard accessibility; the original grid's keyboard cell navigation and UIA text still require Windows inspection. Displayed endpoints remain reported event metadata, **not** verified host identity, packet attribution, reachability or successful connection.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Hover a visually clipped Source cell with an IPv6/long endpoint: tooltip shows the complete **current displayed** Source value.
2. Hover a visually clipped Destination cell: tooltip shows the complete **current displayed** Destination value.
3. An absent Source/Destination retains the original em-dash fallback in both visible text and tooltip.
4. Filter, clear filters and refresh while moving between rows: tooltip reflects the current row's value, never a recycled row's stale endpoint.
5. Source/Destination preserve original bindings, minimum 120px widths, theme foreground/ellipsis, 2px TextBlock margins and unchanged header provenance.
6. Read-only row selection, existing DataGrid cell focus outline, frozen Event time, horizontal scrolling, keyboard navigation and virtualization remain unchanged.
7. Inspect 1440/1100/1099/1024/1023/640px at 125–200% DPI and high contrast; check tooltip visibility, long-value wrapping/overflow and clipped-cell readability.
8. Screen-reader/UI Automation and keyboard-only inspection: establish what existing cell text is exposed and explicitly document that hover tooltip is not independently keyboard-discoverable.
9. Local PPS ScottPlot, incident queue/investigation, KPIs, Live Events 80/500 bounds, unavailable CLI, sidebar, Cisco/WebView2 and capture controls remain unaffected.
10. Verify no demo IP/metrics/timestamps/confidence, new evidence payloads, fabricated monitoring or packet attribution claim, privacy/security/shared API change or independent detection/protocol modification.

**Open quality GAs:** pinned-SHA Windows WPF compilation and actual hover, UI Automation, keyboard/screen-reader, high-contrast/DPI and responsive screenshot inspection **only when the owner explicitly says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-47:** inspect fresh LIVE HEAD, approved reference, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–46.

**References:** [WPF DataGridTextColumn.ElementStyle](https://learn.microsoft.com/dotnet/api/system.windows.controls.datagridboundcolumn.elementstyle); [WPF TextBlock.TextTrimming](https://learn.microsoft.com/dotnet/api/system.windows.controls.textblock.texttrimming); [WPF ToolTipService](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice).

## GA UI-47 — Evidence and Delivery cell-level provenance guidance in read-only Live Events

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `56e073f22df97aff1ff06c7f8a649e9220e4e5d1`; prior GA UI-46 source `e290ce617f672246099f6dc55a7a18f26940257f`, publication `84b569b1edfbd53fdfbacb862781276c491601b0`. Independent GA P0281–P0290 RGMP source/test/protocol documentation and subsequent protocol-documentation source-link correction were already present at the starting HEAD, and remain untouched. **Exact GA UI-47 source SHA:** `c146d0059980d6c884ccdbc8a74cb95b86197067`. **Owned paths:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; tests executed: 0.** No build, dotnet test, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, capture, running-WPF inspection or screenshot.

### Approved reference, original consumers and distinct need

Resolved and **visually inspected** the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`: navy/graphite, cyan/teal, restrained severity, left navigation, operational KPIs, traffic chart, prioritized incidents, investigation, read-only local Live Events and explicitly **UNAVAILABLE** visual-only CLI. Screenshot IPs, Mbps, rule IDs, timestamps, confidence and metrics are **DEMO ONLY**, not observed traffic or capture-health evidence.

Inspected LIVE remote HEAD, recent commits and this ledger through GA UI-46; `MainWindow.xaml` and its WPF partial consumers `MainWindow.DashboardEvents.cs`, `MainWindow.Dashboard.cs`, `MainWindow.Responsive.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.xaml.cs`, and `Theme.xaml`. `DashboardEventRowVm.FromDetection` maps `EvidenceSummary` to a reported structured-evidence item count or presence/absence, **never** to raw `Evidence` or `StructuredEvidence.Items` payloads. It maps `DeliveryStatus` to `DetectionEvent.DeliveryStatus.ToString()`, which is not incident resolution. The read-only `DashboardLiveEventsGrid` already has accurate **header** caveats, but individual Evidence/Delivery cells have no point-of-use explanation. This GA adds cell-local metadata only; it does not repeat GA UI-41–43 header guidance or GA UI-46 endpoint-value hover tooltips.

### One cohesive UI-owned change

Add two narrowly scoped TextBlock styles, `DashboardLiveEvidenceCellText` and `DashboardLiveDeliveryCellText`, in existing `MainWindow.xaml` Window.Resources. Both derive from the existing implicit TextBlock theme, retain the framework `DataGridTextColumn` display margin `2,0,2,0` and inherited character-ellipsis trimming, and supply source-accurate **hover ToolTip** and **AutomationProperties.HelpText** explaining each cell's meaning. Apply each style only to its corresponding existing Evidence or Delivery `DataGridTextColumn.ElementStyle`.

Evidence guidance says **reported presence/count, not raw evidence or verified chain of custody**. Delivery guidance says **detection-event transport status, not investigation progress, remediation or incident resolution**. The displayed value remains the original `EvidenceSummary`/`DeliveryStatus` binding; no raw payload, new lookup, source, network operation, data collection or verification claim is introduced. Original widths (128px Evidence, 105px Delivery), column order, headers and their existing tooltips/HelpText, frozen Event time, row virtualization, read-only selection, filters, 80 displayed/500 retained, focus visual, source/destination cell style, navigation, responsive thresholds and theme are preserved.

No new focus stops, commands, event handlers, data producers, telemetry, engine, model, service, protocol/detection inspector, capture/trust/privacy/security control, shared API, CI or external call. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099, graceful below 1024, local PPS ScottPlot ten-sample average/bounded 120-point history, prioritized incidents, investigation, unavailable CLI and Cisco/WebView2.

### Start/end static divergence, source provenance and publication guard

**Start:** `56e073f22df97aff1ff06c7f8a649e9220e4e5d1` is two independent protocol commits after GA UI-46 publication. The disjoint changed paths are `Carthago.Tests/ProtocolIntelligence/RgmpMessageInspectorTests.cs`, `Carthago/Services/ProtocolIntelligence/RgmpMessageInspector.cs`, `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md` and `docs/protocols/PROTOCOL_GA_P0281-P0290.md`. Private GA UI-47 source commit `c146d0059980d6c884ccdbc8a74cb95b86197067` descends directly from starting HEAD and changes only `Carthago/Views/MainWindow.xaml`: two new scoped styles and two column ElementStyle references. The original row projection, partial consumers, event values, theme, XAML names, focus/selection and privacy boundaries remain unchanged.

**End/publication gate:** immediately before publishing, re-read LIVE remote HEAD and compare any concurrent detection/protocol/UI changes against `56e073f22df97aff1ff06c7f8a649e9220e4e5d1`; verify source/docs ancestry, two authorized paths, exact source SHA, unique style declarations/references, original bindings/widths/header semantics, approved reference and privacy. Publish complete source/docs candidate via **one** non-forced atomic GitHub `update_ref` with `expected_sha` lease on the same existing branch. If HEAD moved on disjoint paths, rebuild both private commits from the fresh HEAD and use a fresh lease; STOP on conflict or missing guarantee. No partial publication, branch/PR creation, force push, history rewrite or independent automation changes.

**Residual risks:** Windows compilation, WPF style resolution, actual tooltip presentation, UI Automation HelpText exposure, screen-reader verbosity/duplication with header HelpText, virtualized/recycled row correctness, keyboard-only tooltip discovery, high contrast, 125–200% DPI, horizontal scrolling and 1440/1100/1099/1024/1023/640px screenshots remain **UNVERIFIED**. Hover tooltips do not independently establish keyboard-only accessibility; UI Automation HelpText is metadata whose actual screen-reader presentation is unverified. No claim of verified evidence chain, delivery success, capture health or incident resolution is made.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Hover an Evidence cell displaying a reported count: see the presence/count-only caveat; no raw evidence payload appears.
2. Hover an Evidence cell displaying `Reported` or `Not reported`: see the same source-accurate caveat, with the original visible value unchanged.
3. Hover a Delivery cell for each available transport state: see the transport-only caveat, never incident-resolution wording.
4. UI Automation exposes distinct Evidence/Delivery cell HelpText; screen-reader verbosity and actual announcement behavior are inspected rather than assumed.
5. Evidence/Delivery preserve original `EvidenceSummary`/`DeliveryStatus` bindings, column widths, ordering, header guidance and implicit theme/ellipsis.
6. Existing DataGrid keyboard navigation, cell focus outline, selection, frozen Event time and horizontal scrolling remain unchanged; no new tab stops.
7. Filter, clear filters and refresh while scrolling recycled rows: cell tooltip and HelpText remain correct for each column without stale event data.
8. Inspect 1440/1100/1099/1024/1023/640px, 125–200% DPI and high contrast for tooltip readability, clipping and overflow.
9. Confirm local PPS ScottPlot, KPIs, incident queue/investigation, Live Events 80/500 read-only bounds, unavailable CLI, sidebar, Cisco/WebView2 and capture controls are unaffected.
10. Confirm no screenshot demo values, evidence payloads, fabricated monitoring/delivery claim, security/privacy/shared API change or independent detection/protocol edit.

**Open quality GAs:** pinned-SHA Windows WPF compilation and actual tooltip/UI Automation/keyboard/screen-reader/high-contrast/DPI/responsive screenshot inspection **only when the owner explicitly says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-48:** inspect fresh LIVE HEAD, approved reference, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–47.

**References:** [WPF DataGridTextColumn.ElementStyle](https://learn.microsoft.com/dotnet/api/system.windows.controls.datagridboundcolumn.elementstyle); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF TextBlock.TextTrimming](https://learn.microsoft.com/dotnet/api/system.windows.controls.textblock.texttrimming).

## GA UI-48 — Keyboard-discoverable navigation scope for Live Events “All detections”

**2026-10-31 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE HEAD: 2b72e5cf3dfc1eed71039d512a8fcdb617785679 on existing feature/carthago-reliability-hardening. Prior GA UI-47 source c146d0059980d6c884ccdbc8a74cb95b86197067; publication e1bda7ffed1c38601dea991d94e321871a17e1f5. Independent GA P0291–P0300 protocol documentation was already present at the starting HEAD and is not edited. **Exact GA UI-48 source SHA: 478f0a44cf03649622b5b99917bb005707ff130e.** **Owned paths:** Carthago/Views/MainWindow.xaml and docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md only. **Tests authored: 0; tests executed: 0.** No build, dotnet test, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, capture, running-WPF inspection or screenshot.

### Approved reference, original consumers and distinct need

Resolved and **visually inspected** the exact approved ChatGPT Library image libfile_b0a34361560c8191b641e432b3e6b15c: navy/graphite, cyan/teal, restrained severity, left navigation, operational KPIs, local traffic visualization, prioritized incidents, investigation, read-only Live Events and explicitly UNAVAILABLE visual-only CLI. Its IPs, Mbps, rule IDs, timestamps, confidence and other metrics are **DEMO ONLY**, not capture, monitoring or detection-quality evidence.

Inspected LIVE remote branch, recent commits, ledger through UI-47, MainWindow.xaml, MainWindow.DashboardEvents.cs, MainWindow.Navigation.cs, MainWindow.Dashboard.cs, MainWindow.Responsive.cs, MainWindow.DashboardResponsive.cs, MainWindow.xaml.cs, MainWindow.Core.cs, Sidebar.xaml.cs and Carthago/Views/Theme.xaml. Existing DashboardLiveEventsOpenDetections_Click delegates directly to Nav_Alerts_Click; the existing route calls ShowView(AlertsView), selects sidebar Alerts and shows sidebar detection filters. The dashboard Live Events filter controls are separate and are not changed by that handler. The existing All detections button inherits SecondaryButton and its keyboard focus visual, but lacked specific accessible naming and scope guidance. The adjacent Open Live Traffic button already has its own name/HelpText. This improvement does not repeat UI-01–47.

### One cohesive UI-owned change

Add exactly four WPF attributes to the existing Live Events **All detections →** Button: a navigation-only hover ToolTip naming the existing Raw Detections view, ToolTipService.ShowsToolTipOnKeyboardFocus=True, AutomationProperties.Name=Open Raw Detections, and source-accurate AutomationProperties.HelpText describing the existing route/sidebar filters while distinguishing navigation from dashboard filtering, evidence export, capture activation and delivery verification.

Preserve the original caption/arrow, DockPanel placement, MinWidth=130, Height=30, SecondaryButton style, Click=DashboardLiveEventsOpenDetections_Click, original route, tab order and focus outline. No new focus stop, handler, command, filter behavior, data binding, data producer, telemetry, evidence payload, engine, model, service, protocol/detection rule, capture/trust/privacy/security control, shared API or external call. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024; local PPS ScottPlot 10-sample average and bounded 120-point history; prioritized incidents/investigation; read-only local Live Events 80 displayed/500 retained; unavailable visual-only CLI; Cisco/WebView2 and privacy/capture boundaries. No demo values added.

### Start/end static divergence, provenance and publication guard

**Start:** LIVE 2b72e5cf3dfc1eed71039d512a8fcdb617785679 is one independent protocol documentation commit after GA UI-47 publication e1bda7ffed1c38601dea991d94e321871a17e1f5. Disjoint paths: docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md and docs/protocols/PROTOCOL_GA_P0291-P0300.md. Private source commit 478f0a44cf03649622b5b99917bb005707ff130e descends directly from 2b72e5cf3dfc1eed71039d512a8fcdb617785679 and changes only Carthago/Views/MainWindow.xaml: four attributes on one existing navigation button. Original WPF partial consumers, sidebar route, filter semantics, names, theme, privacy and capture boundaries remain unchanged.

**End/publication gate:** immediately before publishing, re-read LIVE remote HEAD and compare concurrent detection/protocol/UI paths with 2b72e5cf3dfc1eed71039d512a8fcdb617785679; verify two private commits, ancestry, exact owned-path diff, original handler/theme, source SHA, approved reference and privacy. Publish the complete candidate only through ONE non-forced atomic GitHub update_ref with expected_sha lease on the same existing branch. If HEAD moves on disjoint paths, reconstruct both commits from the fresh HEAD and obtain a fresh lease; STOP on conflict or missing guarantee. No partial publication, branches, PRs, force push, history rewrite or independent automation changes.

**Residual risks:** Windows compilation, WPF attached-property resolution, actual keyboard-focus tooltip display, UI Automation Name/HelpText exposure, screen-reader announcement/verbosity, focus outline, high contrast, 125–200% DPI, 1440/1100/1099/1024/1023/640px screenshots and responsive clipping are **UNVERIFIED**. The metadata is not proof of accessibility compliance or monitoring success. Route behavior is inspected statically, not executed.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Hover All detections: tooltip identifies the existing Raw Detections view and navigation-only scope.
2. Tab to the existing button: the original focus visual remains and tooltip is available on keyboard focus without another tab stop.
3. UI Automation exposes Open Raw Detections and distinct HelpText; inspect actual screen-reader announcements, not assume them.
4. Activate with mouse, Enter and Space: existing DashboardLiveEventsOpenDetections_Click delegates to Nav_Alerts_Click and shows AlertsView.
5. Existing sidebar Alerts selection and detection-filter presentation remain unchanged.
6. Dashboard Severity/Protocol/Rule/Search filters and Clear filters behavior are unchanged when navigating away and back.
7. Original button caption, arrow, width/height, style, placement, keyboard order and focus outline remain.
8. Inspect 1440/1100/1099/1024/1023/640px, 125–200% DPI and high contrast for tooltip readability, focus and clipping.
9. KPIs, local PPS ScottPlot, incidents/investigation, Live Events 80/500 read-only bounds, unavailable CLI, Cisco/WebView2 and capture controls remain unaffected.
10. Verify no screenshot demo telemetry, evidence export, capture or delivery-health assertion, privacy/security/shared API change or independent detection/protocol edit.

**Open quality GAs:** pinned-SHA Windows WPF compilation and actual tooltip, keyboard, UI Automation, screen-reader, high-contrast/DPI and responsive screenshot inspection **only when owner explicitly says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-49:** inspect fresh LIVE HEAD, approved reference, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–48.

**References:** [WPF ToolTipService.ShowsToolTipOnKeyboardFocus](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice.showstooltiponkeyboardfocus); [WPF AutomationProperties.Name](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.name); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext).


## GA UI-49 — Keyboard-discoverable scope for both Signal Investigation detail triggers

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `4fac77433bc2f1fd47887cd9c5558f55aa26e7e1`; prior published GA UI-48 docs HEAD `30dae3d9b0a142e774bccd06cbb911914785c386`. Exact UI source commit: `7e8a4d79b0f23ba79e94fb07ce786e677ee43a65`. Approved concept reference: ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`, visually inspected in this GA. Source-owned path: `Carthago/Views/MainWindow.xaml`; ledger-owned path: `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. No other paths may change. No tests, builds, replays, runners, CI, screenshots of running software or production capture were executed.

### Reference, live-source and consumer audit

The approved image remains a **DEMO ONLY** composition: navy/graphite, cyan/teal, restrained severity, left navigation, operational KPIs, traffic plot, prioritized incidents, investigation, local Live Events and an illustrated CLI. Its IPs, Mbps, rule IDs, timestamps, confidence and capture-health indicators are not real data. Inspected LIVE remote HEAD and one independent P0301–P0310 IPFIX protocol source/test/docs commit since GA UI-48; audited this ledger through GA UI-48, `MainWindow.xaml`, `MainWindow.Dashboard.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.Navigation.cs`, `MainWindow.Responsive.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.xaml.cs`, `MainWindow.Core.cs`, `DashboardSignalDetailDialog.xaml`, `DashboardSignalDetailDialog.xaml.cs`, and `Theme.xaml`. No prior GA UI-01–48 added accessible scope metadata to the two existing **Full detail** / **Full Detail** triggers.

The two original dashboard buttons both call `DashboardOpenSignalDetail_Click`. That handler builds `CreateDashboardSignalDetailModel()`, opens `DashboardSignalDetailDialog` modally via `ShowDialog()`, and responds to the dialog's optional `RequestedAction` by navigating to the existing incident or anomaly view. The dialog's existing `CopySummary_Click` copies a text summary to the clipboard. The model can reflect the selected incident/anomaly or an existing fallback incident; therefore the tooltip says **current local incident or anomaly context**, not a guaranteed selected or verified incident. The upper `DashboardOpenSignalDetailButton` remains `Visibility=Collapsed`; the lower `Full Detail` button remains visible and uses the same handler. Existing `SecondaryButton` inherits the theme keyboard-focus outline. The nearby `View Related Incident` and `Review finding` buttons and their original enablement/handlers are not modified.

### One cohesive UI-owned improvement

Add identical, source-accurate hover and keyboard-focus tooltips, `AutomationProperties.Name` and `AutomationProperties.HelpText` to **both existing Full Detail triggers**. The guidance describes the existing modal Signal Investigation detail, optional clipboard summary and incident/anomaly navigation, and distinguishes opening a dialog from capture activation, raw evidence export, remediation or verification. Preserve the original captions, names, widths, heights, styles, focus order, collapsed state, click handlers, modal dialog, clipboard implementation, conditional navigation and data producers. No new controls, focus stops, commands, bindings, telemetry, services, models, capture/trust/privacy, detection/protocol changes, shared API or security controls. Do not change the dialog itself.

Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099, graceful below 1024, local PPS ScottPlot 10-sample average and bounded 120-point history, prioritized incidents/investigation, read-only Live Events 80 displayed/500 retained, explicitly UNAVAILABLE visual-only CLI and Cisco/WebView2/ScottPlot behavior. No screenshot DEMO values introduced.

### Start/end static divergence and publication gate

**Start:** LIVE `4fac77433bc2f1fd47887cd9c5558f55aa26e7e1` is one protocol-only commit ahead of UI-48 publication `30dae3d9b0a142e774bccd06cbb911914785c386`. Disjoint independent paths: `Carthago.Tests/ProtocolIntelligence/IpfixMessageInspectorTests.cs`, `Carthago/Services/ProtocolIntelligence/IpfixMessageInspector.cs`, `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md`, `docs/protocols/PROTOCOL_GA_P0301-P0310.md`. The private UI source commit `7e8a4d79b0f23ba79e94fb07ce786e677ee43a65` descends from that LIVE HEAD and changes only `Carthago/Views/MainWindow.xaml`, limited to the two existing buttons. Their original handler/visibility/style and consumers remain unchanged.

**End/publication gate:** re-read LIVE remote HEAD immediately before publication, compare all intervening paths and inspect source/ledger provenance, exact UI-only diff, unchanged consumers, image fidelity, privacy and capture boundaries. Prepare a separate private ledger commit descending from the source commit. Publish both commits together through **one non-forced atomic `update_ref` with `expected_sha` lease** on the same branch. If concurrent changes touch owned paths or the lease guarantee is unavailable, STOP; if disjoint, rebuild both private commits on fresh LIVE HEAD and recheck before publication. Never partially publish or change independent automations.

**Residual risks:** Windows WPF compilation, keyboard-focus tooltip display, UI Automation metadata resolution, screen-reader announcements, the collapsed header trigger, focus visual, clipboard and optional dialog navigation, high contrast, 125–200% DPI and responsive screenshots at 1440/1100/1099/1024/1023/640px are **UNVERIFIED**. Tooltip text may be verbose for assistive technology. Static handler inspection does not prove runtime behavior or accessibility compliance.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Hover the visible lower **Full Detail** button: guidance names the existing Signal Investigation dialog, not a new investigation service.
2. Keyboard Tab to the visible lower button: original focus outline remains and tooltip appears on keyboard focus; no extra focus stop.
3. UI Automation exposes the accessible name **Open signal investigation detail** and source-accurate HelpText; verify actual screen-reader presentation on Windows.
4. Activate the lower button with mouse, Enter and Space: existing handler opens the existing modal dialog without changing incident selection.
5. Inspect the upper **Full detail** trigger: metadata matches the lower button and it remains collapsed unless original behavior changes it.
6. In the dialog, verify existing **Copy summary** copies only the original summary and that no clipboard action occurs merely by opening it.
7. Verify existing optional **Open incident** / **Open anomalies** dialog actions preserve their routes and are not implied when unavailable.
8. Check 1440/1100/1099/1024/1023/640px, 125–200% DPI and high contrast for tooltip placement, clipping and keyboard focus.
9. Verify KPIs, local PPS plot, incidents, Live Events 80/500, unavailable CLI, Cisco/WebView2 and capture controls are unaffected.
10. Confirm no fabricated telemetry, verified evidence/health claim, raw evidence export, capture, remediation, shared API, privacy/security or independent detection/protocol changes.

**Open quality GAs:** pinned-SHA Windows WPF compilation and actual UI/keyboard/UI Automation/screen-reader/high-contrast/DPI/responsive inspection **only after owner says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-50:** inspect fresh LIVE HEAD, approved image, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–49.

## GA UI-50 — Full recorded metadata-cell text in read-only Live Events

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `92a61e5e5b753bca00501b74cf42cf19b1a01361`; prior published GA UI-49 source `7e8a4d79b0f23ba79e94fb07ce786e677ee43a65` and publication `e99396fa6e86e4cdb5b960ea3e419fc086b5d2e9`. Exact GA UI-50 source commit: `44461c7405bf42c0b3f469c43bfbe0bf2ef799b4`. **Authorized paths:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; tests executed: 0.** No dotnet build/test, xUnit, replays, holdouts, CI, GitHub Actions, runners, benchmarking, production capture, runtime WPF inspection or screenshot execution.

### Approved reference and original WPF consumers

Resolved and **visually inspected** the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`. The navy/graphite surfaces, cyan/teal accents, restrained severity, left navigation, operational KPIs, traffic chart, prioritized incidents, investigation and read-only Live Events remain the design reference; the illustrated CLI is **UNAVAILABLE, visual-only** in the application. The image's IPs, Mbps, metrics, rule IDs, timestamps, confidence and monitoring indicators are **DEMO ONLY**, not real telemetry or capture-health evidence.

Audited LIVE remote branch HEAD and recent commits, this ledger through GA UI-49, `MainWindow.xaml`, `MainWindow.DashboardEvents.cs`, `MainWindow.Dashboard.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.Navigation.cs`, `MainWindow.Core.cs`, `MainWindow.xaml.cs`, `Sidebar.xaml.cs` and `Theme.xaml`. The original `DashboardEventRowVm.FromDetection` supplies formatted `EventTime`, `RuleId`, `Severity` and `Protocol` as strings; `RefreshDashboardLiveEvents` supplies a bounded, filtered read-only projection. The existing theme gives `TextBlock` character-ellipsis trimming and the DataGrid its original typography, padding, focus and virtualization. GA UI-41/43 clarified these headers; GA UI-46 added endpoint-cell full-text hover; GA UI-47 clarified Evidence/Delivery cells. No previous UI-01–49 added full-text hover to the four remaining recorded metadata cells.

### One cohesive UI-owned change

Add one `DashboardLiveMetadataCellText` `TextBlock` style scoped to the existing Live Events grid and apply it **only** to the existing **Event time, Rule, Severity and Protocol** `DataGridTextColumn.ElementStyle` properties. The style inherits the existing TextBlock theme, retains the original 2px horizontal margins, and binds the hover tooltip to `Text` on the current cell TextBlock. This exposes the complete **currently displayed string** when a narrow column visually truncates it; it does **not** query event payloads, infer timezone, verify rule evaluation, prove severity impact or perform protocol inspection. The tooltip is available on hover even when text is not truncated; it is not conditional on clipping. No new focus stop, handler, data binding to underlying event sources, value, status, event ordering, filter behavior, column width/order, virtualization or data producer. Existing Source/Destination, Evidence/Delivery cell styles and all header tooltips remain unchanged.

Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024, left navigation, local PPS ScottPlot 10-sample average / bounded 120-point history, prioritized incidents/investigation, Live Events 80 displayed / 500 retained, unavailable visual-only CLI, Cisco/WebView2/ScottPlot behavior and capture/trust/privacy boundaries. No engine, model, service, detection/protocol, telemetry, evidence payload, shared API, security control or screenshot DEMO value changed.

### Start/end static divergence, provenance and publication gate

**Start:** LIVE `92a61e5e5b753bca00501b74cf42cf19b1a01361` is one independent GA P0311–P0320 GDB RSP protocol commit ahead of UI-49 publication `e99396fa6e86e4cdb5b960ea3e419fc086b5d2e9`. The intervening independent paths are `Carthago.Tests/ProtocolIntelligence/GdbRspCommandInspectorTests.cs`, `Carthago/Services/ProtocolIntelligence/GdbRspCommandInspector.cs`, `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md` and `docs/protocols/PROTOCOL_GA_P0311-P0320.md`. They are disjoint and untouched. Private source commit `44461c7405bf42c0b3f469c43bfbe0bf2ef799b4` descends directly from LIVE `92a61e5e5b753bca00501b74cf42cf19b1a01361` and changes only `Carthago/Views/MainWindow.xaml` (one style declaration and four column style references). The original WPF partials/consumers, names, headers, routes, filtering, privacy and capture boundaries are unchanged.

**End/publication guard:** re-read LIVE remote HEAD immediately before publication; compare intervening detection/protocol/UI changes and confirm exact owned paths, ancestry, source blob, ledger, approved reference, unchanged consumers/APIs and no demo telemetry. Prepare the separate private ledger commit descending from the source commit. Publish both together through **ONE non-forced atomic GitHub `update_ref` with `expected_sha` lease** on the same existing branch. If concurrent commits touch owned paths or lease protection is unavailable, STOP; if disjoint, reconstruct both commits on fresh LIVE HEAD and recheck. No partial publication, new branches, PRs, force push, history rewrite or independent automation changes.

**Residual risks:** Windows WPF compilation, `DataGridTextColumn.ElementStyle` resolution, actual hover tooltip rendering and virtualized-cell reuse, long rule IDs/protocol labels, timestamp display and timezone interpretation, keyboard-only discovery, UI Automation/screen-reader behavior, high contrast, 125–200% DPI, 1440/1100/1099/1024/1023/640px layouts and responsive clipping are **UNVERIFIED**. Hover tooltips do not independently establish keyboard accessibility or screen-reader announcement. Static inspection is not proof of compilation, accessibility compliance, detection quality or capture health.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Hover a truncated Event time cell: tooltip displays the complete current formatted timestamp without timezone inference or conversion.
2. Hover a truncated Rule ID: tooltip displays the full current identifier without implying rule accuracy or enablement.
3. Hover a long Protocol label: tooltip displays the full current label without implying verified protocol decoding.
4. Hover Severity and non-truncated metadata: tooltip reflects the current displayed text, with no invented impact or conditional clipping claim.
5. Filter by Severity, Protocol, Rule and Search, then reset: tooltip values track the displayed rows; filtering semantics remain unchanged.
6. Scroll horizontally and vertically with recycled/virtualized rows: tooltip never shows a stale row value; frozen Event time behavior remains.
7. Verify all four column widths, original order, 2px margins, character ellipsis, header explanations and theme colors remain unchanged.
8. Inspect 1440/1100/1099/1024/1023/640px, high contrast and 125–200% DPI for tooltip clipping/readability; assess keyboard and screen-reader limitations.
9. Verify original read-only Live Events 80/500 limits, event provenance, KPI/ScottPlot, incidents, CLI unavailability and Cisco/WebView2 behavior remain unchanged.
10. Confirm no new telemetry, capture/health assertions, evidence exposure, protocol/detection rule change, shared API/security/privacy change or edits to independent streams.

**Open quality GAs:** pinned-SHA Windows WPF compilation and actual tooltip, virtualization, keyboard, UI Automation, screen-reader, high-contrast, DPI and responsive screenshot inspection **only after owner explicitly says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-51:** inspect fresh LIVE HEAD, approved reference, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–50.

**References:** [WPF DataGridTextColumn.ElementStyle](https://learn.microsoft.com/dotnet/api/system.windows.controls.datagridboundcolumn.elementstyle); [WPF TextBlock.TextTrimming](https://learn.microsoft.com/dotnet/api/system.windows.controls.textblock.texttrimming); [WPF ToolTip](https://learn.microsoft.com/dotnet/api/system.windows.frameworkelement.tooltip).

## GA UI-51 — Source-accurate local time provenance for prioritized queue rows

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `ff2d29347cbbcf7e9667ae2b7258b3423dcc02c7`. Prior GA UI-50 source `44461c7405bf42c0b3f469c43bfbe0bf2ef799b4`; publication `5e0284a8006ab0ceeb363ee86d8599d986181bd0`. **Exact GA UI-51 source SHA:** `36ff441d92769cdb637aae954a4902806a662daa`. **Owned paths only:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; tests executed: 0.** No dotnet build/test, xUnit, replays, holdouts, CI, GitHub Actions, runners, benchmarks, live capture or runtime screenshots.

### Approved visual reference, consumer audit and distinct scope

Resolved and **visually inspected** exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928). Preserve navy/graphite, cyan/teal, restrained severity, left navigation, operational KPIs, local PPS ScottPlot 10-sample average with 120-point bound, prioritized incidents, selected investigation, read-only Live Events 80 shown / 500 retained, and explicitly **UNAVAILABLE visual-only CLI**. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful layout below 1024. All screenshot IPs, traffic/Mbps, sensor counts, timestamps, rule IDs, severity/confidence percentages, monitoring indicators and CLI text are **DEMO ONLY**, not application telemetry or capture-health claims.

Static inspection included LIVE remote HEAD/recent commit, this ledger through UI-50, `MainWindow.xaml`, `MainWindow.Dashboard.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Navigation.cs`, `MainWindow.Core.cs`, `MainWindow.xaml.cs`, and `Theme.xaml`. The existing `DashboardAnomalyList` is populated by `BuildSocAnomalyItems`; `SocAnomalyVm.TimeText` is formatted as local `HH:mm:ss` using `incident.UpdatedUtc.ToLocalTime()` for correlated incidents and `anomaly.CreatedUtc.ToLocalTime()` for anomaly signals. `SocAnomalyVm.AccessibilityLabel` already announces local time. The original `ListBoxItem` automation name, item template, keyboard focus border and selection handler remain in place. No UI-01–50 candidate had added this queue-time origin explanation.

### One cohesive UI-owned change

In the existing prioritized incident/anomaly `ListBox.ItemContainerStyle`, add `AutomationProperties.HelpText` explaining the existing local-clock time: incident last update versus anomaly creation, `HH:mm:ss` with date omitted, not a packet-capture or event-delivery timestamp. On the existing `TimeText` TextBlock, add a matching hover `ToolTip`. These are static explanatory UI attributes only. **No new focus stop, timestamp computation, conversion, timezone inference, date, binding, command, selection behavior, queue ordering, score, risk label, status or data producer.** No change to the existing `AccessibilityLabel` or `DashboardAnomalyList_SelectionChanged` consumer. Tooltip may appear even when the time text is not clipped. No tooltip claims that an incident update equals first detection or packet attribution.

Source commit `36ff441d92769cdb637aae954a4902806a662daa` descends directly from starting LIVE `ff2d29347cbbcf7e9667ae2b7258b3423dcc02c7` and changes only `Carthago/Views/MainWindow.xaml`. Existing Cisco/WebView2/ScottPlot, detection/protocol, telemetry/capture, trust/privacy/security, shared APIs, tests and independent automations remain outside scope.

### Start/end static divergence and publication protection

**Start:** LIVE `ff2d29347cbbcf7e9667ae2b7258b3423dcc02c7` is one independent P0321–P0330 HICP protocol candidate ahead of UI-50 publication `5e0284a8006ab0ceeb363ee86d8599d986181bd0`. Its intervening paths are `Carthago.Tests/ProtocolIntelligence/HicpConfigurationAttemptInspectorTests.cs`, `Carthago/Services/ProtocolIntelligence/HicpConfigurationAttemptInspector.cs`, `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md` and `docs/protocols/PROTOCOL_GA_P0321-P0330.md`; all disjoint and untouched. Private source changes one UI XAML path only. No new names, WPF partial hooks, engine calls, services, protocol rules, data values or altered privacy/capture claims.

**End/publication gate:** immediately re-read LIVE remote HEAD, compare all intervening paths and provenance, review the exact UI source diff and unchanged partials/consumers, source/docs Git blobs, approved reference and absence of fabricated telemetry. Publish **only** the complete source+ledger commit chain with ONE non-forced atomic GitHub `update_ref` using `expected_sha` lease on the same branch. If concurrent work touches owned paths, lease protection fails or conflicts cannot be safely reconciled, STOP. If only disjoint independent changes arrive, rebuild both private commits on the new HEAD and recheck before a fresh lease. Never publish partially, create branches/PRs, rewrite history or change independent automations.

**Residual risks:** WPF compilation, actual ListBoxItem HelpText exposure, assistive-technology announcements, tooltip rendering and hover behavior, virtualized/recycled queue rows, clock presentation, high contrast, 125–200% DPI, 1440/1100/1099/1024/1023/640px layouts, selection/focus and screen-reader verbosity are **UNVERIFIED**. Static provenance review does not prove Windows UI Automation compatibility or accessibility compliance. Local time is a presentation conversion; no timezone metadata is added to the displayed HH:mm:ss.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Hover an incident queue time: tooltip correctly identifies local HH:mm:ss as incident **last update**, not initial detection.
2. Hover an anomaly signal time: tooltip correctly identifies local HH:mm:ss as **signal creation**.
3. Confirm both kinds omit the calendar date and neither tooltip invents one or asserts verified timezone.
4. Confirm neither tooltip nor row HelpText implies packet-capture timestamp, delivery success or verified incident impact.
5. With keyboard focus on a row, verify original item accessible name and the added HelpText are exposed appropriately in Windows UI Automation and screen readers.
6. Navigate the queue with arrow keys: existing focus border, selection, ordering and Incident Investigation update remain unchanged, with no extra Tab stop.
7. Refresh and recycle queue rows: the existing bound local time remains current and the static tooltip never implies another row's values.
8. Inspect 1440/1100/1099/1024/1023/640px, high contrast and 125–200% DPI for readable time/tooltip without clipping or layout regression.
9. Verify unchanged operational KPIs, local PPS chart, Live Events 80/500 read-only filters, visual-only unavailable CLI, Cisco/WebView2 and capture/trust/privacy boundaries.
10. Confirm no fabricated screenshot data, engine/model/service/protocol/detection/shared API/security/test/automation changes or unrelated repository path edits.

**Open quality GAs:** pinned-SHA Windows compilation and actual UI, keyboard, tooltip, screen-reader, high-contrast, DPI and responsive inspection **only when the owner says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-52:** inspect fresh LIVE HEAD, approved image, ledger and WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–51.

**References:** [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF FrameworkElement.ToolTip](https://learn.microsoft.com/dotnet/api/system.windows.frameworkelement.tooltip); [DateTime.ToLocalTime](https://learn.microsoft.com/dotnet/api/system.datetime.tolocaltime).

## GA UI-52 — Truthful conditional navigation for the related incident action

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `abc69cf065c4f19855fee89bf659706c005c3b8d`. Prior GA UI-51 source `36ff441d92769cdb637aae954a4902806a662daa`, publication `8f2e575a814d3eebe1325fe6ded399d40a729a38`. **Exact GA UI-52 source SHA:** `acddf69055626cf9e691fe4f70ec64bdff52a9af`. **UI source blob:** `5d6e36d010f3c233972c6c4429c85ac7d4081c15`. **Owned paths only:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; tests executed: 0.** No dotnet build/test, xUnit, replays, holdouts, CI, GitHub Actions, runners, benchmarks, live capture or running-software screenshots.

### Approved reference, original consumers and non-duplicated scope

Resolved and **visually inspected** exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928). Preserve its navy/graphite surfaces, cyan/teal accents, restrained severity, left navigation, operational KPIs, prioritized incidents, selected investigation, read-only local Live Events (80 displayed / 500 retained), local PPS ScottPlot (10-sample average, bounded 120-point history), and **UNAVAILABLE visual-only CLI**. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024. All reference screenshot IPs, Mbps/traffic lines, monitoring badges, sensor counts, rule IDs, confidence, timestamps and CLI output are **DEMO ONLY**; no application values or capture-health claims are inferred from the image.

Audited live remote HEAD and recent commits, the ledger through GA UI-51, `MainWindow.xaml`, `MainWindow.xaml.cs`, `MainWindow.Core.cs`, `MainWindow.Navigation.cs`, `MainWindow.Dashboard.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.DashboardResponsive.cs`, and `Theme.xaml`. The existing `DashboardViewRelatedIncidentButton` in Incident Investigation / Recommended actions has `Click="DashboardViewRelatedIncident_Click"`. That handler returns if `_selectedDashboardIncidentId` is absent; otherwise it calls `OpenSelectedIncidentWorkspace()`, which delegates to the existing `OpenIncidentWorkspace`. `UpdateSocSignalDetails` already sets `IsEnabled = detail.CanOpenIncident`. Unlike the existing **Review finding** (GA UI-27) and **Full Detail** (GA UI-49) controls, this particular button previously had no source-specific tooltip or UI Automation explanation. This is distinct from UI-01–51.

### One cohesive UI-owned improvement

Add only static WPF metadata to the existing `View Related Incident` button: a truthful hover tooltip, keyboard-focus tooltip support, disabled-state tooltip support, `AutomationProperties.Name` and `AutomationProperties.HelpText`. Explain that it opens an existing correlated-incident workspace only when a related incident is available; an unavailable action is not a promise of incident linkage. Opening it does **not** start packet capture, export raw evidence, remediate, or verify impact/detection accuracy. The existing caption, `MinWidth=154`, `Height=30`, `SecondaryButton` style, margin, handler, conditional enablement, tab order and all incident/anomaly data remain unchanged. No new controls, focus stops, route, commands, data producers, services, protocols, telemetry, security controls, API contracts, capture behavior or evidence payloads.

The private source commit `acddf69055626cf9e691fe4f70ec64bdff52a9af` descends directly from the starting LIVE HEAD and changes only `Carthago/Views/MainWindow.xaml` (12 added lines, one replaced line). All independent protocol/detection work remains outside UI ownership.

### Start/end static divergence and publication guard

**Start:** the only commit since GA UI-51 publication was `abc69cf065c4f19855fee89bf659706c005c3b8d`, independent P0331–P0340 MSDP protocol work in `Carthago/Services/ProtocolIntelligence/MsdpEnvelopeInspector.cs`, `Carthago.Tests/ProtocolIntelligence/MsdpEnvelopeInspectorTests.cs` and `docs/protocols/**`. Its paths are disjoint from the UI-owned source and ledger. No changes to WPF partial hooks, consumers, naming, route mappings, source values, privacy/capture/trust boundaries, Cisco/WebView2/ScottPlot or approved-reference interpretation.

**End/publication gate:** re-read LIVE remote HEAD **immediately before publication**; compare all intervening commits and changed paths, and recheck UI XAML/ledger blobs, existing handler, conditional `IsEnabled`, unchanged WPF partials/consumers, naming and privacy. Publish the **complete** private source+documentation commit chain only with **ONE** non-forced atomic GitHub `update_ref` carrying the exact `expected_sha` lease on the same existing branch. If the branch moves, reconcile only disjoint independent changes onto fresh HEAD, rebuild the complete private chain and recheck a fresh lease. Stop on overlap, failed lease or missing guarantee; never publish partially, force push, create branches/PRs, rewrite history or modify independent automations.

**Residual risks:** WPF compilation, actual enabled/disabled tooltip behavior, `ToolTipService.ShowOnDisabled`, keyboard focus, UI Automation exposure, screen-reader announcements, high contrast, 125–200% DPI, 1440/1100/1099/1024/1023/640px layout, focus traversal and selection/navigation are **UNVERIFIED**. Tooltips on disabled controls may be discoverable by mouse but not keyboard; the static metadata does not establish assistive-technology usability or accessibility compliance. A related incident may be unavailable while an anomaly remains selected; the existing disabled state is authoritative, not a health signal.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. With a selected correlated incident, hover `View Related Incident`: tooltip describes opening the existing incident workspace only.
2. Keyboard-focus the enabled button: verify the contextual tooltip and accessible name/HelpText in Windows UI Automation.
3. Select an anomaly with no related incident: verify the original `CanOpenIncident` disabled state remains, with disabled-state tooltip available on hover.
4. Confirm no linked incident produces no new navigation or invented incident, and no fallback capture/telemetry action.
5. Activate the enabled button: verify the original `DashboardViewRelatedIncident_Click` → `OpenSelectedIncidentWorkspace` route and original incident workspace.
6. Confirm opening does not capture packets, export raw evidence, remediate, or assert verification of detection accuracy or incident impact.
7. Navigate the adjacent **Review finding** and **Full Detail** controls by keyboard: no new Tab stop, handler change or order regression.
8. Inspect 1440/1100/1099/1024/1023/640px, high contrast and 125–200% DPI for legible tooltip and unchanged panel geometry.
9. Verify unchanged local PPS chart, 80/500 read-only Live Events, unavailable CLI, Cisco/WebView2/ScottPlot and capture/trust/privacy boundaries.
10. Confirm only the two authorized paths changed, no fabricated screenshot metrics, no independent protocol/detection/test/workflow/runner/automation modifications.

**Open quality GAs:** pinned-SHA Windows compilation, actual keyboard/tooltip/screen-reader/high-contrast/DPI/responsive inspection **only after the owner says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-53:** inspect fresh LIVE HEAD, exact approved reference, this ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–52.

**References:** [WPF ToolTipService.ShowOnDisabled](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice.showondisabled); [WPF ToolTipService.ShowsToolTipOnKeyboardFocus](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice.showstooltiponkeyboardfocus); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext).

## GA UI-53 — Source-accurate numeric-cell guidance for High-Risk Hosts

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `a5698cd642c26c438f658c1b2915ab233ede357c`. Prior GA UI-52 source `acddf69055626cf9e691fe4f70ec64bdff52a9af`, publication `fe38d99133eec71c6d10bd2951f4732782fdec4f`. Independent P0341–P0350 OSCORE outer-option inspector work was already present at the starting HEAD. **Exact GA UI-53 source SHA:** `38340b79782d2daf439628a0019160250a862016`; **UI source blob:** `98ac275e9137fa3e60b605c6ff795cbf00474a66`. **Owned paths only:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; executed: 0.** No build, dotnet test, xUnit, replay, holdout, CI, runner, benchmark, production capture or running-app screenshot.

### Approved reference, original consumers and distinct scope

Resolved and **visually inspected** exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928). Its navy/graphite/cyan/teal palette, restrained severity, left navigation, KPIs, prioritized incidents, investigation, local PPS ScottPlot (10-sample average, bounded 120-point history), read-only local Live Events (80 displayed/500 retained), and explicitly **UNAVAILABLE visual-only CLI** remain unchanged. Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024 remain the existing layout contracts. Reference IPs, Mbps lines, timestamps, rule IDs, confidence, sensor counts and monitoring badges are **DEMO ONLY**; no values or capture health are inferred.

Audited live branch/ref and its recent commits, the implementation ledger through UI-52, `MainWindow.xaml`, `MainWindow.xaml.cs`, `MainWindow.Core.cs`, `MainWindow.Navigation.cs`, `MainWindow.Dashboard.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.DashboardResponsive.cs` and `Theme.xaml`. The original `DashboardHostItemsControl` binds to private `_dashboardHostRows` populated by `BuildSocHostRows`. Its `SocHostVm.RiskScore` is the maximum local score of grouped **unresolved correlated incidents** for each host, or the maximum normalized anomaly score only when there are no incident hosts. Its existing `ActiveIncidents` numeric property represents the number of unresolved correlated incidents, or the number of anomaly signals in that fallback. The existing full-host tooltip, accessible host-row name, eight-bucket activity description, visual values, grouping, order and five-row bound already exist (UI-18/UI-29). This GA specifically clarifies the **previously unexplained per-cell numeric meanings**; it does not repeat host identity or trend work.

### One cohesive UI-owned improvement

Add source-accurate `ToolTip` and `AutomationProperties.HelpText` to each of the two **existing** High-Risk Hosts numeric TextBlocks: `RiskScore` and `ActiveIncidents`. Risk guidance explains the maximum local group score and distinguishes it from detection confidence or verified impact. Items guidance explains incident-count versus anomaly-signal-count fallback and distinguishes the count from packets or verified incident impact. The tooltip and HelpText are **static explanations**, not new metrics. Existing `Text` bindings, accessible host label, foregrounds, fonts, alignment, spacing, item templates, keyboard focus, responsive widths and source data remain unchanged. No additional focus stops, controls, handlers, models, viewmodels, commands, telemetry, capture, security, protocol or detection changes.

The private source commit `38340b79782d2daf439628a0019160250a862016` descends directly from starting LIVE HEAD `a5698cd642c26c438f658c1b2915ab233ede357c` and changes only `Carthago/Views/MainWindow.xaml`. The source diff consists of four WPF attributes on two existing numeric TextBlocks. Source blob `98ac275e9137fa3e60b605c6ff795cbf00474a66`.

### Start/end static divergence and publication guard

**Start:** comparison of GA UI-52 publication `fe38d99133eec71c6d10bd2951f4732782fdec4f` with LIVE HEAD `a5698cd642c26c438f658c1b2915ab233ede357c` found one independent P0341–P0350 OSCORE protocol commit. Its changed paths were `Carthago/Services/ProtocolIntelligence/OscoreOuterOptionInspector.cs`, `Carthago.Tests/ProtocolIntelligence/OscoreOuterOptionInspectorTests.cs`, `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md`, and `docs/protocols/PROTOCOL_GA_P0341-P0350.md`; all disjoint from UI-owned files. Existing WPF partials/consumers, naming, routing, source and data contracts, privacy, capture/trust boundaries, Cisco/WebView2/ScottPlot and approved-reference interpretation are unchanged by this candidate.

**End/publication gate:** re-read LIVE remote branch HEAD **immediately before publication**, compare all intervening commits and paths, recheck both prepared source/docs blobs, XAML attributes and existing consumers, naming and provenance, and publish the **complete source+ledger private commit chain only** with one non-forced atomic GitHub `update_ref` and exact `expected_sha` lease. If the branch moves, reconcile only disjoint independent changes on a fresh HEAD and rebuild both private commits; STOP on overlap, failed lease, absent guarantee or unresolvable conflict. Never publish partially, create branches/PRs, rewrite history, modify independent streams or change their automations.

**Residual risks:** Windows compilation, WPF tooltip rendering on numeric TextBlocks, UI Automation HelpText exposure, screen-reader verbosity or duplicate announcements alongside the existing host accessible name, high contrast, 125–200% DPI, 1440/1100/1099/1024/1023/640px layout, pointer accessibility and row refresh are **UNVERIFIED**. The non-focusable numeric cells' hover tooltips do not establish keyboard-only discoverability; the host row accessible name remains the primary existing non-pointer explanation. Existing displayed host identifiers can be sensitive; no new identifiers, capture-health assertions or data collection were added.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Hover the Risk numeric cell in a correlated-incident host row: the tooltip explains maximum local risk, not detection confidence.
2. Hover the Items numeric cell in that row: the tooltip explains grouped unresolved correlated incidents, not packet counts.
3. With no incident hosts and anomaly-signal fallback active, confirm Risk guidance remains truthful for normalized anomaly risk.
4. In anomaly fallback, confirm Items guidance accurately describes signal counts rather than falsely claiming incidents.
5. Inspect UI Automation HelpText and screen-reader presentation for both numeric cells; check duplicate narration against the existing host accessible name.
6. Confirm original `RiskScore` and `ActiveIncidents` values, host truncation/full-host tooltip, five-row bound, ordering, activity glyphs and risk colors are unchanged.
7. Refresh source snapshots: ensure the two static tooltips remain truthful and no stale per-row values or cross-row labels are introduced.
8. Inspect 1440/1100/1099/1024/1023/640px, high contrast and 125–200% DPI for tooltip legibility, clipping and unchanged layout.
9. Verify unchanged operational KPIs, local PPS chart, prioritized incidents, investigation, Live Events 80/500, unavailable visual-only CLI, Cisco/WebView2 and privacy/capture/trust boundaries.
10. Confirm no fabricated screenshot telemetry and no engine/model/service/protocol/detection/shared API/security/test/benchmark/workflow/runner/automation or unrelated path edits.

**Open quality GAs:** pinned-SHA Windows compilation and actual UI, tooltip, keyboard, screen-reader, high-contrast, DPI and responsive inspection **only when the owner says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-54:** inspect fresh LIVE HEAD, approved image, ledger and WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–53.

**References:** [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF FrameworkElement.ToolTip](https://learn.microsoft.com/dotnet/api/system.windows.frameworkelement.tooltip).

## GA UI-54 — Full-text hover for truncated Recommended Actions rows

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `0689f736fa730e245031c1eafaf58c9175435677`. Prior GA UI-53 source `38340b79782d2daf439628a0019160250a862016`, publication `65a7833e3c00c1644d062928cbc205d9d806f5af`. The independent P0351–P0360 protocol research/documentation reconciliation commit `0689f736fa730e245031c1eafaf58c9175435677` was already present and untouched. **Exact GA UI-54 source commit SHA:** `a468978c0ec49dce725bb4c86fd420c807e0a174`; **source XAML blob:** `015834cce90899cff767729f7d32704caaaaf78e`. **Owned paths only:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; executed: 0.** No builds, dotnet test, xUnit, replays, holdouts, CI, GitHub Actions, runners, benchmarking, production capture or running-app screenshots.

### Approved reference and original-consumer audit

Resolved and **visually inspected** the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928). Its navy/graphite/cyan/teal visual system, restrained severity, left navigation, operational KPIs, prioritized incidents, investigation, local PPS ScottPlot (10-sample average, bounded 120-point history), read-only local Live Events (80 displayed / 500 retained), and explicitly **UNAVAILABLE visual-only CLI** are not altered. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024. Screenshot IPs, Mbps lines, timestamps, rule IDs, confidence and sensor/coverage figures are **DEMO ONLY**; no example values or capture-health claims were added.

Static inspection included the live remote ref, prior UI-53 candidate and intervening protocol paths, this ledger through UI-53, `MainWindow.xaml`, `MainWindow.xaml.cs`, `MainWindow.Core.cs`, `MainWindow.Navigation.cs`, `MainWindow.Dashboard.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.DashboardResponsive.cs` and `Theme.xaml`. The existing `DashboardActionItemsControl` binds to the private `_dashboardActionRows` collection populated by `BuildSocActionRows`. Incident rows use up to four existing `Incident.RecommendedActions` strings with a host/risk subtitle; anomaly fallback uses the existing anomaly summary; baseline fallback uses a static informational suggestion. The title and subtitle TextBlocks already use `TextTrimming="CharacterEllipsis"`, so long strings can be visually clipped within the narrow summary panel. GA UI-27 clarified badge provenance and GA UI-32/36 clarified panel info glyphs; neither exposes the full **Recommended Actions title and subtitle** when clipped. No shared contract, viewmodel or new source is needed.

### One cohesive UI-owned improvement

On the **two existing Recommended Actions row TextBlocks only**, add `ToolTip="{Binding Title}"` to the already `Text="{Binding Title}"` title and `ToolTip="{Binding Subtitle}"` to the already `Text="{Binding Subtitle}"` subtitle. Hover reveals the **same full current displayed string**, without a second source, inference, transformation or persistence. This also covers incident, anomaly and baseline fallback rows and refreshes with the existing item data context. The tooltip is not conditional on actual clipping. Preserve text bindings, trimming, font, foreground, alignment, row dimensions, scrolling, badge semantics and badge tooltip, item ordering, risk calculations, keyboard order and original navigation. No new focus stops, controls, handlers, commands, services, engines, models, protocols, detection logic, capture, security or telemetry.

The private source commit `a468978c0ec49dce725bb4c86fd420c807e0a174` descends from the exact starting HEAD `0689f736fa730e245031c1eafaf58c9175435677` and changes **only** `Carthago/Views/MainWindow.xaml`: two existing TextBlocks receive one tooltip binding each; no other XAML lines are edited. Source blob `015834cce90899cff767729f7d32704caaaaf78e`.

### Start/end static divergence and publication guard

**Start:** compare prior GA UI-53 publication `65a7833e3c00c1644d062928cbc205d9d806f5af` against starting LIVE HEAD `0689f736fa730e245031c1eafaf58c9175435677`: exactly one independent P0351–P0360 documentation commit changed `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md` and `docs/protocols/PROTOCOL_GA_P0351-P0360.md`. These paths are disjoint from UI ownership. Existing WPF partials/consumers, action VM properties, resource keys, naming, navigation, privacy/capture/trust boundaries, Cisco/WebView2/ScottPlot and the approved-reference interpretation remain unchanged by the proposed source diff.

**End/publication gate:** re-read LIVE remote branch HEAD immediately before publishing, compare all intervening commits and paths, inspect prepared source+ledger Git objects and WPF consumers, naming, provenance, privacy and approved reference, and publish the **complete source+ledger private chain only** through one non-forced atomic GitHub `update_ref` with exact `expected_sha` lease. If the branch moved, reconcile disjoint independent work with fresh HEAD and new private commits; STOP on overlap, conflict, absent lease guarantee or unsafe merge. Never publish a partial candidate, create branches/PRs, rewrite history, or modify independent streams/automations.

**Residual risks:** Windows compilation, tooltip display and placement for long/untrusted incident text, dynamic row refresh, high contrast, 125–200% DPI, narrow-window clipping and scrolling, UI Automation/screen-reader behavior and keyboard-only discoverability are **UNVERIFIED**. Tooltips on non-focusable TextBlocks do not establish keyboard-only access; the underlying TextBlock text remains present in the visual/automation tree, subject to actual Windows inspection. Subtitle text can include reported host identifiers already visible in the row; the tooltip exposes no new identifiers or raw evidence. No detection-quality, remediation, verified impact, packet-attribution or capture-health claim is added.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Hover a truncated incident action title; tooltip shows the full exact current `Title` without ellipsis.
2. Hover a truncated incident host/risk subtitle; tooltip shows the full current `Subtitle` without asserting verified host identity or impact.
3. With anomaly-only fallback, verify title/subtitle tooltips reflect the existing anomaly summary and no incident-specific assertion.
4. With no incidents/anomalies, verify baseline-learning title/subtitle tooltips match the existing informational strings.
5. Refresh incident/anomaly snapshots and switch fallback states; verify tooltips track the current row and never retain previous text.
6. Verify up to four incident action rows, original order, list scrolling, `#N` badge, anomaly `Risk N` badge, baseline `—` badge and existing `BadgeDescription` tooltips remain unchanged.
7. Inspect UI Automation and screen-reader reading of title/subtitle and tooltip; check duplicate narration, hover discoverability and keyboard-only limitations.
8. Inspect 1440/1100/1099/1024/1023/640px, high contrast and 125–200% DPI for tooltip placement, overflow, clipping and unchanged summary-panel geometry.
9. Verify unchanged operational KPIs, local PPS ScottPlot, incident selection, investigation, Live Events 80/500, unavailable visual-only CLI, Cisco/WebView2, and privacy/capture/trust boundaries.
10. Confirm only two authorized paths changed; no fabricated screenshot metrics, shared API, engine/model/service, protocol/detection, test/benchmark/workflow/runner/automation or unrelated modifications.

**Open quality GAs:** pinned-SHA Windows compilation, actual tooltip/keyboard/screen-reader/high-contrast/DPI/responsive inspection **only after the owner says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-55:** inspect fresh LIVE HEAD, exact approved reference, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–54.

**References:** [WPF FrameworkElement.ToolTip](https://learn.microsoft.com/dotnet/api/system.windows.frameworkelement.tooltip); [WPF TextBlock.TextTrimming](https://learn.microsoft.com/dotnet/api/system.windows.controls.textblock.texttrimming); [WPF ToolTipService](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice).

## GA UI-55 — Keyboard-focus destination guidance for Raw / Advanced shortcut tiles

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `3ba828431effefc948b83028617060a9a6495a99`. Prior GA UI-54 source `a468978c0ec49dce725bb4c86fd420c807e0a174`, documentation/publication `36d88e246ec4f1c5318a694b6433af832625481c`. Independent P0361–P0370 SOME/IP-SD source/tests/protocol documentation were already present at the starting HEAD. **Exact GA UI-55 source commit SHA:** `04ccd17466d8bb2da07e69314f70823fe19f7aa8`; **source XAML blob SHA:** `a49f77bea55e1178dab9b212b62559850ce9f8ba`. **Owned paths only:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; executed: 0.** No build, dotnet test, xUnit, replay, holdout, CI, runner, benchmark, capture or running-app screenshot.

### Approved reference, original consumers and distinct scope

Resolved and **visually inspected** exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928). The reference's navy/graphite/cyan/teal, restrained severity, left navigation, operational KPIs, prioritized incidents, investigation, local PPS ScottPlot (10-sample average, bounded 120-point history), read-only local Live Events (80 displayed/500 retained) and explicitly **UNAVAILABLE** visual-only CLI remain unchanged. Existing Wide >=1440, Standard 1100–1439, Compact 1024–1099 and below-1024 behavior remain unchanged. Screenshot IPs, traffic Mbps lines, rule IDs, timestamps, confidence, sensor counts and health indicators are **DEMO ONLY**; no values or monitoring/capture health are inferred.

Audited LIVE branch/recent commits, ledger through GA UI-54, `MainWindow.xaml`, `MainWindow.xaml.cs`, `MainWindow.Core.cs`, `MainWindow.Dashboard.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Navigation.cs` and `Theme.xaml`. The existing four `Raw / Advanced Shortcuts` tile buttons already have source-accurate visible labels and AutomationProperties.Name/HelpText (GA UI-20 and GA UI-32); however they lack pointer/keyboard-focus tooltips. Their original handlers route `DashboardRawTraffic_Click` and `DashboardPcapExplorer_Click` to `Nav_LiveTraffic_Click`, and `DashboardRawDetections_Click` and `DashboardForensicsWorkspace_Click` to `Nav_Alerts_Click`. The navigation partial activates the corresponding existing sidebar traffic or detection filters. No separate PCAP Explorer or forensics workspace is opened. This GA is limited to **keyboard-discoverable hover/focus guidance on these four existing tile controls**, not a repeat of earlier destination naming, accessible labels, or routing changes.

### One cohesive UI-owned improvement

Add `ToolTip` and `ToolTipService.ShowsToolTipOnKeyboardFocus="True"` to the four existing Raw Traffic, Raw Detections, Traffic Analysis and Detection Investigation shortcut tiles. Tooltips describe the actual existing destination and explicitly avoid claiming separate PCAP/forensics workspaces, capture activation, verified detections or evidence export. Original `Click` handlers, `AutomationProperties.Name`/`HelpText`, button styles, visual text, order, tab stops, tile geometry, colors, routing, sidebar filters and data remain untouched. Exactly eight static WPF attributes are added across four existing buttons; no new controls, bindings, commands, models, viewmodels, telemetry, detection/protocol code, capture or shared API.

The private source commit `04ccd17466d8bb2da07e69314f70823fe19f7aa8` descends directly from starting LIVE HEAD `3ba828431effefc948b83028617060a9a6495a99` and changes only `Carthago/Views/MainWindow.xaml`. Its blob is `a49f77bea55e1178dab9b212b62559850ce9f8ba`.

### Start/end static divergence and publication guard

**Start:** comparing prior GA UI-54 publication `36d88e246ec4f1c5318a694b6433af832625481c` with starting LIVE HEAD `3ba828431effefc948b83028617060a9a6495a99` shows one independent P0361–P0370 SOME/IP-SD protocol commit. Its changed paths are `Carthago/Services/ProtocolIntelligence/SomeIpSdEnvelopeInspector.cs`, `Carthago.Tests/ProtocolIntelligence/SomeIpSdEnvelopeInspectorTests.cs`, `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md`, and `docs/protocols/PROTOCOL_GA_P0361-P0370.md`; none overlap UI-owned files. The new candidate does not change WPF partial hooks/consumers, names, routing, capture/trust/privacy, Cisco/WebView2/ScottPlot, responsive thresholds or reference interpretation.

**End/publication gate:** re-read LIVE remote HEAD immediately before publishing, compare all intervening commits and changed paths, and inspect prepared source/docs blobs, the four original handlers, existing accessible labels, naming, provenance, privacy and approved reference. Publish **complete private source+documentation commit chain only** using **one non-forced atomic GitHub `update_ref` with exact `expected_sha` lease**. If moved, reconcile disjoint changes onto fresh HEAD with new private commits and a fresh lease; STOP on overlap, conflict, failed lease or missing guarantee. Never publish partially, force push, rewrite history, create branches/PRs or change independent streams/automations.

**Residual risks:** Windows compilation, actual keyboard-focus tooltip behavior, screen-reader/UI Automation presentation, tooltip positioning, focus traversal, high contrast, 125–200% DPI, and 1440/1100/1099/1024/1023/640px rendering remain **UNVERIFIED**. WPF tooltip presentation can vary by Windows accessibility client; static metadata alone is not proof of accessible usability. No telemetry/capture-health or verified-security claims are introduced.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Hover Raw Traffic: tooltip accurately describes existing Live Traffic and traffic filters, without promising capture.
2. Keyboard-focus Raw Traffic: tooltip appears without adding a Tab stop; UI Automation retains original accessible Name/HelpText.
3. Hover and keyboard-focus Raw Detections: tooltip describes existing Detection Events and detection filters without promising verification or evidence export.
4. Hover and keyboard-focus Traffic Analysis: tooltip clarifies it opens existing Live Traffic, not a separate PCAP Explorer.
5. Hover and keyboard-focus Detection Investigation: tooltip clarifies it opens existing Detection Events, not a separate forensics workspace.
6. Activate each tile: verify the original `DashboardRawTraffic_Click`, `DashboardRawDetections_Click`, `DashboardPcapExplorer_Click` and `DashboardForensicsWorkspace_Click` routes and sidebar filter behavior.
7. Navigate four tiles with Tab/Shift+Tab: original focus order, styles, dimensions and neighboring Open Live Traffic button remain unchanged.
8. Inspect 1440/1100/1099/1024/1023/640px, high contrast and 125–200% DPI for tooltip placement, contrast and clipping.
9. Confirm operational KPIs, local PPS ScottPlot, incidents/investigation, read-only Live Events 80/500, unavailable CLI, Cisco/WebView2 and capture/trust/privacy remain unchanged.
10. Confirm only two UI-owned paths changed, no fabricated reference data, no detection/protocol/test/workflow/runner/automation or shared API edits.

**Open quality GAs:** pinned-SHA Windows compilation and actual tooltip/keyboard/screen-reader/high-contrast/DPI/responsive inspection only after the owner says **“now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-56:** inspect fresh LIVE HEAD, approved image, this ledger and WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–55.

**References:** [WPF ToolTipService.ShowsToolTipOnKeyboardFocus](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice.showstooltiponkeyboardfocus); [WPF FrameworkElement.ToolTip](https://learn.microsoft.com/dotnet/api/system.windows.frameworkelement.tooltip); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext).

## GA UI-56 — Keyboard-focus filter guidance in read-only Live Events

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `df49577886a511639333acc2643ae5384ea7af61`. Prior GA UI-55 source `04ccd17466d8bb2da07e69314f70823fe19f7aa8`, docs/publication `0e48047c071c2fcea02181764ec648bc8bde3517`. The intervening independent P0371–P0380 protocol reconciliation modified only `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md` and `docs/protocols/PROTOCOL_GA_P0371-P0380.md`; it was already present and is untouched. **Exact GA UI-56 source commit:** `49af4979745e721d226ff94e81ae2d25e1db7235`; **source XAML blob:** `c1b513e85304ba179ee233406e8c988e5c24e678`. **Owned paths only:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; executed: 0.** No builds, dotnet tests, xUnit, replays, holdouts, CI, runners, benchmarks, production capture or running-app screenshots.

### Approved reference, consumers and non-duplication

Resolved and **visually inspected** the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928). Preserve navy/graphite/cyan/teal, restrained severity, left navigation, operational KPIs, local PPS ScottPlot (10-sample average, bounded 120-point history), prioritized incidents, investigation, read-only local Live Events (80 displayed / 500 retained), and explicitly **UNAVAILABLE visual-only CLI**. Existing Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below-1024 behavior remain unchanged. Screenshot IPs, Mbps series, timestamps, rule IDs, confidence, sensor counts and capture-health graphics are **DEMO ONLY**; no fabricated values or claims are added.

Static audit included the LIVE branch and recent commit divergence, ledger through UI-55, `MainWindow.xaml`, `MainWindow.xaml.cs`, `MainWindow.Core.cs`, `MainWindow.Dashboard.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Navigation.cs`, `MainWindow.DataEvents.cs`, `MainWindow.Filters.cs`, `MainWindow.Responsive.cs` and `Theme.xaml`. The existing Live Events filter row has four keyboard-focusable controls (Severity, Protocol, Rule, Search) with source-accurate hover ToolTips and UI Automation Name/HelpText. The Clear filters button already has truthful HelpText but no tooltip. The original `DashboardLiveEventsClearFilters_Click` resets exactly the two ComboBox selected indices and clears the two TextBoxes, then refreshes the bounded local display. `RefreshDashboardLiveEvents` filters existing retained `_alerts` and takes up to 80 rows; `MainWindow.DataEvents.cs` retains at most 500 events. GA UI-16/26/39 covered visible filter labels and HelpText; GA UI-55 covered shortcut tiles, not **keyboard-focus tooltip discoverability across the Live Events filter row**. No shared contract, viewmodel, data producer or new handler is needed.

### One cohesive UI-owned improvement

Add `ToolTipService.ShowsToolTipOnKeyboardFocus="True"` to the four existing Severity/Protocol/Rule/Search filter controls, retaining their original ToolTip strings. Give the existing **Clear filters** button a truthful hover tooltip, `Reset only the four dashboard Live Events filters. Retained local detection events and filters in other views are not cleared.`, and enable the same keyboard-focus tooltip behavior. **Exactly six WPF attributes added across five existing controls; zero deletions.** Existing `AutomationProperties.Name`/`HelpText`, visible captions, focus/tab order, dimensions, bindings, filter selection/text handlers, refresh, read-only grid, virtualization, frozen time column, status/provenance labels and source values remain unchanged. No telemetry, capture, rule evaluation, protocol inspection, evidence export, remediation, storage or security changes.

Private source commit `49af4979745e721d226ff94e81ae2d25e1db7235` descends directly from starting LIVE HEAD `df49577886a511639333acc2643ae5384ea7af61`, changing only `Carthago/Views/MainWindow.xaml` (+6/-0). Source blob `c1b513e85304ba179ee233406e8c988e5c24e678` is prepared but remains **unverified** until Windows inspection is authorized.

### Start/end static divergence and publication guard

**Start:** prior GA UI-55 publication `0e48047c071c2fcea02181764ec648bc8bde3517` to LIVE HEAD `df49577886a511639333acc2643ae5384ea7af61` shows exactly one disjoint protocol documentation commit (P0371–P0380); no UI paths overlap. The new source-only diff changes no WPF partials, handlers, bindings, API names, theme, responsive breakpoints, Cisco/WebView2/ScottPlot, privacy/trust/capture or approved-reference interpretation. The original consumer explicitly resets only the four filter values, not retained events.

**End/publication gate:** immediately before publication re-read LIVE branch HEAD, compare all intervening changes with the private source/docs chain, inspect both Git blobs, original WPF consumers, naming, provenance, privacy and approved image. Publish **complete source+ledger chain only** through a single non-forced atomic GitHub `update_ref` with `expected_sha` lease on the same branch. If moved, reconcile disjoint independent work onto fresh HEAD with new private commits and a fresh lease; STOP on overlapping paths, conflicts or missing guarantee. Never publish a partial candidate, create branches/PRs, rewrite history, force push or alter independent streams/automations.

**Residual risks:** Windows compilation, actual WPF keyboard-focus tooltip behavior, ComboBox popup focus, text-entry focus, screen-reader/UI Automation narration, tooltip overlap and lifetime, high contrast, 125–200% DPI, and responsive 1440/1100/1099/1024/1023/640px remain **UNVERIFIED**. Tooltip presentation may differ by Windows accessibility client. Existing accessible labels/HelpText remain primary non-tooltip descriptions. Clear filters never clears underlying retained events; no capture-health, packet attribution, detection-quality or verified-impact assertion is introduced.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Tab-focus Severity: existing tooltip appears; accessible label, HelpText and selected value remain unchanged.
2. Tab-focus Protocol: existing tooltip appears; All protocols still includes protocols beyond the individual dropdown entries.
3. Tab-focus Rule: existing tooltip appears without changing the exact/partial rule-ID filter or invoking rule evaluation.
4. Tab-focus Search: existing tooltip appears without implying raw evidence or archived-event search.
5. Hover and Tab-focus Clear filters: new tooltip explains only four dashboard filter values reset, not retained event deletion or other views' filters.
6. Activate Clear filters after combined filtering: existing ComboBox indices/text values reset and bounded retained events reappear without loss, preserving 80 displayed / 500 retained limits.
7. Tab/Shift+Tab through five existing controls: no new focus stops, handler changes, duplicated accessible names or focus traps; inspect ComboBox popup interaction and screen-reader announcements.
8. Inspect 1440/1100/1099/1024/1023/640px, high contrast and 125–200% DPI for tooltip legibility, placement and unchanged filter geometry.
9. Verify unchanged operational KPIs, local PPS ScottPlot, prioritized incidents, investigation, Live Events row provenance, unavailable CLI, Cisco/WebView2 and privacy/capture/trust.
10. Confirm exactly two authorized paths in the complete candidate, no fabricated reference telemetry and no engine/model/service/detection/protocol/shared API/security/test/workflow/runner/automation edits.

**Open quality GAs:** pinned-SHA Windows compilation and actual tooltip, keyboard, screen-reader, high-contrast, DPI and responsive inspection only after owner says **“now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-57:** inspect fresh LIVE HEAD, approved reference, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–56.

**References:** [WPF ToolTipService.ShowsToolTipOnKeyboardFocus](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice.showstooltiponkeyboardfocus); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext).

## GA UI-57 — Keyboard-discoverable dashboard panel footer navigation

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `8e159ef6a87215e06fc67dc2e29c451a2f46c99a`. Prior GA UI-56 source `49af4979745e721d226ff94e81ae2d25e1db7235`, documentation/publication `fe34d1126d512a22faafbb6389d8f72f4cacb252`. Independent GA P0381–P0390 BACnet BVLC control inspector source, authored tests and protocol documentation were already present in the starting HEAD; this UI stream did not edit or execute them. **Exact GA UI-57 source commit:** `f4ef51f806c74e012d0eeeef76a73b2e89cfbd8b`; **source XAML blob:** `8436e1c4642335dd6b6241efe7863a4ac5116cf5`. **Owned paths only:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; tests executed: 0.** No dotnet build/test, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, production capture or running-WPF screenshot.

### Approved image, source audit and distinct scope

Resolved and **visually inspected** the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928), not an approximate substitute. Its deep navy/graphite, cyan/teal, restrained severity, left navigation, operational KPI cards, local PPS ScottPlot (10-sample average, bounded 120-point history), prioritized incidents, investigation, read-only local Live Events (80 displayed / 500 retained) and explicitly **UNAVAILABLE** visual-only CLI remain unchanged. Existing Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below-1024 presentation are not changed. Screenshot IPs, Mbps curves, timestamps, rule IDs, confidence and capture-health/sensor graphics are **DEMO ONLY**; none is imported into telemetry or represented as observed.

Audited LIVE remote HEAD/recent commits, ledger through GA UI-56, `MainWindow.xaml`, `MainWindow.Dashboard.cs`, `MainWindow.Navigation.cs`, `MainWindow.xaml.cs`, `MainWindow.Core.cs`, `MainWindow.DashboardResponsive.cs` and `Theme.xaml`. The visible **Review findings →** button in the High-Risk Hosts panel already has truthful hover ToolTip and UI Automation Name/HelpText but lacks keyboard-focus tooltip discoverability. `DashboardInvestigateHost_Click` calls `OpenSelectedIncidentWorkspace()` if an incident is selected, otherwise `Nav_Anomalies_Click`. The visible **Open Live Traffic →** footer in Raw / Advanced Shortcuts already has an accessible Name/HelpText but no ToolTip. `DashboardRawTraffic_Click` delegates to `Nav_LiveTraffic_Click`, which activates `LiveTrafficView` and the existing sidebar traffic filters. GA UI-20 corrected footer labels/destinations and GA UI-55 added focus tooltips to the **four shortcut tiles**, not these two separate **panel footer buttons**. GA UI-56 covered Live Events filters. No new handler, shared contract, viewmodel, telemetry producer or route is needed.

### One cohesive UI-owned change

Complete keyboard-focus contextual guidance on the **two existing dashboard summary-panel footer navigation buttons** only:

- **Review findings →**: retain its original truthful hover ToolTip, accessible Name/HelpText, button style and `DashboardInvestigateHost_Click` handler; add `ToolTipService.ShowsToolTipOnKeyboardFocus="True"` so the existing incident-or-anomaly destination explanation is available when focused.
- **Open Live Traffic →**: add a truthful hover ToolTip, `Opens the existing Live Traffic view and its sidebar traffic filters. Navigation only; this button does not start capture.`, and `ToolTipService.ShowsToolTipOnKeyboardFocus="True"`. Preserve its existing accessible Name/HelpText, caption, dimensions, `DashboardRawTraffic_Click` handler, and actual traffic-filter destination.

Exactly **three WPF attributes** are added to two existing buttons. No new controls, focus stops, event handlers, source values, commands, data bindings, navigation routes, state changes, layout resources or UI partials. No capture activation, evidence export, remediation, verified detection, or host inventory is implied. The source commit `f4ef51f806c74e012d0eeeef76a73b2e89cfbd8b` is a direct child of starting HEAD `8e159ef6a87215e06fc67dc2e29c451a2f46c99a`, changes only `Carthago/Views/MainWindow.xaml`, and contains the source blob `8436e1c4642335dd6b6241efe7863a4ac5116cf5`.

### Start/end static divergence and publication guard

**Start:** compare prior GA UI-56 publication `fe34d1126d512a22faafbb6389d8f72f4cacb252` with LIVE `8e159ef6a87215e06fc67dc2e29c451a2f46c99a`: exactly one independent GA P0381–P0390 protocol commit, changing `Carthago/Services/ProtocolIntelligence/BacnetBvlcControlInspector.cs`, `Carthago.Tests/ProtocolIntelligence/BacnetBvlcControlInspectorTests.cs`, `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md` and `docs/protocols/PROTOCOL_GA_P0381-P0390.md`. These paths are disjoint from UI ownership. Original WPF partials/consumers, names, sidebar routes, accessible metadata, responsive breakpoints, theme resources, local PPS ScottPlot, Cisco/WebView2, privacy/capture/trust boundaries and approved-reference interpretation remain unchanged by the source diff.

**End/publication gate:** re-read LIVE remote branch HEAD immediately before publication, compare any concurrent detection/protocol commits and their changed paths, inspect both prepared Git blobs, exact source parentage and WPF consumers/naming/privacy/provenance/reference. Publish **the complete private source+ledger chain only** via **one non-forced atomic GitHub `update_ref` with exact `expected_sha` lease** on the existing branch. If moved, reconcile only disjoint changes onto the fresh HEAD with new private commits and fresh lease; STOP on overlap, conflict or absent lease guarantee. Never publish a partial candidate, create branches/PRs, force push, rewrite history or alter independent streams or their automations.

**Residual risks:** Windows compilation, actual tooltip visibility and keyboard-focus timing, screen-reader/UI Automation announcements, conditional incident/anomaly navigation, focus retention on view changes, high contrast, 125–200% DPI and 1440/1100/1099/1024/1023/640px screenshots remain **UNVERIFIED**. Keyboard-focus tooltip metadata does not itself prove accessible presentation on Windows. Tooltip content contains no new host identifiers, telemetry, evidence payloads or capture-health claims.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Hover Review findings: existing tooltip describes incident workspace when available, otherwise Anomalies; no host-inventory claim.
2. Tab-focus Review findings: original tooltip is discoverable on keyboard focus; original accessible Name/HelpText unchanged.
3. Activate Review findings with selected incident: original incident workspace opens; no new capture, export or remediation.
4. Activate Review findings without selected incident: original Anomalies navigation occurs.
5. Hover Open Live Traffic: new tooltip names existing Live Traffic and sidebar traffic filters, not capture activation.
6. Tab-focus Open Live Traffic: new tooltip is discoverable, original accessible Name/HelpText and focus order unchanged.
7. Activate Open Live Traffic: original `DashboardRawTraffic_Click` route and traffic filters work; neighboring four tiles remain unchanged.
8. Inspect 1440/1100/1099/1024/1023/640px, high contrast and 125–200% DPI for tooltip placement, legibility, clipping, focus and unchanged footer geometry.
9. Verify unchanged operational KPIs, local PPS ScottPlot, incident selection/investigation, Live Events 80/500, unavailable visual-only CLI, Cisco/WebView2 and capture/privacy/trust.
10. Confirm only two UI-owned paths in the complete candidate, no fabricated screenshot data and no engine/model/service/detection/protocol/shared API/security/test/benchmark/workflow/runner/automation edits.

**Open quality GAs:** pinned-SHA Windows WPF compilation, real tooltip/keyboard/screen-reader/high-contrast/DPI/responsive inspection **only after owner says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-58:** inspect fresh LIVE HEAD, approved image, this ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–57.

**References:** [WPF ToolTipService.ShowsToolTipOnKeyboardFocus](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice.showstooltiponkeyboardfocus); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext).

## GA UI-58 — Keyboard-discoverable System Settings destination for dashboard Customize

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `f8388d27cbf1105336364a2b49cf4862d79ee029`. Prior GA UI-57 source `f4ef51f806c74e012d0eeeef76a73b2e89cfbd8b`, docs/publication `a032e83b3c4e2b6fb9cf65a585c7474195ac8261`. Intervening independent P0391–P0400 protocol source audit/documentation commit `f8388d27cbf1105336364a2b49cf4862d79ee029` touched only `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md` and `docs/protocols/PROTOCOL_GA_P0391-P0400.md`; it was already in the starting HEAD and remains untouched. **Exact GA UI-58 source commit:** `688f941864d4228b76ea9b4262dc4f6b19c87046`; **XAML source blob:** `9b26f60b2011279aa130e3a97fc275b445270858`. **Owned paths only:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; executed: 0.** No build, dotnet test, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, production capture or running-WPF screenshot.

### Approved image, source audit and non-duplication

Resolved and **visually inspected** exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928). Preserve navy/graphite/cyan/teal, restrained severity, left navigation, operational KPI cards, local PPS ScottPlot (ten-sample moving average, bounded 120-point history), prioritized incidents, investigation, read-only local Live Events (80 displayed / 500 retained), and explicitly **UNAVAILABLE** visual-only CLI. Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024 remain unchanged. Screenshot IPs, Mbps traces, sensor/coverage values, timestamps, rule IDs, confidence and CLI output are **DEMO ONLY**, not evidence or actual capture health.

Inspected LIVE branch/recent commits and ledger through GA UI-57, `MainWindow.xaml`, `MainWindow.xaml.cs`, `MainWindow.Dashboard.cs`, `MainWindow.Navigation.cs`, `MainWindow.Core.cs`, `MainWindow.Responsive.cs`, `MainWindow.DashboardResponsive.cs`, and `Theme.xaml`. The visible header **Customize** button has `DashboardOpenSettings_Click` but previously lacked explicit destination tooltip and accessible Name/HelpText. Original handler in `MainWindow.Dashboard.cs` delegates to `Nav_Settings_Click`; `MainWindow.Navigation.cs` displays the existing `SettingsView`, activates `SystemSettings` sidebar selection and hides sidebar filters. It does **not** invoke the hidden dashboard layout-manager editor, edit preferences, or activate capture. GA UI-20/48/55/57 documented other navigation buttons; GA UI-31 documented the adjacent capture-source selector. No previous GA UI-01–57 provided keyboard-focus destination guidance on **this Customize header button**.

### One cohesive UI-owned improvement

Add exactly four WPF attributes to the **existing** header Customize button: a truthful hover `ToolTip` naming the existing System Settings view and navigation-only scope; `ToolTipService.ShowsToolTipOnKeyboardFocus="True"`; `AutomationProperties.Name="Open System Settings"`; and `AutomationProperties.HelpText` describing the actual Settings view, sidebar selection/filter visibility, and the absence of dashboard-layout editing or capture activation. The original visible caption **Customize**, width 104, height 30, `SecondaryButton` style, margin, handler, route, tab/focus order and responsive group are preserved. No new control, command, layout editor, focus stop, viewmodel, event producer, telemetry, preference write, capture action or shared API. Source-only commit `688f941864d4228b76ea9b4262dc4f6b19c87046` is a direct child of starting LIVE HEAD `f8388d27cbf1105336364a2b49cf4862d79ee029`; its sole changed path is `Carthago/Views/MainWindow.xaml`.

### Start/end static divergence and publication guard

**Start:** prior GA UI-57 publication `a032e83b3c4e2b6fb9cf65a585c7474195ac8261` to LIVE `f8388d27cbf1105336364a2b49cf4862d79ee029` is one disjoint protocol-docs-only commit (P0391–P0400). Existing WPF partials/consumers, handler names, responsive breakpoints, theme, local PPS ScottPlot, Cisco/WebView2, privacy/capture/trust boundaries, and approved-reference interpretation are not modified. `DashboardOpenSettings_Click` and `Nav_Settings_Click` were read, not executed.

**End/publication gate:** immediately before publication re-read LIVE branch HEAD and compare intervening detection/protocol/UI changes; inspect both private Git blobs, commit parentage, exact owned changed paths, original WPF consumers, names, provenance, privacy and approved reference. Publish the **complete source+ledger chain only** with **one non-forced atomic GitHub `update_ref` and exact `expected_sha` lease** on the same existing branch. If HEAD moves, reconcile disjoint work onto fresh HEAD with new private commits and a fresh lease; STOP on overlap, conflict or missing guarantee. Never publish a partial candidate, create branches/PRs, rewrite history, force push, or modify independent streams/automations.

**Residual risks:** Windows WPF compilation, tooltip rendering on hover and keyboard focus, actual screen-reader/UI Automation Name/HelpText exposure, tooltip timing/placement, focus after Settings navigation, high contrast, 125–200% DPI and 1440/1100/1099/1024/1023/640px screenshots remain **UNVERIFIED**. An accessible metadata declaration is not proof of screen-reader behavior. No fabricated reference telemetry, capture-health claim, evidence payload or incident-resolution assertion is added.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Hover the existing header Customize button: tooltip describes navigation to System Settings, not inline dashboard layout editing.
2. Tab-focus Customize: the same tooltip becomes discoverable without new focus stops or a changed tab order.
3. Inspect UI Automation: accessible Name is "Open System Settings" and HelpText accurately describes the existing destination and limitations.
4. Activate Customize by mouse: the original `DashboardOpenSettings_Click` delegates to `Nav_Settings_Click` and opens `SettingsView`.
5. Activate Customize by keyboard: the existing `SystemSettings` sidebar selection and sidebar-filter hiding occur; no new route or command is introduced.
6. Confirm that simply navigating to Settings does not alter the dashboard layout, write preferences, start/stop capture, or claim capture health.
7. Confirm original visible caption, dimensions, theme, focus visual, handler, neighboring anomalies-only toggle and capture-source selector remain unchanged.
8. Inspect Wide 1440, Standard 1100, Compact 1099/1024, and below-1024 1023/640px with 125–200% DPI and high contrast for tooltip legibility, focus and unchanged header positioning.
9. Verify unchanged operational KPIs, local PPS/ten-sample average/120-point history, prioritized incidents, investigation, Live Events 80/500, visual-only unavailable CLI and Cisco/WebView2/ScottPlot.
10. Confirm exactly two authorized paths in the complete candidate, zero fabricated screenshot metrics, and no engine/model/service/detection/protocol/shared API/security/test/benchmark/workflow/runner/automation changes.

**Open quality GAs:** pinned-SHA Windows WPF compilation and real tooltip/keyboard/screen-reader/high-contrast/DPI/responsive inspection **only after owner says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-59:** inspect fresh LIVE HEAD, exact approved image, ledger and WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–58.

**References:** [WPF ToolTipService.ShowsToolTipOnKeyboardFocus](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice.showstooltiponkeyboardfocus); [WPF AutomationProperties.Name](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.name); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext).

## GA UI-59 — Source-accurate UTC footer clock provenance

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `fd9a518e37b5ee1e9bffc4c30f8ce638bc0fe459`. Prior GA UI-58 source `688f941864d4228b76ea9b4262dc4f6b19c87046`, documentation/publication `710174ccfaead3a9eaa642ce705a622ad8e3f4f4`. The one intervening independent protocol commit `fd9a518e37b5ee1e9bffc4c30f8ce638bc0fe459` reconciles GA P0401–P0410 media inputs/distinctness in `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md` and `docs/protocols/PROTOCOL_GA_P0401-P0410.md`; these are disjoint, already present, and untouched by UI. **Exact UI source commit:** `7fb25b4e70bc88e725b01a7a29d75aab28e56b74`; **XAML blob:** `1f06d923923a0a0bf412cb7ed92082268315902f`. **Owned paths only:** `Carthago/Views/MainWindow.xaml` and this `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; executed: 0.** No dotnet build/test, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, production capture or running-WPF screenshot.

### Approved image, original consumers and non-duplication

Resolved and **visually inspected** exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928). The reference is a visual concept, not an operational telemetry source: its IPs, Mbps traces, timestamps, confidence, rule IDs, sensor/coverage counts and CLI output are **DEMO ONLY**. Preserve deep navy/graphite, cyan/teal, restrained severity, left navigation, operational KPI cards, local PPS ScottPlot (ten-sample moving average, bounded 120-point history), prioritized incidents, investigation, read-only local Live Events (80 displayed / 500 retained), and explicitly **UNAVAILABLE** visual-only CLI. Wide >=1440, Standard 1100–1439, Compact 1024–1099, graceful below 1024 and existing Cisco/WebView2/ScottPlot behavior remain untouched.

Audited live branch/recent commits, ledger through UI-58, `MainWindow.xaml`, `MainWindow.xaml.cs`, `MainWindow.Core.cs`, `MainWindow.Dashboard.cs`, `MainWindow.Navigation.cs`, `MainWindow.Responsive.cs`, `MainWindow.DashboardResponsive.cs` and `Theme.xaml`. The existing footer `FooterUtcText` initially displays `UTC --:--:--`. Its sole source writer is `UpdateMonitoringHeader` in `MainWindow.Dashboard.cs`, assigning `$"UTC {DateTime.UtcNow:HH:mm:ss}"` when the monitoring header refreshes. The header refresh is timer-driven and can also occur on dashboard state/events; it is **not a guaranteed per-second clock**. This UTC system-clock sample is neither a packet/detection/incident timestamp nor evidence of clock synchronization. Earlier UI-01–58 preserved the footer clock and corrected local capture-health claims but did **not** provide accessible current-value and time-provenance guidance for `FooterUtcText`.

### One cohesive UI-owned change

On the existing, non-focusable footer UTC `TextBlock` only, add: (1) a hover tooltip describing system-clock `HH:mm:ss`, header-refresh sampling, omitted date, and non-event/non-synchronization scope; (2) `AutomationProperties.Name` bound to that **same current Text** via `RelativeSource Self`, including the honest pre-refresh placeholder; and (3) `AutomationProperties.HelpText` with the same source boundary. Exactly **three WPF attributes**, one explanatory XAML comment and formatting of that one existing `TextBlock`; no additional element, focus stop, timer, time conversion, data binding to a new producer, event handler, command, navigation, layout, theme, shared API, capture, telemetry, security or preference change. The original `Text`, `x:Name`, foreground, footer geometry and writer remain unchanged. The source commit `7fb25b4e70bc88e725b01a7a29d75aab28e56b74` is a direct child of starting HEAD `fd9a518e37b5ee1e9bffc4c30f8ce638bc0fe459` and changes only `Carthago/Views/MainWindow.xaml`.

### Start/end static divergence and publication guard

**Start:** compare prior GA UI-58 publication `710174ccfaead3a9eaa642ce705a622ad8e3f4f4` with LIVE `fd9a518e37b5ee1e9bffc4c30f8ce638bc0fe459`: one disjoint protocol-documentation reconciliation; no overlapping UI paths. Static inspection of original WPF partials/consumers confirms `FooterUtcText` is written by `UpdateMonitoringHeader`, not a packet/event timestamp producer. No changed handler, namescope, API, responsive breakpoints, theme, local PPS, Cisco/WebView2, privacy/trust/capture boundaries, or approved-reference interpretation.

**End/publication gate:** immediately before publication re-read LIVE branch HEAD and compare any intervening detection/protocol/UI changes, private source/docs blobs and parentage, exact changed paths, WPF partials/consumers, naming, provenance, privacy and approved reference. Publish the **complete private source+ledger chain only** via **one non-forced atomic GitHub `update_ref` with exact `expected_sha` lease** on the existing branch. If moved, reconcile disjoint independent changes onto fresh HEAD using new private commits and a fresh lease; STOP on overlap, conflict or missing guarantee. No partial publication, branch/PR, force push, history rewrite, independent-stream or automation changes.

**Residual risks:** Windows compilation and XAML parsing, dynamic self-`Text` automation-name binding, UI Automation TextBlock exposure, screen-reader browse-mode discovery (the clock remains non-focusable), hover tooltip timing/placement, stale sample between refreshes, high contrast, 125–200% DPI and 1440/1100/1099/1024/1023/640px screenshots remain **UNVERIFIED**. Tooltip/HelpText metadata is not proof of screen-reader behavior or clock accuracy. No fabricated capture-health, synchronization, telemetry or evidence claim is added.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Before first header refresh, footer shows `UTC --:--:--` and the accessible Name mirrors that placeholder, not a fabricated current time.
2. After a header refresh, `FooterUtcText` displays the current `UTC HH:mm:ss` sample and its accessible Name mirrors the actual displayed string.
3. Hover the UTC footer: tooltip explains system-clock sampling at last monitoring-header refresh, omitted date, and non-event/non-synchronization scope.
4. Inspect screen-reader browse mode and UI Automation Name/HelpText on the existing non-focusable TextBlock; no claim that keyboard Tab alone reaches it.
5. With monitoring paused/offline/error/degraded, footer time remains a clock sample, not evidence of active capture or successful detection.
6. Compare capture-status and incident/detection event timestamps: the UTC footer must not be confused with capture time, event delivery, incident update or anomaly creation.
7. Confirm original monitoring-header timer/events and `DateTime.UtcNow:HH:mm:ss` writer unchanged; no extra polling, conversion or UI thread work introduced.
8. Inspect Wide 1440, Standard 1100, Compact 1099/1024, below-1024 1023/640px, 125–200% DPI and high contrast for unchanged footer geometry, readable tooltip and screen-reader discoverability.
9. Verify unchanged operational KPIs, local PPS ScottPlot ten-sample/120-point bounds, prioritized incidents, investigation, Live Events 80/500, visual-only unavailable CLI and Cisco/WebView2/ScottPlot/capture/privacy/trust.
10. Confirm exactly two authorized paths in the complete candidate, no demo screenshot data and no engine/model/service/detection/protocol/shared API/security/test/benchmark/workflow/runner/automation edits.

**Open quality GAs:** pinned-SHA Windows WPF compilation and real tooltip, accessibility, high-contrast, DPI and responsive inspection **only after owner says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-60:** inspect fresh LIVE HEAD, approved image, ledger and WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–59.

**References:** [WPF AutomationProperties.Name](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.name); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF RelativeSource Self](https://learn.microsoft.com/dotnet/desktop/wpf/advanced/relativesource-markupextension).

## GA UI-60 — Dynamic local capture-state context in the global footer

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `badbe2cca9cefa72f117be1f6f86b1aa800dfa29`. Previous UI-59 source `7fb25b4e70bc88e725b01a7a29d75aab28e56b74`, documentation/publication `7a6152e013022dd72df396a62b8c6b63cab008b5`. Intervening independent protocol commit `badbe2cca9cefa72f117be1f6f86b1aa800dfa29` reconciled GA P0411–P0420 Bluetooth media boundaries in `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md` and `docs/protocols/PROTOCOL_GA_P0411-P0420.md`; no UI overlap. **Exact UI source commit:** `aae4285f77aa513722cfd7bd70aa43f4d3b86fd2` (direct child of starting HEAD). **UI XAML blob:** `de7bb10fe7a87e3af5b60b0d49336ee1efc88f59`. **Authorized changed paths only:** `Carthago/Views/MainWindow.xaml` and this `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. No tests authored or executed; no dotnet build/test, xUnit, replay, holdout, CI, GitHub Actions, runners, benchmark, production capture or running-WPF screenshots.

### Approved reference, provenance and non-duplication

Resolved and **visually inspected** exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928). Its navy/graphite/cyan/teal, restrained severity, left navigation, operational KPIs, prioritized incidents, investigation and dense local event presentation are visual guidance only. Screenshot IPs, Mbps traces, timestamps, rule IDs, confidence, sensors/coverage and CLI output are **DEMO ONLY**, not Carthago observations. Existing local PPS ScottPlot (10-sample average, bounded 120-point history), read-only local Live Events (80 displayed / 500 retained), and explicitly **UNAVAILABLE** visual-only CLI remain unchanged. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024; Cisco/WebView2/ScottPlot untouched.

Audited live branch/recent commits, design ledger UI-01–59, `MainWindow.xaml`, `MainWindow.Dashboard.cs`, `MainWindow.Core.cs`, `MainWindow.xaml.cs`, responsive partials and `Theme.xaml`. `UpdateMonitoringHeader` is the existing writer of `FooterTelemetryStateText.Text` and `Foreground`: `Monitoring` → `On`, `Paused` → `Paused`, `Error` → `Error`, `Degraded` → `Degraded`, otherwise `Offline`; initial XAML value is `Unknown`. The status projection depends on existing capture error, local flow state/drops, sink presence and capture control state. `On` is **not proof of received packets**, verified source health, or system/database/sensor health. Refresh occurs via the existing monitoring-header timer and state/event callbacks, not a new source or guaranteed immediate UIA announcement.

GA UI-24 previously removed false global-health/database claims, bound the footer dot to the state color and added **static** contextual help to the left-hand `Local capture state` group. GA UI-59 added dynamic UTC-clock metadata. Neither gave the **right-hand changing capture-state value** its own dynamic accessible Name and source-specific hover/HelpText. UI-60 addresses only that separate state-value gap; it does not repeat UI-24's footer correction or UI-59's time semantics.

### One minimal UI-owned improvement

On the **existing** `FooterTelemetryStateText` only, retain its `x:Name`, `Unknown` placeholder, `Foreground`, `Margin`, current writer and all state/color mappings. Add a hover `ToolTip` that explains the existing five displayed states, initial Unknown, monitoring-header sampling and the absence of packet-flow/global-health proof; bind `AutomationProperties.Name` to the current `Text` through `RelativeSource Self`; and add `AutomationProperties.HelpText` stating the same narrow local-capture scope. One explanatory XAML comment, **three new WPF attributes**, formatting of the existing single TextBlock; no new control, focus stop, data producer, timer, converter, handler, route, command, preferences write, telemetry, capture behavior or API.

The existing footer left indicator, `Capture:` label, status colors, UTC sample, geometry, theme and responsive behavior remain unchanged. The source-only change is not evidence of successful WPF parsing, accessible announcement, screen-reader discovery, packet capture, detection quality or health verification.

### Start/end static divergence and publication guard

**Start:** exact remote HEAD `badbe2cca9cefa72f117be1f6f86b1aa800dfa29` is one disjoint protocol-documentation commit after UI-59 publication. The original WPF footer consumer `UpdateMonitoringHeader`, core capture callbacks, XAML name, theme, responsive partials, approved visual reference and earlier GA UI-24/UI-59 changes were inspected. No shared contract is needed. The prepared source commit is a direct child of starting HEAD and the source-only diff is one authorized XAML file.

**End/publication:** re-read LIVE remote HEAD immediately before publication; compare any intervening detection/protocol/UI changes with the complete private source/docs chain and ownership. Reconcile disjoint concurrent work onto fresh HEAD with new private commits and a fresh expected-SHA lease if needed; STOP on conflict or missing atomicity. Publish both commits together via **one non-forced atomic GitHub `update_ref` using exact `expected_sha`** on the existing branch; never partially publish or overwrite independent work. Reinspect final changed paths, WPF partials/consumers, names, privacy/trust/capture boundaries, provenance and approved-reference fidelity. All runtime claims remain **UNVERIFIED**.

**Residual risks:** Windows XAML parsing/compilation; dynamic UI Automation Name updates and screen-reader browse-mode discovery on a non-focusable TextBlock; hover placement; repeated state refresh; potential confusion between `On` and actual packet reception; contrast/high contrast; 125–200% DPI; and narrow-window footer clipping remain unverified. No keyboard Tab stop was added and no accessible announcement guarantee is claimed.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Before the first monitoring-header refresh, the right footer value and its accessible Name both read `Unknown`, without claiming capture is running.
2. In the existing Monitoring projection, the value and accessible Name both read `On`; the tooltip explicitly does not equate this with received packets or verified source health.
3. In Paused, Degraded, Error and Offline projections, each value and accessible Name follow the original `UpdateMonitoringHeader` mapping with no invented states.
4. Hover the state value: tooltip explains local capture-state provenance, five states, initial Unknown and no system/database/sensor-health verdict.
5. Inspect UI Automation Name and HelpText with screen-reader browse mode; do not assume keyboard-only Tab discoverability for the non-focusable TextBlock.
6. Confirm the left footer indicator still follows the original state foreground, and the existing `Local capture state` group and `Capture:` label are unchanged.
7. Confirm the header `CaptureStatusText`, `MonitoringStatusBadge`, capture toggle and source-health/flow diagnostic producers remain untouched; no additional polling or event handler.
8. Inspect 1440/1100/1099/1024/1023/640px, 125–200% DPI and high contrast for legible value/tooltip, preserved footer geometry and unchanged focus order.
9. Verify no change to operational KPIs, local PPS ScottPlot 10-sample/120-point bounds, incidents, investigation, read-only Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot or capture/privacy/trust boundaries.
10. Confirm complete candidate changes only the two authorized UI/design-doc paths, preserves intervening independent protocol/detection work, adds no screenshot demo values, and executes zero tests/builds/replays/CI/runners/capture.

**Open quality GAs:** pinned-SHA Windows WPF compilation and actual tooltip, UI Automation/screen-reader, keyboard, high-contrast, DPI and responsive inspection **only after owner says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-61:** inspect fresh LIVE HEAD, approved image, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–60.

**References:** [WPF AutomationProperties.Name](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.name); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF RelativeSource Self](https://learn.microsoft.com/dotnet/desktop/wpf/advanced/relativesource-markupextension).

## GA UI-61 — Source-accurate local PPS chart capture-status context

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `3528b93902d79900d252fda1940b3e121564637f`. Prior GA UI-60 source `aae4285f77aa513722cfd7bd70aa43f4d3b86fd2`, documentation/publication `b2f80001442922b40008321a9d4e32eda0e535d7`. Two intervening independent protocol commits, `04790805c3d2741979716882b43e25cd273017e1` and `3528b93902d79900d252fda1940b3e121564637f`, added GA P0421–P0430 distcc-prefix protocol source/tests/docs and corrected its authored-invocation count. They are disjoint and remain untouched. **Exact UI source commit:** `2900c46b9f38b1d9cb85004bf25c500c03333fae` (direct child of starting HEAD). **UI XAML blob:** `69994223314118c887339f276add57cd304c50fe`. **Owned paths only:** `Carthago/Views/MainWindow.xaml` and this `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Tests authored: 0; executed: 0.** No dotnet build/test, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, production capture or running-WPF screenshot.

### Approved reference, original consumers and non-duplication

Resolved and **visually inspected** exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928). Preserve navy/graphite/cyan/teal, restrained severity, left navigation, operational KPIs, local PPS ScottPlot (10-sample moving average, bounded 120-point history), prioritized incidents, investigation, read-only Live Events (80 displayed / 500 retained), and explicitly **UNAVAILABLE** visual-only CLI. Wide >=1440, Standard 1100–1439, Compact 1024–1099, graceful below 1024, Cisco/WebView2/ScottPlot and privacy/capture boundaries remain unchanged. Reference IPs, Mbps lines, counts, timestamps, rule IDs, confidence and CLI output are **DEMO ONLY**, not observations.

Inspected LIVE ref and recent commits, ledger through UI-60, `MainWindow.xaml`, `MainWindow.xaml.cs`, `MainWindow.Core.cs`, `MainWindow.Dashboard.cs`, `MainWindow.Plots.cs`, `MainWindow.Navigation.cs`, `MainWindow.Responsive.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.DashboardEvents.cs` and `Theme.xaml`. The **PPS chart-header** capture label (not the footer state) is the existing unnamed TextBlock whose `Text` binds to `CaptureStatusText.Text` and whose foreground binds to `MonitoringStatusBadge.BorderBrush`. `UpdateMonitoringHeader` sets `CaptureStatusText.Text` to `MONITORING`, `PAUSED`, `DEGRADED`, `ERROR` or `OFFLINE` based on local capture/error/flow/sink state. Its XAML initial source is `Paused`; the label inherits that value before header refresh. `MainWindow.Plots.cs` `RenderTraffic` displays local PPS timer samples, optional ten-sample average and text summary; zero timer samples may occur without active capture. This is not global throughput, authenticated packet reception or sensor health.

GA UI-60 addressed the **right-hand global footer** value `FooterTelemetryStateText`, which maps Monitoring to `On`. GA UI-61 addresses the **separate PPS chart-header label**, whose actual text remains the uppercase monitoring-header projection. Earlier chart GAs covered chart labels, waiting state, source warnings and summary but did not add the chart-header capture-label's own current-value UI Automation Name or hover provenance. This is one distinct chart-context improvement, not a duplicate footer change.

### One cohesive UI-owned improvement

On the existing PPS chart-header status TextBlock only, add (1) a hover `ToolTip` explaining the five local capture/flow states, no packet-flow proof and timer-generated zero possibility; (2) `AutomationProperties.Name` bound to the **same displayed Text** through `RelativeSource Self`; and (3) static `AutomationProperties.HelpText` describing local PPS context rather than global traffic or verified sensor health. One explanatory XAML comment, **three added WPF attributes**, no new control or focus stop. Preserve the original `Text` and foreground `ElementName` bindings, font, geometry, status dot, producer, chart summary, chart renderer, plot, navigation, commands, theme and responsive repositioning below 1024px. No engine/model/service, protocol/detection, telemetry, capture, trust/privacy, shared API, test, benchmark, workflow, runner or automation change.

### Start/end static divergence and publication guard

**Start:** LIVE HEAD `3528b93902d79900d252fda1940b3e121564637f` is two disjoint protocol commits ahead of UI-60 publication `b2f80001442922b40008321a9d4e32eda0e535d7`; their four changed paths are outside UI ownership. The original WPF source/partials and chart status consumer, chart renderer, theme, names, responsive breakpoints, privacy boundaries and approved reference were inspected. Prepared source commit is a direct child of LIVE starting HEAD; its single changed path is the authorized XAML.

**End/publication gate:** immediately before publication re-read LIVE remote HEAD, compare concurrent detection/protocol/UI changes with the full private source/docs chain, and confirm exact source/docs blobs, parentage, changed paths, WPF consumers/APIs, naming, provenance, privacy and reference fidelity. Publish **both** private commits together through **one non-forced atomic GitHub `update_ref` with exact `expected_sha` lease** on the existing branch. If moved, reconcile disjoint work onto fresh HEAD with new private commits and fresh lease; STOP on overlap, conflict or missing atomicity. No partial publication, new branch/PR, force push or history rewrite.

**Residual risks:** Windows XAML parsing/compilation, UI Automation Name self-binding and updates, screen-reader browse-mode discoverability (status TextBlock is non-focusable), tooltip hover timing, repeated status refresh, ambiguous Monitoring versus packet reception, high contrast, 125–200% DPI and 1440/1100/1099/1024/1023/640px presentation remain **UNVERIFIED**. Metadata does not establish screen-reader announcements or capture health.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Before monitoring-header refresh, chart label and accessible Name reflect the original `Paused` source text; no fabricated Monitoring or packet-flow claim.
2. After header refresh, chart status and accessible Name mirror `MONITORING`, `PAUSED`, `DEGRADED`, `ERROR` or `OFFLINE` from the original producer without changing the state calculation.
3. Hover the chart status label: tooltip explains the local capture/flow projection and explicitly rejects packet-flow or sensor-health proof.
4. Inspect UI Automation Name/HelpText and screen-reader browse mode; do not assume keyboard Tab can focus the unchanged non-focusable TextBlock.
5. Confirm chart status dot and label retain the original `MonitoringStatusBadge.BorderBrush` binding, including degraded/error/paused/offline color behavior.
6. Confirm `RenderTraffic` still uses local PPS timer samples, ten-sample average and bounded 120-point history; zero samples remain possible without capture.
7. Confirm global footer `On` projection and UTC clock, chart text summary, waiting overlay and capture-state producer remain untouched.
8. Inspect 1440/1100/1099/1024/1023/640px, 125–200% DPI and high contrast for unchanged chart-header geometry, below-1024 repositioning, tooltip legibility and focus order.
9. Verify unchanged operational KPIs, incident queue/investigation, read-only Live Events 80/500, unavailable visual-only CLI, Cisco/WebView2/ScottPlot and privacy/trust/capture boundaries.
10. Confirm exactly two authorized paths in complete source/docs candidate, all independent protocol/detection changes preserved, no screenshot demo data and **zero** builds/tests/replays/CI/runners/capture.

**Open quality GAs:** pinned-SHA Windows WPF compilation and actual tooltip/UI Automation/screen-reader/high-contrast/DPI/responsive inspection **only after owner says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-62:** inspect fresh LIVE HEAD, approved image, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–61.

**References:** [WPF AutomationProperties.Name](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.name); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF RelativeSource Self](https://learn.microsoft.com/dotnet/desktop/wpf/advanced/relativesource-markupextension).

## GA UI-62 — Accessible anomaly-presentation preference in the command header

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `bf567c3f02857dbba4b9e276fdb93cf6defab22c`. Prior GA UI-61 source `2900c46b9f38b1d9cb85004bf25c500c03333fae`, documentation/publication `788b1dc037ce6143abf89482ec0adb8ed91e75fc`. **Exact GA UI-62 UI source SHA:** `b3c6ef1773dba47dfc17c9009030f8da85241019` (direct child of starting LIVE HEAD). Owned files: `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; executed: 0.** No build, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, production capture or running-WPF screenshot.

### Approved visual reference and original consumers

Resolved and **visually inspected** the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1672×941). Preserve navy/graphite/cyan/teal, restrained severity, left navigation, operational KPIs, local PPS ScottPlot (10-sample moving average, bounded 120-point history), prioritized incidents, investigation, read-only Live Events (80 displayed/500 retained), explicitly **UNAVAILABLE** visual-only CLI, Cisco/WebView2/ScottPlot, and breakpoints Wide >=1440, Standard 1100–1439, Compact 1024–1099, graceful below 1024. Reference IPs, metrics, rule IDs, timestamps, confidence, Mbps lines and terminal text are **DEMO ONLY**, not Carthago telemetry or capture-health evidence.

Audited LIVE ref and recent commits, ledger through UI-61, `MainWindow.xaml`, `MainWindow.xaml.cs`, `MainWindow.Dashboard.cs`, `MainWindow.Core.cs`, `MainWindow.Settings.cs`, `MainWindow.Responsive.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.Navigation.cs`, `MainWindow.Plots.cs`, `Theme.xaml`, `AppPreferences.cs` and `PreferencesService.cs` read-only. The existing header `AnomalyModeText` starts as `Anomalies only`; `ApplyAnomalyPreferenceState` and `UpdateMonitoringHeader` set it to **Anomalies only** or **Expanded telemetry** from the existing `ShowAnomaliesOnly` preference. The existing `AnomaliesOnlyToggle_Changed` writes that preference through `PreferencesService.Update`; `MainWindow.Settings.cs` also writes it when settings are saved. The checkbox remains the original focusable control; the badge remains non-focusable. Neither badge is evidence of capture, sensor health, or verified detection. Prior UI-02 covered truthful **capture** status and the overview title; UI-31 covered capture-source selection; UI-35 covered last analysis; UI-59–61 covered footer/chart status. None added dynamic accessible preference context to this separate anomaly-mode badge and toggle pair.

### One cohesive UI-owned improvement

On the existing header `AnomalyModeText`, add a source-accurate hover `ToolTip`, `AutomationProperties.Name` bound to its **current displayed Text** via `RelativeSource Self`, and `AutomationProperties.HelpText` clarifying that the value is the existing dashboard presentation preference, not capture/detection health. On the existing `AnomaliesOnlyToggle`, add a truthful hover `ToolTip`, `ToolTipService.ShowsToolTipOnKeyboardFocus="True"`, and `AutomationProperties.HelpText` explaining that the control changes the existing `ShowAnomaliesOnly` preference and does not start/stop capture. One explanatory XAML comment and **six WPF attributes**; no new control, command, focus stop, preference writer, API, binding converter or data producer. Keep existing text, caption, handlers, checkbox state, original badge background and foreground, font, geometry, navigation, theme and responsive positioning unchanged. No engine/model/service, detection/protocol, telemetry/capture/trust/privacy, tests, benchmarks, workflows, runners, project, shared API or automation edits.

### Start/end static divergence and publication guard

**Start:** compare prior UI-61 publication `788b1dc037ce6143abf89482ec0adb8ed91e75fc` to LIVE `bf567c3f02857dbba4b9e276fdb93cf6defab22c`: one independent P0431–P0440 protocol-documentation reconciliation, changing only `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md` and `docs/protocols/PROTOCOL_GA_P0431-P0440.md`. No overlap with UI-owned files. Source commit `b3c6ef1773dba47dfc17c9009030f8da85241019` has exactly one authorized changed path, `Carthago/Views/MainWindow.xaml`, and retains the original checkbox event names and `AnomalyModeText` producer. Reference, partial consumers, preferences, names, layout, privacy and capture boundaries inspected statically.

**End/publication gate:** inspect the complete source/docs commit chain and its two changed blobs/paths; immediately before publication re-read LIVE remote HEAD and compare all concurrent detection/protocol/UI changes. Publish both prepared private commits **together**, once, through a non-forced atomic GitHub `update_ref` with exact `expected_sha` lease on the **same** branch. If HEAD moves, reconcile disjoint changes into new private commits and obtain a fresh lease; STOP on overlap, conflict or missing guarantee. Never publish partially or overwrite independent work.

**Residual risks:** Windows WPF compilation/XAML parsing, dynamic `AutomationProperties.Name` binding refresh, checkbox keyboard-focus tooltip behavior, screen-reader interpretation of badge versus checkbox, badge non-focusability, tooltip readability, high contrast, 125–200% DPI, and 1440/1100/1099/1024/1023/640px rendering remain **UNVERIFIED**. Tooltip and UI Automation metadata do not establish actual keyboard-only access to the non-focusable badge or detection correctness.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Initial header badge remains `Anomalies only` until existing preference synchronization; accessible Name reflects displayed text rather than an invented capture status.
2. Preference enabled: original badge text and accessible Name show `Anomalies only`, without changing badge typography, color, placement or source.
3. Preference disabled: original badge text and accessible Name show `Expanded telemetry`; no false packet-flow, detection-coverage or sensor-health claim.
4. Hover the badge: tooltip explains dashboard presentation preference and explicitly distinguishes it from capture/detection health.
5. Keyboard-focus the existing checkbox: tooltip describes the original preference action; focus order, checked/unchecked handlers and control caption remain unchanged.
6. Toggle and save settings: the original `PreferencesService.Update` and `ApplyAnomalyPreferenceState` synchronization remain the only writers/readers; no new preference or capture side effect.
7. Inspect UI Automation Name/HelpText and screen-reader browse mode for both states; do not assume the non-focusable badge becomes a Tab stop.
8. Inspect Wide 1440px, Standard 1100px, Compact 1099/1024px and below-1024 1023/640px, 125–200% DPI and high contrast for unchanged header wrapping, badge alignment and tooltip visibility.
9. Confirm original operational KPIs, local PPS/ten-sample average/120-point history, prioritized incidents, investigation, Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot and capture/privacy/trust remain untouched.
10. Confirm exactly two authorized paths across source/docs candidate, concurrent protocol/detection work preserved, no demo telemetry introduced, and **zero** builds/tests/replays/CI/runners/capture.

**Open quality GAs:** pinned-SHA Windows WPF compilation and actual UI Automation/tooltip/screen-reader/high-contrast/DPI/responsive inspection **only after owner says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-63:** inspect fresh LIVE HEAD, exact approved image, ledger and WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–62.

**References:** [WPF AutomationProperties.Name](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.name); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF ToolTipService.ShowsToolTipOnKeyboardFocus](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice.showstooltiponkeyboardfocus); [WPF RelativeSource Self](https://learn.microsoft.com/dotnet/desktop/wpf/advanced/relativesource-markupextension).

## GA UI-63 — Keyboard and assistive guidance for dashboard-section settings

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `8cc7cfcd93cf4ff1535cccbc9f8007f496859771`. Prior GA UI-62 source `b3c6ef1773dba47dfc17c9009030f8da85241019`, documentation/publication `bc2afc7fa895b19e30deedeed000c273f419b443`. **Exact GA UI-63 source SHA:** `37e44c252bfea507c41edb07cad1cb0fa4f7b6e1` (direct child of starting LIVE HEAD). Owned paths: `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; executed: 0.** No build, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, production capture or running-WPF screenshot.

### Approved reference, original controls and consumers

Resolved and **visually inspected** exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1672×941). Preserve its navy/graphite/cyan/teal palette, restrained severity, left navigation, operational KPIs, prioritized incidents, investigation and read-only Live Events (80 displayed / 500 retained). The implementation remains local PPS ScottPlot with optional 10-sample average and bounded 120-point history; visual-only CLI is explicitly **UNAVAILABLE**. Preserve Cisco/WebView2/ScottPlot, privacy and capture boundaries, and Wide >=1440 / Standard 1100–1439 / Compact 1024–1099 / graceful below 1024. Reference IPs, Mbps lines, metrics, timestamps, rule IDs, confidence and terminal text are **DEMO ONLY**, not measured telemetry or verified capture health.

Audited LIVE remote ref and recent commits, ledger through UI-62, `MainWindow.xaml`, `MainWindow.Settings.cs`, `MainWindow.Dashboard.cs`, `MainWindow.xaml.cs`, `MainWindow.Navigation.cs`, `MainWindow.Responsive.cs`, `MainWindow.DashboardResponsive.cs`, and `Theme.xaml` read-only. In the existing visible System Settings **Dashboard & Sections** `UniformGrid`, twelve named `DashboardShow*Check` checkboxes already have distinct hover ToolTips and existing `Checked`/`Unchecked` event handlers. `MainWindow.Settings.cs` `DashboardSectionToggle_Changed` writes the current dashboard-section preferences via `PreferencesService.Update`; `ApplyDashboardSectionSettingsFromUi` reads the original checkbox states. The Developer demo section preference remains gated by `_demoModeEnabled`. These are presentation/section-visibility settings, not packet capture or proof of detection. GA UI-62 covered the separate command-header `AnomaliesOnlyToggle`, **not** these twelve System Settings checkboxes.

### One cohesive UI-owned change

For the **twelve existing dashboard-section visibility checkboxes only** (Incidents, Anomalies, Statistics, Timeline, Baseline learning, ML-assisted scoring, Recommended actions, Raw/Advanced shortcuts, Cisco, External delivery, Forensics shortcuts, Developer demo section), add `ToolTipService.ShowsToolTipOnKeyboardFocus="True"` and bind `AutomationProperties.HelpText` to each control's **existing ToolTip** using `RelativeSource Self`. One XAML provenance comment and **24 added WPF attributes**; 25 added lines and zero deletions in source. This exposes existing source-authored descriptions to keyboard focus and UI Automation without inventing descriptions or changing the checked state, captions, tooltip content, handlers, preference writer, focus order, dimensions, styles, responsive layout or availability. No new controls, commands, telemetry, capture, detection/protocol logic, trust/privacy change, services, shared APIs, tests, benchmarks, workflows, runners or automations.

### Start/end static divergence and publication guard

**Start:** prior UI-62 publication `bc2afc7fa895b19e30deedeed000c273f419b443` to LIVE `8cc7cfcd93cf4ff1535cccbc9f8007f496859771` is **one independent P0441–P0450 OMAPI protocol commit**, changing only `Carthago.Tests/ProtocolIntelligence/OmapiStartupInspectorTests.cs`, `Carthago/Services/ProtocolIntelligence/OmapiStartupInspector.cs`, `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md`, and `docs/protocols/PROTOCOL_GA_P0441-P0450.md`. No overlap with owned paths. GA UI-63 source commit `37e44c252bfea507c41edb07cad1cb0fa4f7b6e1` changes only `Carthago/Views/MainWindow.xaml` (25 additions, zero deletions). Static source review compared all twelve original checkboxes, their event names and tooltip values; remaining XAML was unchanged. Theme, WPF partial consumers, naming, reference fidelity, capture/privacy boundaries and independent streams were inspected without edits.

**End/publication gate:** inspect both private source/docs commits and exact changed paths/blobs; immediately before publication re-read LIVE remote HEAD and compare concurrent detection/protocol/UI changes. Publish **both** private commits together via **one non-forced atomic GitHub `update_ref` with exact `expected_sha` lease** on the same branch. If HEAD moved, reconcile disjoint paths into a fresh private chain and fresh lease; STOP on overlap, conflict or missing guarantee. Never partially publish, create branches/PRs or overwrite independent work.

**Residual risks:** Windows XAML parsing/compilation, `AutomationProperties.HelpText` self-binding to `ToolTip`, keyboard-focus tooltip behavior, checkbox tab sequence, screen-reader announcement, high contrast, 125–200% DPI, 1440/1100/1099/1024/1023/640px layouts, disabled/hidden demo section behavior and live preference synchronization remain **UNVERIFIED**. Existing tooltip text may not be announced identically by every accessibility client. No keyboard-focus or screen-reader success claim is made.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Tab through the twelve dashboard-section checkboxes in System Settings: original captions and focus order remain, and existing guidance appears on keyboard focus where supported.
2. Inspect each checkbox's UI Automation Name, check state and HelpText: HelpText matches that checkbox's original tooltip, without fabricated metrics or detection claims.
3. Toggle Incidents, Anomalies, Statistics and Timeline: original `DashboardSectionToggle_Changed` and preference projection remain the only writers and readers.
4. Toggle Baseline learning, ML-assisted scoring and Recommended actions: descriptions remain about optional dashboard presentation, not verified detection or sensor health.
5. Toggle Raw/Advanced, Forensics, Cisco and External delivery: existing advanced navigation and data paths remain available as before, with no new capture, export or CLI action.
6. Inspect Developer demo section checkbox with demo mode disabled/enabled: original `_demoModeEnabled` preference gate and availability remain unchanged.
7. Inspect checkbox hover and keyboard focus, UI Automation HelpText, screen-reader output and tooltip timing; do not assume every assistive client announces ToolTips.
8. Inspect Wide 1440px, Standard 1100px, Compact 1099/1024px and below-1024 1023/640px, high contrast and 125–200% DPI for original two-column settings layout, legibility and focus visuals.
9. Confirm unchanged operational KPIs, local PPS/10-sample average/120-point history, prioritized incidents/investigation, read-only Live Events 80/500, unavailable visual-only CLI, Cisco/WebView2/ScottPlot and capture/privacy/trust boundaries.
10. Confirm exact two authorized paths across source/docs, independent P0441–P0450 and any concurrent detection/protocol commits preserved, no screenshot demo data added, and **zero** builds/tests/replays/CI/runners/capture.

**Open quality GAs:** pinned-SHA Windows WPF compilation and actual keyboard-focus tooltip, UI Automation, screen-reader, high-contrast, DPI and responsive inspection **only after owner says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-64:** inspect fresh LIVE HEAD, exact approved image, ledger and WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–63.

**References:** [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF ToolTipService.ShowsToolTipOnKeyboardFocus](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice.showstooltiponkeyboardfocus); [WPF RelativeSource Self](https://learn.microsoft.com/dotnet/desktop/wpf/advanced/relativesource-markupextension).

## GA UI-64 — Accessible consequences for System Settings dashboard presets

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `b10b3d07f319d244d2da8c1486f61fc4163836c5`. Prior GA UI-63 source `37e44c252bfea507c41edb07cad1cb0fa4f7b6e1`, documentation/publication `2c0f349fde97f8e9b3cd3692167db2b755bff837`. **Exact GA UI-64 UI source SHA:** `36e144b8d6b58d49d783bba9492e03eaed5e824f` (direct child of starting LIVE HEAD). Owned paths: `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; executed: 0.** No build, xUnit, replay, holdout, CI, GitHub Actions, runner, benchmark, production capture or running-WPF screenshot.

### Approved reference and original consumers

Resolved and **visually inspected** the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1672×941). Retain navy/graphite/cyan/teal, restrained severity, left navigation, operational KPIs, prioritized incidents/investigation, read-only Live Events (80 displayed/500 retained), local PPS ScottPlot (10-sample average, bounded 120-point history), explicitly **UNAVAILABLE** visual-only CLI, Cisco/WebView2/ScottPlot, Wide >=1440 / Standard 1100–1439 / Compact 1024–1099 / graceful below 1024. All reference IPs, rule IDs, timestamps, metrics, confidence, Mbps lines and terminal text are **DEMO ONLY** and never source telemetry or verified capture health.

Read LIVE remote ref, recent commits, implementation ledger through UI-63, `MainWindow.xaml`, `MainWindow.xaml.cs`, `MainWindow.Dashboard.cs`, `MainWindow.Settings.cs`, `MainWindow.Core.cs`, `MainWindow.Navigation.cs`, `MainWindow.Responsive.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.Plots.cs`, `Views/Theme.xaml` and `App.xaml` read-only. In the visible System Settings **Recommended layouts** card, `DashboardPresetCombo` displays the existing `_dashboardAvailablePresets` items; selecting a preset alone does not call `PreferencesService.Update`. `DashboardApplyPreset_Click` passes the selected ID to `ApplyDashboardPreset` or falls back to `MinimalSecurityOverview` when no selection exists. `DashboardResetLayout_Click` writes `DashboardPresetService.CreateEmptyMinimal()` to the dashboard preferences. Both actions apply without a confirmation prompt. They change dashboard layout/section presentation preferences; neither handler deletes retained events/incidents nor starts/stops capture. GA UI-63 covered twelve *section visibility* checkboxes, not the distinct preset selector/apply/reset workflow.

### One cohesive UI-owned improvement

Add `x:Name="DashboardPresetsLabel"` to the **existing** visible Recommended layouts heading, and `AutomationProperties.LabeledBy` to its existing ComboBox. For the ComboBox, **Apply preset**, and **Reset dashboard**, add truthful hover `ToolTip`, `ToolTipService.ShowsToolTipOnKeyboardFocus="True"` and `AutomationProperties.HelpText` bound to each existing ToolTip via `RelativeSource Self`. Explain that selection is non-mutating, applying a preset **replaces** dashboard preferences (with a fallback when unselected), and resetting replaces them with an empty minimal dashboard. Both action buttons apply immediately without confirmation; none of these controls is a capture toggle or data-deletion command. One XAML provenance comment; **10 new WPF attributes** (ComboBox 4, each button 3), one name on an existing heading, and no new control, focus stop, handler, producer, API, preference write, theme, dimensions, keyboard order, or routing.

### Start/end static divergence and publication guard

**Start:** prior GA UI-63 publication `2c0f349fde97f8e9b3cd3692167db2b755bff837` to LIVE `b10b3d07f319d244d2da8c1486f61fc4163836c5` is **one independent GA P0451–P0460 ZEPv2 protocol commit**, touching only `Carthago.Tests/ProtocolIntelligence/ZepV2EnvelopeInspectorTests.cs`, `Carthago/Services/ProtocolIntelligence/ZepV2EnvelopeInspector.cs`, `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md`, `docs/protocols/PROTOCOL_GA_P0451-P0460.md`. No UI-owned path overlap. Source commit `36e144b8d6b58d49d783bba9492e03eaed5e824f` modifies only `Carthago/Views/MainWindow.xaml`; original `DashboardApplyPreset_Click` / `DashboardResetLayout_Click` handlers, bindings, `PreferencesService.Update`, `DashboardPresetService` consumers, naming, WPF partials, theme, responsive layout, privacy/capture boundaries and independent streams remain unchanged. The source diff is one focused 11-line net XAML addition.

**End/publication gate:** statically inspect the private source/docs commit chain, exact changed paths/blobs, and original consumers. Immediately before publication re-read LIVE remote HEAD and compare all concurrent detection/protocol/UI changes. Publish the **complete** candidate with exactly one non-forced atomic GitHub `update_ref` and matching `expected_sha` lease on the **same branch**. If HEAD moved, reconcile disjoint paths into new private commits and obtain a fresh lease; STOP on overlap/conflict or missing atomic guarantee. No partial publication, new branch, PR, force push, history rewrite or independent automation edit.

**Residual risks:** Windows WPF compilation/XAML parsing, `AutomationProperties.LabeledBy` target resolution, HelpText self-binding, ComboBox keyboard-focus tooltip and popup behavior, screen-reader announcements, high contrast, 125–200% DPI, 1440/1100/1099/1024/1023/640px settings-card layout, preference-write failures and any stale selected-preset state remain **UNVERIFIED**. Guidance does not add confirmation or rollback and does not establish actual assistive-technology behavior.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. In System Settings, Tab to preset ComboBox: existing visible heading remains unchanged and UI Automation exposes it as the selector label.
2. Hover or keyboard-focus the ComboBox: guidance distinguishes selecting a preset from applying it; changing selection alone does not write preferences.
3. Select a preset and activate **Apply preset**: original selected-ID handler and `DashboardPresetService.ApplyPreset` remain the only action path.
4. With no selected preset, activate **Apply preset**: original `MinimalSecurityOverview` fallback remains; tooltip does not imply a no-op.
5. Hover or keyboard-focus **Apply preset**: guidance communicates immediate replacement of dashboard layout/section preferences and absence of a confirmation prompt.
6. Hover or keyboard-focus **Reset dashboard**: guidance communicates immediate `CreateEmptyMinimal()` preference replacement, without claiming incident/event deletion or capture control.
7. Inspect UI Automation HelpText and screen-reader output on all three existing focusable controls; do not infer success from XAML metadata alone.
8. Inspect 1440/1100/1099/1024/1023/640px, high contrast, and 125–200% DPI for original preset card geometry, button order, focus visibility and tooltip readability.
9. Confirm unchanged operational KPIs, local PPS/10-sample average/120-point history, prioritized incidents/investigation, read-only Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot and privacy/trust/capture boundaries.
10. Confirm exactly two authorized source/docs paths, preserved concurrent protocol/detection changes, no demo telemetry, and **zero** builds/tests/replays/CI/runners/capture.

**Open quality GAs:** pinned-SHA Windows WPF compilation and actual tooltip, UI Automation, screen-reader, high-contrast, DPI and responsive inspection **only after owner says “now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-65:** inspect fresh LIVE HEAD, approved reference, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–64.

**References:** [WPF AutomationProperties.LabeledBy](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.labeledby); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF ToolTipService.ShowsToolTipOnKeyboardFocus](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice.showstooltiponkeyboardfocus); [WPF RelativeSource Self](https://learn.microsoft.com/dotnet/desktop/wpf/advanced/relativesource-markupextension).

## GA UI-65 — Accessible scope of sensitivity selection and global Settings actions

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `50e8493413148447d19e3bddcb0901e45e45829f`. Prior GA UI-64 UI source `36e144b8d6b58d49d783bba9492e03eaed5e824f`; prior docs/publication `042d3db820872d2dbce4f5b70060346b75054575`. **Exact GA UI-65 UI source SHA:** `1924cccb267eadde36bc34f27589aa3f89d7fc25`. Source blob: `67f2d59c4dd8675a9a0e9a9545b42735b74c7fa6`. Owned changed paths: `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; executed: 0.** No builds, XAML compilation, xUnit, replays, holdouts, CI, Actions, runners, benchmarks, production capture or running-app screenshots.

### Approved reference, start divergence and original consumers

Resolved and **visually inspected** exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1672×941). Preserve navy/graphite/cyan/teal, restrained severity, left navigation, operational KPIs, prioritized incidents/investigation, local PPS ScottPlot with optional 10-sample average and bounded 120-point history, read-only local Live Events (80 displayed / 500 retained), explicitly **UNAVAILABLE** visual-only CLI, Cisco/WebView2/ScottPlot and privacy/capture boundaries. Preserve Wide >=1440 / Standard 1100–1439 / Compact 1024–1099 / graceful below 1024. Screenshot IPs, metrics, rule IDs, timestamps, confidence, Mbps lines and terminal content are **DEMO ONLY** and not measured telemetry or proof of capture health.

At start, prior GA UI-64 publication `042d3db820872d2dbce4f5b70060346b75054575` to LIVE `50e8493413148447d19e3bddcb0901e45e45829f` contains independent protocol work only (P0461–P0470 ERSPAN Type II research/source/tests/docs), with no UI-owned overlap. Read the implementation ledger through UI-64, `MainWindow.xaml`, `MainWindow.Settings.cs`, `MainWindow.Core.cs`, `MainWindow.Dashboard.cs`, `MainWindow.xaml.cs`, Navigation, Plots, DashboardEvents, DashboardResponsive, Responsive, `Views/Theme.xaml` and the read-only `PreferencesService.cs` reset consumer. The existing `SensitivityCombo_SelectionChanged` is a no-op; sensitivity is persisted by `SaveSettings_Click` with capture auto-start, default BPF, WHOIS, reputation, anomaly presentation and dashboard section preferences. The Save handler calls `ApplyRuntimePreferences(..., applyActiveCaptureFilter: true)`, which may apply the default filter to active Npcap capture. `ResetSettings_Click` calls `PreferencesService.Reset()`, which replaces and persists **all** app preferences, then reapplies runtime preferences and may apply an active Npcap filter. Reset does not prompt for confirmation. This is separate from GA UI-63 section checkboxes and GA UI-64 dashboard preset controls.

### One cohesive UI-owned change

In the existing **Detection Sensitivity** settings card only, name the visible Sensitivity label `SettingsSensitivityLabel` and associate it with the existing ComboBox using `AutomationProperties.LabeledBy`. Add source-accurate hover/keyboard-focus ToolTips and UI Automation HelpText for that ComboBox and the existing Save and Reset buttons; give the two generic-caption buttons explicit accessible Names **Save settings** and **Reset all settings**. The guidance distinguishes selection-only from saving, discloses Save's multi-preference scope and runtime filter application, and discloses that Reset replaces **all** application preferences without a pre-confirmation. Exactly three existing focusable controls gain guidance; no new control, command, focus stop, layout, theme, capture operation, security setting, handler, service, API or persistence behavior. Original captions, selections, handlers, tab order and geometry remain unchanged.

### End static divergence and publication guard

Inspect the prepared private source/docs commit chain and exact changed paths/blobs. Immediately before publication, re-read LIVE remote HEAD and compare all concurrent changes against `50e8493413148447d19e3bddcb0901e45e45829f`; reconcile disjoint detection/protocol commits into a fresh private chain and lease, but STOP on overlapping UI paths, conflicts or missing expected-SHA guarantee. Publish complete source plus ledger via exactly **one non-forced atomic GitHub `update_ref`** with the matching `expected_sha` lease on this same branch. Never publish partially or alter independent detection/protocol work, automations or schedules. This is a **static source review only**, not proof of compilation, runtime accessibility or correct persistence.

**Residual risks:** WPF XAML parsing and compilation, `AutomationProperties.LabeledBy` target resolution, ToolTip self-binding to HelpText, ComboBox popup and focus behavior, accessible Name changes for the two buttons, screen-reader output, high contrast, 125–200% DPI, 1440/1100/1099/1024/1023/640px layouts, preference-write errors and active Npcap filter effects remain **UNVERIFIED**. Tooltips do not add a confirmation dialog or rollback. No claim that capture is healthy, telemetry is verified or accessibility behavior was observed.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. In Settings > Detection Sensitivity, tab to the existing ComboBox; the visible Sensitivity label remains unchanged and UI Automation resolves `LabeledBy`.
2. Select Relaxed/Balanced/Aggressive without Save; verify `SensitivityCombo_SelectionChanged` remains non-persisting.
3. Hover and keyboard-focus the ComboBox; inspect its ToolTip and HelpText without assuming every accessibility client announces them.
4. Focus Save; confirm its visible caption stays Save, accessible Name says Save settings, and guidance discloses the multi-preference write.
5. Activate Save with controlled preferences only after test authorization; inspect `PreferencesService.Update` and runtime filter application, including Npcap-active and inactive cases.
6. Focus Reset; confirm its visible caption stays Reset, accessible Name says Reset all settings, and guidance discloses global reset without pre-confirmation.
7. Activate Reset only after test authorization; inspect persisted defaults, UI projection and active Npcap filter behavior without assuming data deletion.
8. Inspect keyboard focus, ComboBox popup, high contrast, 125–200% DPI and 1440/1100/1099/1024/1023/640px layout for unchanged geometry and readable guidance.
9. Confirm unchanged local PPS/10-sample average/120-point history, prioritized incidents, read-only Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot, trust/privacy and capture boundaries.
10. Compare both commits and their blobs against the approved reference and concurrent protocol/detection changes; confirm only two authorized paths and **zero** builds/tests/replays/CI/runners/capture.

**Open quality GAs:** pinned-SHA Windows WPF compilation and live accessibility/visual verification only when owner says **“now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-66:** inspect fresh LIVE HEAD, approved reference, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–65.

**References:** [WPF AutomationProperties.LabeledBy](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.labeledby); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF ToolTipService.ShowsToolTipOnKeyboardFocus](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice.showstooltiponkeyboardfocus).

## GA UI-66 — Accessible default BPF filter scope and Save effects

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `39774f0cc12fbd04a764d5a1ea689becb498975c`. Prior GA UI-65 UI source `1924cccb267eadde36bc34f27589aa3f89d7fc25`; prior docs/publication `2de0c4921dccfe23d05e6cdbe55edafe46d405cd`. **Exact GA UI-66 UI source SHA:** `739eaaadea0348a3b8a333c6d6568a2336ca1195`. Source blob: `f67866dcaa5cff0a825c66825686eef408771ce6`. Authorized owned paths: `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; executed: 0.** No build, XAML compilation, xUnit, replay, holdout, CI, Actions, runner, benchmark, production capture or running-app screenshot.

### Approved design reference, initial divergence and original consumers

Resolved and **visually inspected** exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1672×941). Maintain navy/graphite/cyan/teal, restrained severity, left navigation, operational KPIs, prioritized incidents/investigation, local PPS ScottPlot with optional 10-sample average and bounded 120-point history, read-only local Live Events (80 displayed / 500 retained), and explicitly **UNAVAILABLE** visual-only CLI. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099, graceful below 1024. Screenshot IPs, metrics, rule IDs, timestamps, confidence, Mbps lines and terminal content are **DEMO ONLY**; none are measured telemetry, verified capture or sensor health.

Before source preparation, LIVE HEAD `39774f0cc12fbd04a764d5a1ea689becb498975c` was exactly one independent protocol commit beyond GA UI-65 publication: P0471–P0480 rexec/BEP14 LSD inspectors, tests and protocol docs; comparison found **no UI-owned path overlap**. Read `MainWindow.xaml`, `MainWindow.Settings.cs`, `MainWindow.Core.cs`, `MainWindow.xaml.cs`, `MainWindow.Navigation.cs`, `MainWindow.Responsive.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Plots.cs`, `Views/Theme.xaml` and read-only `Services/TrafficCaptureService.cs`. The existing `DefaultFilterText` is read by `SaveSettings_Click`: whitespace maps to null; otherwise the value is trimmed and persisted in `PreferencesService.Update` as `DefaultCaptureFilter`. The handler then calls `ApplyRuntimePreferences(..., applyActiveCaptureFilter: true)`, which updates the default and applies it to an active Npcap capture when the original source-selection/state conditions hold. `TrafficCaptureService.ApplyFilter` can stop, close, reopen and restart a running Npcap device while applying a filter; ETW is not a BPF target. Editing the TextBox alone has no write or capture effect. Save also persists other settings (covered separately by GA UI-65). The original `ToolTip` only gave a BPF syntax example.

### One cohesive UI-owned change

In **Settings > Enrichment & Capture**, name the existing visible **Default BPF Filter** label `SettingsDefaultBpfLabel` and associate it with the existing `DefaultFilterText` TextBox via `AutomationProperties.LabeledBy`. Replace its example-only tooltip with truthful guidance about Npcap-only BPF scope, editing versus Save, whitespace clearing the saved default, and possible brief restart of an active Npcap capture when Save reapplies the filter. Expose the same guidance on keyboard focus and through `AutomationProperties.HelpText` bound to the tooltip. Exactly **one existing focusable control** gains three accessibility attributes; no new control, focus stop, validation, API, handler, service, preference, capture action, layout, color, rule, telemetry or security change. Existing label text, TextBox name, width, value, handler paths and responsive geometry are unchanged.

### End static divergence and publication guard

Prepared private UI source commit `739eaaadea0348a3b8a333c6d6568a2336ca1195` and this documentation-only commit on its descendant tree; only the two authorized paths may differ from the starting HEAD. Immediately before publication, re-read LIVE remote HEAD and compare any concurrent detection/protocol commits with the starting HEAD. If disjoint, reconstruct the complete source/docs chain on the fresh HEAD and use a fresh expected-SHA lease; STOP on UI-owned overlap, conflict, missing lease guarantee or divergent ancestry. Publish **only complete source plus ledger** through **one non-forced atomic GitHub `update_ref`** with `expected_sha` on this same branch. Post-publication verify remote HEAD and changed paths/blobs. This is static source review only, not evidence of compilation or live accessibility.

**Residual risks:** WPF XAML parsing/compilation, `LabeledBy` resolution, TextBox keyboard-focus tooltip and screen-reader HelpText exposure, high-contrast readability, DPI 125–200%, widths 1440/1100/1099/1024/1023/640px, invalid BPF syntax, preference-write errors, and Npcap stop/reopen/restart or filter failures remain **UNVERIFIED**. Tooltip disclosure does not add validation, confirmation, rollback or capture safety guarantees. No verified packet flow, system health or detection claims.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. In Settings > Enrichment & Capture, keyboard-focus `DefaultFilterText`; UI Automation should associate the unchanged **Default BPF Filter** label via `LabeledBy`.
2. Hover and keyboard-focus the field; inspect complete tooltip visibility, wording and HelpText in WPF and at least one assistive-technology client.
3. Enter a BPF example such as `tcp or port 443` without Save; verify the current preference and capture filter are unchanged.
4. Enter only whitespace, then Save in a controlled authorized test; inspect the saved null default and original `SetDefaultFilter` behavior.
5. Save a valid BPF with Npcap capture inactive; inspect persisted preference and default filter without claiming live packet filtering.
6. Save with active Npcap capture under controlled conditions; observe original `ApplyFilter` stop/reopen/restart behavior and failure presentation.
7. Save with ETW selected; verify BPF is not presented as an ETW filter and the original conditional Npcap application remains unchanged.
8. Inspect field focus, text clipping, high contrast, 125–200% DPI and widths 1440/1100/1099/1024/1023/640px; ensure no layout/focus regression.
9. Confirm unchanged Cisco/WebView2/ScottPlot, local PPS/10-sample average/120-point history, incident prioritization/investigation, read-only Live Events 80/500, unavailable CLI, and privacy/capture/trust boundaries.
10. Compare source and docs commits and blobs with approved reference and concurrent independent changes; confirm exactly two authorized paths and **zero** builds/tests/replays/CI/runners/capture.

**Open quality GAs:** pinned-SHA Windows WPF compilation, keyboard/screen-reader/visual checks and capture-filter scenario tests only when the owner says **“now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-67:** inspect fresh LIVE HEAD, approved reference, ledger and WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–66.

**References:** [WPF AutomationProperties.LabeledBy](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.labeledby); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF ToolTipService.ShowsToolTipOnKeyboardFocus](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice.showstooltiponkeyboardfocus).

## GA UI-67 — Accessible scope of enrichment and capture preferences

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `5310cc0b0898579bb7d8a9f2d4545b09cb6305c4`. Prior GA UI-66 source `739eaaadea0348a3b8a333c6d6568a2336ca1195`; prior docs/publication `16a13365ef1c45234c751288a6e8ff181f1c8794`. **Exact GA UI-67 source SHA:** `cdb1608b2c6f0f7f901f90c152752b0f2f00e5d9`. Source blob: `d514aa395cc98e6cdc2e986670cf7c21d0003fcb`. Owned paths: `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; executed: 0.** No builds, XAML compilation, xUnit, replays, holdouts, CI, Actions, runners, benchmarks, production capture or running-app screenshots.

### Reference, provenance and initial static divergence

Resolved and **visually inspected** exact approved Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1672×941). Preserve navy/graphite/cyan/teal, restrained severity, left navigation, operational KPIs, prioritized incidents/investigation, local PPS ScottPlot (10-sample average and bounded 120-point history), read-only local Live Events (80 displayed / 500 retained), explicitly **UNAVAILABLE** visual-only CLI, and Cisco/WebView2/ScottPlot and privacy/capture boundaries. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024. Screenshot IPs, metrics, rule IDs, timestamps, confidence, Mbps lines and CLI text are **DEMO ONLY**; no fabricated telemetry or verified capture/sensor health.

The supplied GA UI-66 continuation instruction was stale: GA UI-66 had already been published at `16a13365ef1c45234c751288a6e8ff181f1c8794`; do not repeat it. At start LIVE `5310cc0b0898579bb7d8a9f2d4545b09cb6305c4` was exactly one independent P0481–P0490 protocol-documentation reconciliation beyond UI-66, modifying only `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md` and `docs/protocols/PROTOCOL_GA_P0481-P0490.md`; no UI-owned overlap. Read the ledger through UI-66, `MainWindow.xaml`, `MainWindow.Settings.cs`, `MainWindow.Core.cs`, `MainWindow.Dashboard.cs`, `MainWindow.xaml.cs`, Navigation, Responsive, DashboardResponsive, `Views/Theme.xaml` and read-only `Models/AppPreferences.cs` and `Services/TrafficCaptureService.cs`. The existing three Enrichment & Capture checkboxes are read by `SaveSettings_Click` and persisted through `PreferencesService.Update`; none has a direct Checked/Unchecked handler. `QueueAutoStartCaptureIfConfigured` attempts capture on a later launch only if source/Start-control conditions hold. The traffic enrichment consumer reads `EnableWhois` and `EnableReputation` for eligible public IPs; WHOIS and AbuseIPDB can involve external lookups, and reputation requires an API key. No checkbox click itself proves capture, lookup, credential validity or result.

### One cohesive UI-owned change

On existing `AutoStartCheck`, `EnableWhoisCheck` and `EnableRepCheck` only, add truthful hover and keyboard-focus tooltips and bind `AutomationProperties.HelpText` to each existing control's ToolTip. The three messages distinguish checkbox editing from **Save**; disclose conditional *next-launch* capture, public-IP external WHOIS/ASN/organization lookup, and public-IP external AbuseIPDB lookup plus API-key requirement. Each checkbox retains its original visible Content, accessible name derivation, IsChecked source, handlers (none added), persistence, focus order, geometry and theme. No extra controls, preferences, service calls, API, capture logic, network requests, telemetry, rules, privacy/trust controls or demo data were introduced. **Exactly 12 XAML additions and 3 XAML deletions** in the private source commit (the three self-closing control lines are expanded).

### End static divergence and publication guard

Private source commit `cdb1608b2c6f0f7f901f90c152752b0f2f00e5d9` is a direct child of `5310cc0b0898579bb7d8a9f2d4545b09cb6305c4`; its compare contains **only** `Carthago/Views/MainWindow.xaml`. This ledger update is the second private commit and must remain its descendant. Immediately before publication, re-read LIVE remote HEAD and compare concurrent detection/protocol changes. If disjoint, reconstruct both commits on the fresh HEAD with a fresh expected-SHA lease; STOP for overlapping UI-owned paths, conflicting content, non-fast-forward ancestry or missing lease guarantee. Publish **both commits together only**, via exactly one non-forced atomic GitHub `update_ref` with matching `expected_sha` on the same branch; never publish partially or touch independent streams/automations. Static source inspection is **not** proof of WPF compilation, actual tooltip focus, screen-reader announcements, external lookup behavior or successful preference persistence.

**Residual risks:** XAML parsing and compilation; WPF tooltip behavior on keyboard focus; UI Automation HelpText and assistive-technology announcements; high contrast, DPI 125–200%, widths 1440/1100/1099/1024/1023/640px; Save failures; conditional startup capture and external WHOIS/AbuseIPDB lookup failures; invalid/missing API key. No guarantee of packet flow, capture health, privacy effects beyond existing behavior or enrichment results.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Tab to **Start capture on launch**; verify original caption and state, tooltip and HelpText; checking alone does not initiate capture.
2. Save Auto-Start setting under authorized conditions and inspect persisted preference; only on a subsequent launch with a source and enabled Start control may startup capture be attempted.
3. Tab to **Resolve WHOIS / ASN / Org**; verify hover/keyboard tooltip and HelpText disclose eligible public-IP external lookups and no immediate request on click.
4. Save WHOIS preference under authorized conditions; inspect enrichment gating on eligible versus private/special IPs and failure behavior without assuming successful lookup.
5. Tab to **AbuseIPDB reputation lookups**; verify hover/keyboard tooltip and HelpText disclose external lookups and API-key requirement.
6. Save reputation preference under authorized conditions; inspect eligible-public-IP lookup gating with configured/missing key, and verify checking alone does not validate or query.
7. Inspect keyboard focus, UI Automation names/HelpText, screen-reader output, tooltip wrapping and high contrast without claiming success from static XAML.
8. Inspect 125–200% DPI and 1440/1100/1099/1024/1023/640px widths for original Enrichment & Capture geometry, label readability and focus order.
9. Confirm unchanged Cisco/WebView2/ScottPlot, local PPS/10-sample average/120-point history, prioritized incidents/investigation, read-only Live Events 80/500, unavailable CLI and privacy/capture/trust boundaries.
10. Verify final changed paths/blobs and concurrent protocol/detection ancestry; confirm exactly two owned files and **zero** builds/tests/replays/CI/runners/capture.

**Open quality GAs:** pinned-SHA Windows WPF compilation, live tooltip/keyboard/UI Automation/visual review, and controlled capture/enrichment scenarios only after owner says **“now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-68:** inspect fresh LIVE HEAD, approved reference, ledger and WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–67.

**References:** [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF ToolTipService.ShowsToolTipOnKeyboardFocus](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice.showstooltiponkeyboardfocus).

## GA UI-68 — Accessible session-only AbuseIPDB credential workflow

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `6627ecfa9a597ab5bccdac9207a6be475d609ef7`. Prior GA UI-67 source `cdb1608b2c6f0f7f901f90c152752b0f2f00e5d9`; prior docs/publication `1d04a1f7edcde9df3eb0554793e4f488aca5db44`. **Exact GA UI-68 source commit SHA:** `0babc9e293634336dcfb574a74299933d1478d3b` (direct child of starting LIVE HEAD). Source XAML blob: `082d3dbe9e1a0f9ec00359b26c386c7e128aa945`. Owned paths: `Carthago/Views/MainWindow.xaml` and this `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. **Tests authored: 0; executed: 0.** No builds, XAML compilation, xUnit, replay, holdout, CI, GitHub Actions, runners, benchmarks, production capture or running-app screenshots.

### Approved reference, original consumers and start divergence

Resolved and **visually inspected** exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1672×941). Preserve navy/graphite/cyan/teal, restrained severity, left navigation, operational KPIs, prioritized incidents/investigation, local PPS ScottPlot (optional 10-sample average and bounded 120-point history), read-only local Live Events (80 displayed / 500 retained), explicitly **UNAVAILABLE** visual-only CLI, and Cisco/WebView2/ScottPlot and privacy/capture boundaries. Wide >=1440 / Standard 1100–1439 / Compact 1024–1099 / graceful below 1024 remain untouched. Screenshot IPs, metrics, rule IDs, timestamps, confidence, Mbps lines and terminal content are **DEMO ONLY**; none is real telemetry or evidence of capture health.

At start, prior UI-67 publication `1d04a1f7edcde9df3eb0554793e4f488aca5db44` to LIVE `6627ecfa9a597ab5bccdac9207a6be475d609ef7` was **two independent GA P0491–P0500 BSD rsh/protocol commits**, touching only `Carthago.Tests/ProtocolIntelligence/RshRequestInspectorTests.cs`, `Carthago/Services/ProtocolIntelligence/RshRequestInspector.cs`, `docs/protocols/PROTOCOL_EXPANSION_PROGRESS.md` and `docs/protocols/PROTOCOL_GA_P0491-P0500.md`. No UI-owned overlap. Read LIVE commits/tree, ledger through UI-67, `MainWindow.xaml`, `MainWindow.Settings.cs`, `MainWindow.Core.cs`, `MainWindow.xaml.cs`, Navigation, Dashboard, DashboardEvents, DashboardResponsive, Responsive, Plots, `Views/Theme.xaml` and read-only `TrafficCaptureService.cs`. In the original API-key row, `AbuseApiKeyBox` is a masked `PasswordBox`, and `ApplyApiKey_Click` trims nonempty input, assigns `_captureService.AbuseIpDbApiKey`, refreshes `ApiKeyStatusText` and shows an informational dialog; empty input shows a warning. The setter holds a session override in memory and disposes the cached AbuseIPDB client. The separate `SaveSettings_Click` persists other preferences but **not** the API key. Applying a key does **not** validate credentials, enable reputation lookups or initiate a request. The environment-variable fallback is `ABUSEIPDB_API_KEY`. No secret is introduced into source, XAML metadata, tooltips, logs or design documentation.

### One cohesive UI-owned change

In **Settings > Enrichment & Capture**, name the existing visible `AbuseIPDB API Key` label `SettingsAbuseApiKeyLabel` and associate it with `AbuseApiKeyBox` via `AutomationProperties.LabeledBy`. Replace the PasswordBox's terse hover tooltip with source-accurate guidance on masked entry, non-persistence by Save, the separate session-only action, non-validation and existing environment/.env persistence guidance. Expose this tooltip on keyboard focus and via `AutomationProperties.HelpText` bound to the static tooltip. On the existing **Use for this session** button, add truthful hover/keyboard-focus tooltip, explicit accessible Name and HelpText explaining in-memory override, nonempty requirement and no automatic lookup or preference write. **Two existing focusable controls** gain guidance; no additional control, focus stop, secret-value binding, handler, API, capture behavior, preference write, external request, theme, dimensions, responsive layout or security setting. Original `ApiKeyStatusText` and all status-writing logic remain unchanged.

### Static divergence, publication guard and residual risks

Source commit `0babc9e293634336dcfb574a74299933d1478d3b` changes **only** `Carthago/Views/MainWindow.xaml` (11 additions, 2 deletions); original `ApplyApiKey_Click`, `UpdateApiKeyStatus`, `AbuseIpDbApiKey` getter/setter, preference consumers, WPF partials, capture/privacy/trust boundaries, left navigation, chart and independent streams are untouched. Re-read LIVE remote HEAD **immediately before** publication, compare any concurrent protocol/detection/UI changes, and publish both private source/docs commits **together** through exactly one non-forced atomic GitHub `update_ref` with matching `expected_sha` lease on the same branch. If HEAD moved, reconcile only disjoint changes into a fresh private chain/lease; STOP on overlap, conflict, divergent ancestry or missing guarantee. Post-publication verify exact changed paths and blobs. Never publish partially, create branches/PRs, force-push or modify independent automations.

**Known source limitation:** `UpdateApiKeyStatus` checks `_captureService.AbuseIpDbApiKey` before checking `ABUSEIPDB_API_KEY`, while that getter itself falls back to the environment variable. Therefore an environment-provided key may be displayed as `session override active`; this pre-existing status-source misclassification is **not corrected** in this UI-only GA. Do not treat the status label as proof of credential validity, source provenance or successful lookup. Additional unverified risks: Windows WPF XAML compilation, `LabeledBy` resolution, PasswordBox accessibility/security behavior, keyboard-focus tooltips, UI Automation HelpText and screen-reader announcements, high contrast, DPI 125–200%, widths 1440/1100/1099/1024/1023/640px, empty-key warning, client disposal and any lookup/authentication failure. No claim of observed accessibility or functional success.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED; UNEXECUTED

1. Tab to the existing masked `AbuseApiKeyBox`; verify the visible label is unchanged and UI Automation resolves its `LabeledBy` association without exposing the secret.
2. Hover and keyboard-focus the PasswordBox; inspect tooltip, HelpText and masking, with no password text in accessible guidance or documentation.
3. Type a key without pressing **Use for this session**; confirm no key application, network lookup or preferences write occurs.
4. Activate **Use for this session** with empty input; inspect the original warning path and unchanged runtime key state.
5. Activate with a nonempty key in a controlled authorized scenario; inspect original session-only setter, cached-client disposal and informational dialog without assuming credential validity.
6. Inspect Save settings separately; verify it persists its existing preferences but does not persist the PasswordBox key, and that environment/.env configuration remains the separate persistent option.
7. Inspect the existing `ApiKeyStatusText` for session and environment cases; document the pre-existing environment-source misclassification without claiming verified provenance.
8. Inspect keyboard focus, screen-reader/UI Automation Name and HelpText, high contrast, 125–200% DPI and 1440/1100/1099/1024/1023/640px layouts for unchanged geometry and legibility.
9. Confirm unchanged local PPS/10-sample average/120-point history, prioritized incidents/investigation, read-only Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot, trust/privacy and capture boundaries.
10. Compare both commits/blobs and independent protocol/detection ancestry against approved reference; confirm exactly two owned paths and **zero** builds/tests/replays/CI/runners/capture.

**Open quality GAs:** pinned-SHA Windows WPF compilation, real keyboard/screen-reader/visual review and controlled credential scenarios only after owner says **“now it is test time.”** **Executed tests: 0.**

**Next independent UI GA UI-69:** inspect fresh LIVE HEAD, approved reference, ledger and original WPF consumers for one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–68.

**References:** [WPF AutomationProperties.LabeledBy](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.labeledby); [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF ToolTipService.ShowsToolTipOnKeyboardFocus](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice.showstooltiponkeyboardfocus).

## GA UI-69 — Dashboard-mode flags: truthful keyboard and accessibility guidance

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Start LIVE branch `feature/carthago-reliability-hardening` HEAD: `aae4c8eb59bce398d9cc27418574699bde5c4dde`. Prior GA UI-68 source `0babc9e293634336dcfb574a74299933d1478d3b`; prior documentation/publication `3bfb8562a7b63307277e82b59cfe49ff14a43e8b`. **Exact GA UI-69 source SHA:** `05990b4793085f5a53323a72babb1f3799d66b6f`, source blob `686ce5ab575ead0859789428de8d2a1ac537d5f1`. Owned paths: `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. Tests authored/executed: **0/0**. No builds, XAML compilation, xUnit, replay, holdout, CI, Actions, runner, benchmark, capture or running-WPF screenshot.

### Reference, provenance and start divergence

Resolved and **visually inspected** exact approved Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1672×941). Preserve navy/graphite/cyan/teal, restrained severity, left nav, operational KPIs, prioritized incidents/investigation, local PPS ScottPlot (optional 10-sample average, bounded 120-point history), read-only local Live Events (80 displayed / 500 retained), explicitly **UNAVAILABLE** visual-only CLI, Cisco/WebView2/ScottPlot and capture/privacy/trust boundaries. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099, graceful below 1024. Reference IPs, metrics, rule IDs, timestamps, confidence, Mbps lines and terminal text are **DEMO ONLY**, not telemetry or verified capture health.

The supplied UI-66 instruction was stale: UI-66, UI-67 and UI-68 are already published; do not repeat UI-01–68. Prior UI-68 publication to starting LIVE HEAD was **one independent R545 BACnet I-Am rule candidate** changing only `Carthago.Tests/R545AdvancedAccuracyBatchTests.cs`, `Carthago/Engine/Rules/Catalog/RuleRegistry.cs`, `Carthago/Engine/Rules/Expansion/R545_ExternalBacnetIAmAnnouncementRule.cs`, `docs/RULE_BATCH_545-545.md`, `docs/RULE_HARDENING_PROGRESS.md` and `docs/rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md`. No UI-owned overlap.

Static read-only audit: LIVE HEAD and recent commits, ledger through UI-68, `MainWindow.xaml`, `MainWindow.Settings.cs`, `MainWindow.Core.cs`, `MainWindow.Dashboard.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.xaml.cs`, `MainWindow.Navigation.cs`, `Theme.xaml`, and original read-only `Models/DashboardPreferences.cs`, `Services/DashboardLayoutService.cs`, `Services/DashboardPresetService.cs`. The existing `DashboardMinimalModeCheck` and `DashboardEmptyByDefaultCheck` load `UseMinimalDashboard` and `ShowEmptyDashboardByDefault` through `MainWindow.Core.cs`. Their original Checked/Unchecked `DashboardSectionToggle_Changed` handler persists the flags **immediately** through `PreferencesService.Update` when loaded and not syncing; it does not wait for Save settings. `RefreshDashboardLayoutFromPreferences` derives workspace visibility from configured enabled/available widgets, **not directly from either flag**. The existing `DashboardResetLayout_Click` replaces the layout with `DashboardPresetService.CreateEmptyMinimal()`; the widget-add handler separately sets `ShowEmptyDashboardByDefault=false`. Thus toggling these flags alone must not be presented as clearing configured widgets, retained incidents/events or capture.

### One cohesive UI-owned change

Add source-accurate hover ToolTips, `ToolTipService.ShowsToolTipOnKeyboardFocus="True"`, and `AutomationProperties.HelpText` bound to the ToolTip with `RelativeSource Self` on **exactly these two existing dashboard-mode checkboxes**. Guidance distinguishes immediate preference persistence from widget-driven presentation, and points to the existing Reset dashboard command for actual layout replacement. One provenance comment; **six new WPF attributes, seven XAML additions, zero deletions**. Preserve original captions, check states, handlers, preferences writer, keyboard order, dimensions, styling, responsive layout, source/consumer contracts, capture/privacy/trust and independent streams. No new focus stop, API, preference, telemetry, detection/protocol rule, security control or external request.

### End static review, publication gate and risks

Private source commit `05990b4793085f5a53323a72babb1f3799d66b6f` is a direct child of starting LIVE HEAD, with **only** `Carthago/Views/MainWindow.xaml` changed. This ledger-only commit must be its direct descendant. Static review of original XAML names/handlers, WPF partial consumers, unchanged theme/responsive paths, reference fidelity, privacy and independent R545 paths is not proof of compilation or runtime behavior. Immediately before publication, re-read LIVE remote HEAD and compare any concurrent changes; if disjoint, reconstruct a fresh private source/docs chain on new HEAD and use a fresh lease. STOP on UI-owned overlap, conflict, divergent ancestry or missing atomic lease. Publish complete candidate through **one non-forced atomic GitHub `update_ref` with matching `expected_sha`** on the same branch; no partial publication, branch/PR, force push, history rewrite or automation edit.

**Risks unverified:** Windows WPF parsing/compilation, ToolTip keyboard focus, HelpText binding, screen-reader announcements, high contrast, DPI 125–200%, widths 1440/1100/1099/1024/1023/640px, preference write failures and actual widget-driven dashboard response. These flags may not visibly alter an already configured workspace; tooltips avoid promising otherwise. No verified UI/accessibility or capture-health claim.

### Acceptance scenarios — PLANNED ONLY, NOT AUTHORED OR EXECUTED

1. Tab to **Use minimal dashboard**: original caption/check state/focus order and tooltip/HelpText remain coherent.
2. Tab to **Empty dashboard by default**: original caption/check state/focus order and tooltip/HelpText remain coherent.
3. Toggle minimal with loaded UI: original handler persists immediately without Save settings.
4. Toggle empty-by-default with loaded UI: original handler persists immediately without removing configured widgets.
5. With enabled widgets, inspect widget-driven workspace and honest tooltip wording after either toggle.
6. Activate existing Reset dashboard separately: inspect `CreateEmptyMinimal()` replacement without incident/event deletion.
7. Add widget with existing picker: inspect `ShowEmptyDashboardByDefault=false` original writer.
8. Inspect hover/focus, UI Automation, screen reader, high contrast, 125–200% DPI and widths 1440/1100/1099/1024/1023/640px.
9. Confirm unchanged KPIs, local PPS/10-sample average/120-point history, incident investigation, Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot and capture/privacy/trust boundaries.
10. Compare exact source/docs blobs, ancestry and independent changes; confirm only two owned paths and **zero** builds/tests/replays/CI/runners/capture.

**Next independent UI GA UI-70:** fresh LIVE HEAD, approved reference, ledger and original WPF consumers; one new distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–69. All acceptance remains deferred until owner says **“now it is test time.”**

**References:** [WPF AutomationProperties.HelpText](https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.helptext); [WPF ToolTipService.ShowsToolTipOnKeyboardFocus](https://learn.microsoft.com/dotnet/api/system.windows.controls.tooltipservice.showstooltiponkeyboardfocus); [WPF RelativeSource Self](https://learn.microsoft.com/dotnet/desktop/wpf/advanced/relativesource-markupextension).

## GA UI-70 — Developer demo provenance: distinguish simulated analytics from live capture

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD `760e31061f2428f2b05c1e29614cf228402e28b4`, with independent GA R546 NTP mode-7 UDP/123 fanout rule candidate already present and untouched. Prior UI-69 source `05990b4793085f5a53323a72babb1f3799d66b6f`; prior UI-69 publication `881d67c7a1d17a1a3cecda3917923a86aad88bc8`. **Exact UI-70 source commit:** `78c4deead4a7b5e5e67f87011847c6461227f5f1`; source blob `b314568d9e3c4b3a93eced163987be076a33d88f`. **Owned paths:** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. Tests authored/executed: **0/0**. No build, WPF compilation, screenshot of running software, xUnit, replay, holdout, CI, Actions, runner, benchmark or capture.

### Approved visual reference and source audit

Resolved and visually inspected exact ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`. The approved concept uses navy/graphite surfaces, restrained cyan/teal accents, subdued panel borders, left navigation, operational KPIs, prioritized incidents/investigation and dense read-only local events. All sample addresses, confidence, throughput, rules, times and terminal lines in that image are **DEMO ONLY**; its terminal is visual-only and **UNAVAILABLE**. The screenshot does not show developer settings; the new banner uses existing theme tokens rather than copying sample telemetry. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024, ScottPlot local PPS with optional 10-sample average and bounded 120-point history, Live Events 80 displayed/500 retained, Cisco/WebView2/ScottPlot and privacy/trust/capture boundaries.

Start divergence audit read LIVE branch HEAD and recent commits, ledger through UI-69, existing `MainWindow.xaml` and `Theme.xaml`, plus original WPF partials `MainWindow.Demo.cs`, `MainWindow.Core.cs`, `MainWindow.Settings.cs`, `MainWindow.Dashboard.cs`, `MainWindow.Responsive.cs`, `MainWindow.xaml.cs`. The existing `InitializeDemoMode` reveals `DemoModeGroup` in debug builds or with `--demo-mode`. `RunDemoIncident_Click` creates tagged simulated analytics records, anomaly signals and detection events and refreshes dashboard incident views; `ClearDemoData_Click` clears tagged demo data, and `OpenDemoIncidentQueue_Click` navigates to Incidents. Existing analytics-demo dashboard widget actions reuse these handlers. None of these operations establishes live capture health. The original second-row explanatory text correctly says raw packet, sink and forensic views continue to show real capture data.

### One cohesive UI-owned change

Replace **only** the existing first explanatory `TextBlock` in `DemoModeGroup` with a non-focusable, visually bounded provenance banner. Reuse `PillAccentBgBrush`, `CardBorderBrush`, `AccentBrush` and `TextSubtleBrush` already defined in `Views/Theme.xaml`. Display **SIMULATED ANALYTICS · NOT LIVE CAPTURE** above the existing developer-mode activation explanation, which also clarifies that the panel is not evidence of capture health. Keep the separate raw-capture explanation, three original buttons and handlers, status message, four grid rows, focus order, x:Names, GroupBox visibility, navigation, preference writers, data producers and runtime semantics unchanged. No new interactive control, source/consumer contract, telemetry, simulated incident, external request or security control. This improves visible provenance hierarchy rather than repeating earlier tooltip-only GAs.

### Publication guard and static review

Source commit `78c4deead4a7b5e5e67f87011847c6461227f5f1` is a direct child of starting LIVE HEAD, changing only `Carthago/Views/MainWindow.xaml`. The documentation commit must be its direct child, changing only this ledger. Re-read LIVE HEAD immediately before publication and compare any concurrent detection/protocol/UI changes. Publish the complete two-commit candidate via **one non-forced atomic GitHub `update_ref` with `expected_sha` lease** on the same branch. If moved, reconcile disjoint changes with a fresh private chain and lease; STOP on overlap, missing guarantee or divergent ancestry. Verify post-publication remote HEAD, both blobs and exactly two owned paths. No branch, PR, force push, history rewrite or automation edits.

**Unverified risks:** Windows WPF XAML parsing/compilation; whether a new static banner wraps acceptably at 1440/1100/1099/1024/1023/640px; 125–200% DPI, high contrast and screen-reader reading order; actual distinction between simulated analytics and live packet views; source-dependent demo visibility and status updates. Static source review is not runtime proof.

### Acceptance scenarios — PLANNED ONLY, NOT AUTHORED OR EXECUTED

1. In a debug build, inspect the existing developer section: the banner states simulated analytics, not live capture, with original actions and status below.
2. In a release build without `--demo-mode`, inspect that the entire GroupBox remains collapsed, with no new focus stop.
3. In an authorized release demo launch, inspect that `--demo-mode` reveals the same original GroupBox and banner.
4. Inspect the new cyan-tinted banner, contrast and line wrapping at 1440/1100/1099/1024/1023/640px and 125–200% DPI.
5. Inspect high-contrast theme and assistive-technology reading order; banner text must not imply validated monitoring health.
6. Activate **Simulate compromised laptop** in a controlled demo; inspect tagged analytics and unchanged original handler.
7. Activate **Clear demo data**; inspect tagged-demo cleanup without deletion of real incidents, capture, sink or forensic data.
8. Activate **Open incident queue**; inspect original navigation and status update without a new capture or simulation trigger.
9. Inspect dashboard widgets, PPS, KPIs, incidents, read-only Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot, privacy and capture boundaries for unchanged behavior.
10. Inspect commit ancestry, exact owned paths and blobs against the approved reference; confirm **zero** builds, tests, replays, CI, runners, benchmarks or production capture.

**Next independent UI GA UI-71:** fresh LIVE HEAD, approved reference, ledger and WPF consumers; choose one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–70. All acceptance remains deferred until owner explicitly says **“now it is test time.”**

## GA UI-71 — Live Events empty/no-match state: restrained visual hierarchy

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `0ac575d65dcc59ef05fcba136e559d1d56709a41`. Prior UI-70 source `78c4deead4a7b5e5e67f87011847c6461227f5f1`, publication `3fd5e0fade9792a0e294252edebdb117e85feead`. **Exact UI-71 source commit:** `9280e3b194e545767d5cede871be51eab58c9747`; source XAML blob `3e5d25eb64b92e1e9c87251e92a696bc70aa7cbe`. Owned paths: `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` **only**. No builds, tests, xUnit, replays, holdouts, CI, Actions, runners, benchmarks, production capture or running-WPF screenshots. Authored/executed tests: **0/0**.

### Approved image, baseline and static divergence review

**FIRST** resolved and visually inspected exact ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (dark navy/graphite SOC overview, cyan/teal accents, restrained severity, left navigation, KPI cards, prioritized incidents/investigation and dense Live Events). Its IPs, metrics, rule IDs, confidence, Mbps series, timestamps and terminal lines are **DEMO ONLY**. The terminal remains explicitly **UNAVAILABLE** and visual-only; do not interpret the reference as a telemetry, capture-health, protocol or CLI contract. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024; local ScottPlot PPS with optional 10-sample average and bounded 120-point history; local read-only Live Events 80 displayed/500 retained; Cisco/WebView2/ScottPlot and privacy/trust/capture boundaries.

Starting LIVE HEAD `0ac575d65dcc59ef05fcba136e559d1d56709a41` follows UI-70 publication by **one independent R547 external BACnet Who-Is fanout detection candidate**, changing only `Carthago.Tests/R547AdvancedAccuracyBatchTests.cs`, `Carthago/Engine/Rules/Catalog/RuleRegistry.cs`, `Carthago/Engine/Rules/Expansion/R547_ExternalBacnetWhoIsTargetFanoutRule.cs`, `docs/RULE_BATCH_547-547.md` and `docs/rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md`. No UI-owned overlap. Audited the current `MainWindow.xaml`, `Theme.xaml`, `MainWindow.Dashboard.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.Core.cs`, the UI ledger through UI-70 and original names/bindings/consumers. `DashboardLiveEventsGrid` is read-only, virtualized and bound to the existing bounded `_dashboardLiveEventRows`. The original `DashboardLiveEmptyText` is populated in `RefreshDashboardLiveEvents()`: when `_alerts.Count==0`, it says no local events observed this session; when filters exclude retained rows, it says no local detections match selected filters. That same handler changes its `Visibility` to Visible only for zero displayed rows; filter handlers, 80-row projection, 500-retention status and capture-state caveats are unchanged.

### One cohesive UI-owned design change

Wrap **only** the existing `DashboardLiveEmptyText` in a centered, non-hit-testable, non-focusable `Border` using existing `PillBgBrush`, `SoftDividerBrush`, and restrained 10px radius, with a small cyan `NO ROWS TO DISPLAY` eyebrow above the original source-driven message. Bind the wrapper's `Visibility` to the original named text element's existing `Visibility` so it disappears whenever event rows are displayed. Preserve the original `x:Name`, Text, foreground, wrapping, programmatic updates and all consumers. This is a distinct **visible empty-state hierarchy improvement**, not a duplicate of prior settings/tooltips or UI-70's developer-demo provenance banner. No new data, counts, capture claims, commands, keyboard focus stops, handlers, viewmodels, shared APIs, external calls or detection/protocol changes.

### End static review, publication guard and risks

Private source commit `9280e3b194e545767d5cede871be51eab58c9747` is a direct child of baseline HEAD and changes only `Carthago/Views/MainWindow.xaml` (**31 additions / 10 deletions** for one wrapper replacement). Documentation commit must be its direct child and change only this ledger. The new `Border` visibility depends on WPF `ElementName` resolution of its named descendant; it is **not runtime-verified**. No original event producer, timer, data projection, filtering, incident, capture, preference, chart, CLI, Cisco/WebView2/ScottPlot or security/privacy control was modified. Before publishing, re-read LIVE remote HEAD and compare concurrent protocol/detection changes; reconstruct on a fresh base if disjoint, STOP on UI overlap/conflict or unavailable lease. Publish complete two-commit candidate by **one non-forced atomic GitHub `update_ref` with `expected_sha`** on the existing branch, then verify remote HEAD and changed paths. No new branch/PR, force push, history rewrite or automation edits.

**Unverified risks:** XAML parsing/Windows compilation; descendant `ElementName` visibility binding resolution and initial loading order; empty-state overlay height relative to 190px grid; contrast and text wrapping at 1440/1100/1099/1024/1023/640px and 125–200% DPI; high-contrast theme; assistive-technology reading order and whether the non-interactive eyebrow is announced appropriately; correct empty vs no-match text after filter changes; no accidental overlay on nonempty rows. Source-only static inspection is **not** a verified rendering or accessibility result.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED OR EXECUTED

1. With zero retained local detection events, inspect the centered bounded empty state and original “No local detection events observed in this session.” text.
2. With retained events but filters matching zero rows, inspect the same bounded treatment with the original “No local detections match the selected filters.” text.
3. With at least one displayed row, confirm the wrapper and original empty text are both collapsed, with no overlay over rows or headers.
4. Clear filters and verify the original event grid and read-only projection return without new data or state.
5. Verify the original named `DashboardLiveEmptyText` still receives text/visibility changes from `MainWindow.DashboardEvents.cs` and that `ElementName` binding resolves without errors.
6. Inspect the original four filters, frozen first column, virtualized selection and 80 displayed/500 retained limits for unchanged behavior.
7. Inspect cyan eyebrow, subdued surface, text wrapping and contrast at 1440/1100/1099/1024/1023/640px, 125–200% DPI and high contrast.
8. Inspect keyboard focus, screen-reader reading order and lack of an additional focus stop or obscured interactive grid controls.
9. Inspect unchanged local PPS/10-sample average/120-point history, KPIs, incidents/investigation, CLI unavailable, Cisco/WebView2/ScottPlot and capture/privacy/trust boundaries.
10. Inspect exact two-commit ancestry and two owned paths against approved image and independent R547 changes; confirm **zero** builds/tests/replays/CI/runners/benchmarks/capture.

**Next independent UI GA UI-72:** inspect fresh LIVE HEAD, approved reference, ledger and original WPF consumers; choose one new UI-owned visual/accessibility/readability improvement outside UI-01–71. All acceptance remains deferred until owner says **“now it is test time.”**

## GA UI-72 — High-Risk Hosts: subdued row separators for dense triage readability

**2026-11-01 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE remote branch HEAD: `d93f8b3308ba38d7c809e1248849fc0db1530d3d`. Prior UI-71 source `9280e3b194e545767d5cede871be51eab58c9747`, publication `dc51ac8486607462b59e66bfa2fbfa52aa8198c6`. **Exact UI-72 source commit:** `bc8c92b8114b893f106a7465d47c71b47187c090`; source XAML blob `eb6a9eda4bf064ca2aaf0af6b8672a3b466b584f`. Owned paths: `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` only. Builds, tests, replays, holdouts, CI, GitHub Actions, runners, benchmarks, screenshots of running WPF and production capture: **ZERO**. Acceptance scenarios below are **PLANNED ONLY, NOT AUTHORED OR EXECUTED**.

### Approved design reference and initial divergence review

**FIRST** resolved and visually inspected exact ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`: navy/graphite panels, cyan/teal accents, quiet dividers, restrained severity, left navigation, KPI cards, prioritized incidents, investigation and dense local event tables. Its IPs, metrics, rule IDs, confidence percentages, Mbps plots, timestamps and terminal lines are **DEMO ONLY**. The CLI remains visual-only and explicitly **UNAVAILABLE**; no screenshot claim is live capture or telemetry. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024; local PPS ScottPlot optional 10-sample average/bounded 120-point history; read-only local Live Events 80 displayed/500 retained; Cisco/WebView2/ScottPlot and capture/trust/privacy boundaries.

Read live HEAD, recent commits, ledger through UI-71, `MainWindow.xaml`, `Theme.xaml`, `Sidebar.xaml`, `MainWindow.xaml.cs`, and the original `MainWindow.Dashboard.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.Core.cs` and `MainWindow.Settings.cs` partials. The starting HEAD follows UI-71 publication by **two independent R548 external Modbus write fanout detection candidate commits**, changing engine/rule registry, R548 source/tests and rule/backlog docs only. No UI overlap. `DashboardHostItemsControl` binds to the private `_dashboardHostRows` populated by `BuildSocHostRows()`: at most five locally grouped unresolved incident source hosts, with anomaly-signal fallback only when no incident hosts exist. Existing columns are Host, Risk, Items and Activity. The local risk score is **not** detection confidence; Activity is relative timestamp density, **not** packet traffic or risk history. Host rows are a non-interactive `ItemsControl` DataTemplate in a 112px-max-height ScrollViewer. `DashboardSummaryGrid` is repositioned by the original responsive partial.

### One cohesive UI-owned design change

Add **one non-hit-testable 1px bottom divider** to each existing High-Risk Hosts row template, spanning the four existing columns. Reuse the existing theme `SoftDividerBrush` (`#1B3245`) and enable pixel snapping. The divider occupies the existing row's layout rather than adding a new row, card, column, focus stop or scrollbar contract. Preserve the original 20px minimum row height, margins, four fixed column widths, text/truncation, score accent, full-host tooltip, accessibility names/help, Items/Activity semantics, sorting, five-row bound, navigation and original producers/consumers. This is a **visible row-scanning improvement**, distinct from UI-18's semantic row labels, UI-53's numeric tooltips, and UI-71's Live Events empty-state card. No new count, telemetry, status, external request, capture control, handler, viewmodel, API or detection/protocol change.

### Static end review, risks and publication discipline

Source commit is a direct child of the pinned baseline, changing only `Carthago/Views/MainWindow.xaml`; its documentation descendant changes only this ledger. Recheck LIVE HEAD and compare any intervening independent changes immediately before publication. Publish the complete private two-commit chain by exactly **one non-forced GitHub `update_ref` with `expected_sha` lease** on the existing branch; if HEAD moves, reconstruct on a new disjoint base and fresh lease or STOP on overlap/uncertainty. Post-publication verify remote HEAD, both blobs, ancestry and exactly two owned paths. No branches, PRs, force pushes, history rewrites or automation changes.

**Unverified risks:** Windows WPF XAML parsing/compilation; 1px divider visibility, device-pixel alignment and contrast in standard/high-contrast themes; whether the line touches glyph descenders at 20px row minimum; last-row border appearance; scrollbar and clipping at 112px max height; horizontal alignment of 170/48/62/84px columns at 1440/1100/1099/1024/1023/640px and 125–200% DPI; screen-reader/keyboard reading order. No claim of rendered success, validated accessibility or unchanged runtime behavior.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED OR EXECUTED

1. With five incident-group host rows, inspect one subtle divider per displayed row without altered values, sort order or source grouping.
2. With one incident host, inspect its single divider; no fabricated empty rows or extra counts.
3. With no incident hosts and anomaly fallback, inspect the same separators while Items still means anomaly-signal count.
4. With zero hosts, inspect that no artificial row/divider is shown.
5. Inspect all Host/Risk/Items/Activity column alignment, compact host ellipsis and full-host tooltip.
6. Verify that row separators are not keyboard-focusable, do not intercept hover and do not alter accessible host names.
7. Inspect 112px scroll viewport, five-row visibility, row clipping and last-divider treatment.
8. Inspect Wide/Standard/Compact/below-1024 layouts, 125–200% DPI and high-contrast rendering.
9. Verify PPS, KPIs, incidents/investigation, read-only local Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot and privacy/capture/trust boundaries are unchanged.
10. Verify exact source/docs blobs, commit ancestry, owned-path diff and absence of tests/builds/CI/runners/replays/benchmarks/capture.

**Next independent UI GA UI-73:** inspect fresh LIVE HEAD, approved image, ledger and original WPF consumers; choose one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–72. All acceptance remains deferred until owner explicitly says **“now it is test time.”**

## GA UI-73 — Investigation evidence provenance: restrained visual keyline

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `6b98dd2d52f0ec8929903754504dc90511ba8062`. Previous GA UI-72 source `bc8c92b8114b893f106a7465d47c71b47187c090`, publication `f5f4b706a61d681533b05bc87536f8dee84ac430`. **Exact UI-73 source commit:** `e47cac2595438d4cb5b9be45f31a0cbe23279e28`; source XAML blob `9ec3ee84545f1a68330db98f9bc3c8efdf6798c8`. Authorized owned paths **only**: `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. No tests, builds, xUnit, replays, holdouts, CI, Actions, runners, benchmarks, production capture or running-WPF screenshots: **ZERO**. Acceptance below is **PLANNED AND UNEXECUTED**.

### Approved reference, baseline and initial static divergence review

**FIRST** resolved and visually inspected exact ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`: navy/graphite SOC shell, cyan/teal accents, quiet borders, restrained severity, persistent left navigation, KPIs, traffic panel, prioritized incident triage/investigation and dense event table. All depicted IPs, timestamps, rule IDs, metrics, confidence, Mbps and terminal output are **DEMO ONLY**, not telemetry or capture-health contracts. The CLI remains explicitly **UNAVAILABLE** and visual-only. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099, graceful below 1024, local PPS ScottPlot optional 10-sample average/bounded 120-point history, read-only local Live Events 80 displayed/500 retained, Cisco/WebView2/ScottPlot, privacy/trust/capture boundaries.

Starting HEAD follows UI-72 publication by **two independent R549 default Basic cross-subnet fanout rule commits**, with changes confined to engine rule registry/source, R549 tests, and rule/backlog docs. Compared `f5f4b706a61d681533b05bc87536f8dee84ac430..6b98dd2d52f0ec8929903754504dc90511ba8062`: no UI-owned overlap. Inspected LIVE recent commits, design ledger through UI-72, `MainWindow.xaml`, `Theme.xaml`, `Sidebar.xaml`, `MainWindow.xaml.cs`, `MainWindow.Dashboard.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.Core.cs` and `MainWindow.Settings.cs`. The original `DashboardDetailEvidenceSummaryText` is populated by `MainWindow.Dashboard.cs` using the directly selected correlated incident snapshot, with an explicit no-evidence path and counts of reported evidence/related events; it never asserts a verified chain. `DashboardDetailEvidenceSummaryLabel` is its existing accessible label. No shared API or producer change is needed.

### One cohesive UI-owned visual change

In the existing investigation **Evidence provenance (reported, not verified)** `DetailGridCard`, replace the inner StackPanel with a two-column Grid containing a **decorative, non-hit-testable, non-focusable 3px cyan keyline at 65% opacity** and the unchanged label and dynamic summary in the second column with a 10px gutter. Reuse the existing `AccentBrush` and original `DetailGridCard` surface/border. The visible accent creates a restrained provenance subsection distinct from nearby investigation facts and actions. The text, accessible label association, original `x:Name` values, message content, bindings, selection handlers, incident/anomaly source logic, card position and parent layout are unchanged. The keyline conveys **section hierarchy only**, not verified evidence, severity, risk or capture health. No new telemetry, capture state, command, focus stop, event, viewmodel, preference, external request, shared contract or security control.

This is distinct from UI-04's incident/evidence content, UI-12's labeled facts, UI-25's grouping and UI-70–72's demo banner, Live Events empty state and host-row dividers.

### End static review, publication guard and unverified risks

Source commit `e47cac2595438d4cb5b9be45f31a0cbe23279e28` is a private direct child of baseline `6b98dd2d52f0ec8929903754504dc90511ba8062` and changes only `Carthago/Views/MainWindow.xaml`; the documentation commit must be its direct child and change only this ledger. Before publication re-read LIVE HEAD and compare intervening independent detection/protocol/UI changes. Publish the **complete two-commit candidate** via exactly **one non-forced atomic GitHub `update_ref` with `expected_sha` lease** on the same branch. On movement, reconstruct on disjoint fresh base with fresh lease; STOP on conflict, overlap or missing guarantee. Post-publication check HEAD, ancestry, two exact blobs and exactly two owned paths. No branch/PR creation, force push, history rewrite or automation changes.

**Unverified risks:** Windows WPF XAML parsing/compilation; Grid width allocation and keyline vertical sizing; 3px/65%-opacity contrast and high-contrast visibility; 10px inset reducing text width and possible clipping in narrow windows; long dynamic evidence counts/wrapping; 125–200% DPI, 1440/1100/1099/1024/1023/640px; assistive-technology reading order and whether decorative Border remains absent from keyboard focus. Static inspection is not rendering, accessibility or compilation verification.

### Acceptance scenarios — PLANNED ONLY, NOT AUTHORED OR EXECUTED

1. Select a correlated incident with reported evidence; inspect unchanged count and related-event wording alongside the subdued keyline.
2. Select a correlated incident with zero evidence; inspect the existing no-evidence message, with no implied verified chain.
3. Select an anomaly with no directly selected incident; inspect the original explicit provenance caveat.
4. Switch selections repeatedly; confirm the original `DashboardDetailEvidenceSummaryText` is updated and `DashboardDetailEvidenceSummaryLabel` remains the accessible label.
5. Inspect the keyline for visual hierarchy only, without severity, confidence, sensor-health or capture-status implication.
6. Inspect keyboard focus and screen-reader order; the decorative Border must not add a focus stop or obscure action buttons.
7. Inspect narrow-width text wrapping, label visibility and card gutters at 1440/1100/1099/1024/1023/640px and 125–200% DPI.
8. Inspect standard/high-contrast rendering, opacity, color differentiation and original card surface/border.
9. Inspect unchanged prioritized incidents, KPIs, PPS 10-sample/120-point bounds, local Live Events 80/500, explicitly unavailable CLI, Cisco/WebView2/ScottPlot and capture/privacy/trust boundaries.
10. Verify final source/docs blobs, direct-parent commit ancestry, exact owned-path diff, preserved independent R549 changes and **zero** builds/tests/replays/CI/runners/benchmarks/capture.

**Next independent UI GA UI-74:** inspect fresh LIVE HEAD, exact approved reference, ledger and original WPF consumers; choose one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–73. All acceptance remains deferred until the owner explicitly says **“now it is test time.”**

## GA UI-74 — Prioritized incident queue: visible hover and selected-row surfaces

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `78ad036c6794977c78d88614f9ab49f72654d29f`. Prior UI-73 source `e47cac2595438d4cb5b9be45f31a0cbe23279e28`, publication `f611cedba4b4d99c32976fb227383043f1b13878`. **Exact GA UI-74 source commit:** `95687189a7d184e8a575ef342ade232cd59c4b23`; source XAML blob `1e0218d97a808c9fe53de3eb89d168c0139aac29`. Only owned paths: `Carthago/Views/MainWindow.xaml` and this ledger. No builds, tests, xUnit, replays, holdouts, CI, Actions, runners, benchmarks, production capture or running-WPF screenshots. Authored/executed tests: **0/0**.

### Approved reference, initial divergence and original consumers

**FIRST** resolved and visually inspected exact ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`. It depicts a navy/graphite SOC overview with cyan/teal accents, restrained severity, left navigation, KPIs, dense prioritized incidents/investigation and local Live Events. Its IPs, throughput/Mbps lines, rule IDs, confidence, timestamps and CLI text are **DEMO ONLY**, not capture/telemetry contracts; CLI remains explicitly **UNAVAILABLE** visual-only. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024, local PPS ScottPlot with optional 10-sample average and bounded 120-point history, read-only local Live Events 80 displayed/500 retained, Cisco/WebView2/ScottPlot and privacy/trust/capture boundaries.

Starting LIVE HEAD follows UI-73 publication by three **independent R550 BACnet paired discovery** source/test/docs commits (`a2f0da3`, `3bacd83`, `78ad036`); those changes do not touch UI-owned files. Inspected recent commits, the ledger through UI-73, current `MainWindow.xaml`, `Theme.xaml`, and original `MainWindow.Dashboard.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.Core.cs`, `MainWindow.Navigation.cs`, `MainWindow.Plots.cs`, `MainWindow.xaml.cs` partials. `DashboardAnomalyList` is an existing WPF ListBox bound to `_dashboardAnomalyItems`. Original selection restores an item across refreshes and `DashboardAnomalyList_SelectionChanged` updates investigation details. The ListBoxItem template already has a cyan selected/focus border; the inner `SocTimelineItem` Border's opaque `#081524` background prevents an outer background-only change from being visible. Existing theme brushes `RowHoverBrush` and `SelectionBgBrush` are already defined; no new theme token or contract is required.

### One cohesive UI-owned change

Name only the **existing** incident/anomaly row Border `TriageRowCard`, and add two `DataTemplate.Triggers` that change **that inner Border's background**: `RowHoverBrush` on the parent ListBoxItem hover, `SelectionBgBrush` on selection (declared later to take priority when both apply). This provides a visible, restrained navy/cyan hover-to-selection hierarchy distinct from UI-04's outer selection/focus outline and UI-71/72/73's separate empty-state, host-divider and evidence-keyline treatments. Keep original queue items, severity/risk colors, scores, titles, timestamps, row height, margins, original hover opacity, selected/focus border, keyboard behavior, source collections, ordering, handlers, detail updates and data bindings unchanged. No new focus stop, action, simulated data, telemetry, security/capture behavior, shared API, viewmodel, detection or protocol change.

### Static end review, publication guard and unverified risks

Private source commit `95687189a7d184e8a575ef342ade232cd59c4b23` is a direct child of pinned baseline `78ad036c6794977c78d88614f9ab49f72654d29f` and changes only `Carthago/Views/MainWindow.xaml`. Documentation commit is its direct child and changes only this ledger. Before publication, re-read LIVE remote HEAD and compare all concurrent detection/protocol/UI changes. Publish the complete private two-commit candidate with **one non-forced atomic GitHub `update_ref` using `expected_sha` lease** on the same branch; on movement reconcile disjoint paths with a fresh private chain and lease, or STOP on overlap/uncertainty. Verify post-publication remote HEAD, ancestry, both blobs and exact two-file scope. No branch/PR, force push, history rewrite or automation edits.

**Unverified risks:** WPF XAML parsing/compilation; `RelativeSource FindAncestor ListBoxItem` binding resolution inside a DataTemplate; hover/selection trigger precedence; selected state after collection refresh; contrast and readability of text and existing severity/risk accents against both fill colors; high-contrast themes, 125–200% DPI, 1440/1100/1099/1024/1023/640px widths; focus visuals and screen-reader/keyboard selection; retained row clipping in the fixed-height triage panel. Static source review is not proof of rendered or accessible behavior.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED OR EXECUTED

1. Hover an unselected correlated-incident row; inspect subdued hover fill and unchanged text/severity/risk badge.
2. Hover an unselected anomaly row; inspect the same hover treatment without implying a confirmed incident.
3. Select a row with mouse; inspect selected fill and existing cyan outline, while investigation updates to that item.
4. Move hover off the selected row; verify selection fill persists and hover fill disappears from unselected rows.
5. Use arrow keys to select different rows; verify keyboard focus outline, selected fill and original investigation selection handler.
6. Refresh the queue while a previously selected incident persists; verify original selection restoration and corresponding fill.
7. Inspect empty queue, scrolling, text truncation, original 64px row height, risk badges and local-clock timestamps for no fabricated content.
8. Inspect all breakpoints (1440/1100/1099/1024/1023/640px), 125–200% DPI, high contrast, keyboard focus and assistive-technology row names.
9. Inspect unchanged PPS optional average/120-point bound, KPIs, read-only Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot and capture/privacy/trust boundaries.
10. Inspect exact source/docs blobs, direct-parent commit ancestry, owned-path diff, untouched independent R550 changes and **zero** builds/tests/replays/CI/runners/benchmarks/capture.

**Next independent UI GA UI-75:** inspect fresh LIVE HEAD, exact approved reference, ledger and original WPF consumers; choose one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–74. All acceptance remains deferred until owner explicitly says **“now it is test time.”**

## GA UI-75 — Live Events: visually grouped local filter toolbar

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `0a70a91627be68f3470614db4a62455bfa8f18a9`. Previous GA UI-74 source `95687189a7d184e8a575ef342ade232cd59c4b23`, publication `6d9b7f8578f996926fb599523cb03a5e94180312`. **Exact GA UI-75 source commit:** `6291c341d9aa717f56f8296e4a70c0d9af59e87a`; source XAML blob `285a1c9876df709c4601fd317d6f92f9ff7853f6`. Owned paths only: `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. Builds, dotnet tests, xUnit, replays, holdouts, CI, GitHub Actions, runners, benchmarks, production capture, running-WPF screenshots and authored/executed tests: **ZERO**. Scenarios below are **PLANNED ONLY; UNEXECUTED**.

### Approved reference and initial static divergence review

**FIRST** resolved and visually inspected exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928). Reference has navy/graphite panels, cyan/teal accents, restrained red/amber severity, persistent left navigation, operational KPIs, a traffic plot, prioritized incidents, investigation and a dense Live Events table with filters directly above it. Its IPs, timestamps, Mbps lines, rule IDs, metrics, confidence and terminal text are **DEMO ONLY**, never live telemetry, verified capture health or data sources. Preserve existing Wide >=1440, Standard 1100–1439, Compact 1024–1099, graceful below 1024, local PPS ScottPlot 10-sample average/120-point history, read-only local Live Events 80 displayed/500 retained and the explicitly **UNAVAILABLE** visual-only CLI.

Starting HEAD follows GA UI-74 publication by **two independent R551 BACnet-to-Modbus rule source/tests/docs commits** (`19aca99dca435d51b02ce9edeb53aab20a06bce6`, `0a70a91627be68f3470614db4a62455bfa8f18a9`); comparison against UI-74 publication showed **no UI-owned path overlap**. Read live recent commits and the ledger through UI-74; inspected `MainWindow.xaml`, `Theme.xaml`, `Sidebar.xaml`, `MainWindow.DashboardEvents.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.Dashboard.cs`, `MainWindow.xaml.cs`, `MainWindow.Core.cs`, `MainWindow.Settings.cs` and `MainWindow.Navigation.cs`. The original `DashboardLiveEventsGrid` is read-only, virtualized, with a frozen first column; `MainWindow.DashboardEvents.cs` reads four existing filters, projects at most 80 rows from the retained local collection (max 500), updates source-driven empty/status/provenance text and navigates to existing Raw Detections. The existing `WrapPanel` already wraps filter controls at narrow widths. No shared API, viewmodel, data source or producer change is required.

### One cohesive UI-owned visual change

Wrap the **existing Live Events severity, protocol, rule and search filters plus Clear filters** in one restrained, non-interactive `Border` occupying the original `Grid.Row="1"`. Reuse theme `PillBgBrush` and `SoftDividerBrush`, a 1px outline, 8px corner radius and 10px/9px/10px/3px padding. The original `WrapPanel` remains the child, with **all existing named controls, labels, handlers, tooltips, accessible metadata, control sizes, order and margins unchanged**. This is a visible filter-toolbar grouping and scan-hierarchy improvement, distinct from UI-16/26 filter labels and UI-71 empty-state styling. The decorative container adds no keyboard focus stop, action, telemetry, new filter, capture behavior or fabricated status. The event table, header, status/provenance, 80/500 limits, investigation, Cisco/WebView2/ScottPlot, detection/protocol/security controls and privacy/trust boundaries remain source-unchanged.

### Static end review, publication guard and unverified risks

Private source commit `6291c341d9aa717f56f8296e4a70c0d9af59e87a` is a direct child of pinned baseline `0a70a91627be68f3470614db4a62455bfa8f18a9`, with only `Carthago/Views/MainWindow.xaml` changed (11 additions, 2 deletions). The private documentation descendant changes only this ledger. Re-read LIVE remote HEAD **immediately before publication**; compare intervening detection/protocol/UI changes. Publish the complete private two-commit chain via **one non-forced atomic GitHub `update_ref` with `expected_sha` lease** on the existing branch. On HEAD movement, reconcile only disjoint paths on a fresh base and fresh lease; STOP on overlap, conflicts or absent atomic guarantee. After publication, inspect HEAD, direct ancestry, source/docs blobs, exact owned-path diff and preserved independent R551 files. No new branch, PR, repository, automation, force push or history rewrite.

**Unverified risks:** Windows WPF XAML parsing/compilation; border/padding consuming horizontal room and causing earlier filter wrapping, especially 1024/1023/640px; auto-height toolbar growing with wrapped rows; extra vertical space above the fixed-height 190px table; 1px border visibility and color contrast in high-contrast themes; 125–200% DPI; keyboard tab order, screen-reader reading order, tooltip presentation and whether the non-interactive wrapper affects focus; scrolling/selection, empty state and long labels. Static inspection is **not** rendered UI, accessibility or compilation verification.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED OR EXECUTED

1. At 1440px, inspect the subdued filter toolbar, unchanged labels and visible separation from the read-only event table.
2. At 1100/1099/1024/1023/640px, inspect natural WrapPanel line breaks, control visibility, scroll containment and absence of horizontal clipping.
3. At 125%, 150% and 200% DPI, inspect toolbar padding, 1px border, label/control alignment and row wrapping.
4. Inspect standard/high-contrast themes for readable inputs, focus outlines and restrained toolbar background/border.
5. Use keyboard Tab/Shift+Tab through severity, protocol, rule, search and Clear filters; ensure no additional focus stop.
6. Apply each of the original four filters and Clear filters; verify unchanged event projection and retained local data.
7. With zero events, nonmatching filters and populated events, inspect original empty-state overlay and unchanged 190px virtualized read-only grid.
8. Inspect frozen Event time column, horizontal scrolling, accessibility metadata and original 80 displayed/500 retained boundaries.
9. Inspect unchanged operational KPIs, local PPS 10-sample average/120-point bound, prioritized incidents/investigation, unavailable CLI, Cisco/WebView2/ScottPlot, capture/trust/privacy and independent R551 detection/protocol files.
10. Inspect exact source/docs blobs, two direct-parent commits, only two owned changed paths, fresh expected-SHA publication lease and **zero** tests/builds/replays/CI/runners/benchmarks/capture.

**Next independent UI GA UI-76:** inspect fresh LIVE HEAD, exact approved image, ledger and original WPF consumers; choose one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–75. Acceptance remains deferred until the owner explicitly says **“now it is test time.”**

## GA UI-76 — Recommended Actions: visible review-only context

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `9e8ebdaa63a6365c742754f9e2555813f348a3cb`. Prior GA UI-75 source `6291c341d9aa717f56f8296e4a70c0d9af59e87a`, publication `9b3691c9063bf74815b1fb7405e64f7f17a62e40`. **Exact private GA UI-76 source commit:** `77e4f4431f2749a9f3324e6339730b8b55a22588`; updated XAML blob `fd0f6586aa733b9ecc924d8de033ad98ae4687c7`. Owned paths only: `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. No builds, tests, xUnit, replays, holdouts, CI, GitHub Actions, runners, benchmarking, capture or running-WPF screenshots; authored/executed tests **0/0**. All scenarios below are **PLANNED ONLY — UNEXECUTED**.

### Approved reference, starting divergence and original consumers

**FIRST** resolved and visually inspected exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (native 1672×941 image; ledger's original visual reference described 1648×928). The concept depicts navy/graphite surfaces, cyan/teal accents, left navigation, operational KPIs, local traffic chart, prioritized incidents, investigation, dense Live Events and illustrative terminal panel. All screenshot IPs, Mbps lines, metrics, rule IDs, timestamps and confidence values are **DEMO ONLY**. No fabricated telemetry, capture-health state, or working CLI; existing CLI remains explicitly **UNAVAILABLE** visual-only.

Starting HEAD follows GA UI-75 publication by two independent R552 NTP rule source/tests/docs commits `95857da83ab80faec3f5659e6469859ca1d8701c` and `9e8ebdaa63a6365c742754f9e2555813f348a3cb`; their files are independent and not modified. Inspected live recent commits and ledger through UI-75; audited `MainWindow.xaml`, `Theme.xaml`, `Sidebar.xaml`, and original `MainWindow.Dashboard.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.Settings.cs`, `MainWindow.Navigation.cs`, `MainWindow.Plots.cs` and `MainWindow.xaml.cs` partials. `DashboardActionItemsControl` is populated from `_dashboardActionRows`; its source `SocActionVm` rows represent local incident suggestions (badges `#1` etc. are list positions), anomaly review suggestions (badges can be local risk scores), or baseline-learning guidance (no numeric badge). No item executes remediation. Existing panel header information glyph and tooltips describe this but require discovery; the screenshot-inspired panel should visibly distinguish informational guidance from actionable buttons.

### One cohesive UI-owned readability enhancement

Add a single **visible muted, wrapping status line** directly below the existing `Recommended Actions` heading: **“Review suggestions only · no automatic remediation”**. Reuse existing `TinyStatusText` style, retain the existing header, source-driven row text, icons, badges, tooltips, item template, scroll viewer, bindings, and all navigation/handlers. This is a visible at-a-glance distinction between informational review suggestions and the adjacent real `Raw / Advanced Shortcuts` buttons; it does not repeat prior UI-54's truncated-row tooltips or UI-36's hover/focus explanation. No new focus stop, button, remediation, capture, data producer, model, shared API, viewmodel, or security behavior. No other source file changed.

Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024; local PPS ScottPlot optional 10-sample average and bounded 120-point history; prioritized incidents and investigation; read-only local Live Events 80 displayed/500 retained; Cisco/WebView2/ScottPlot; unavailable visual-only CLI; capture/privacy/trust boundaries and independent detection/protocol streams.

### Static end review, publication and deferred risks

Source commit `77e4f4431f2749a9f3324e6339730b8b55a22588` is a direct child of pinned starting HEAD `9e8ebdaa63a6365c742754f9e2555813f348a3cb` and changes only `Carthago/Views/MainWindow.xaml`. Documentation commit is its direct child and changes only this ledger. The XAML edit adds one non-interactive TextBlock with an existing theme style and no x:Name, event, binding or contract changes. Re-read LIVE remote HEAD **immediately before publication** and compare concurrent detection/protocol/UI changes. Publish complete two-commit chain with **one non-forced atomic GitHub `update_ref` with `expected_sha` lease** on the same branch. If moved, reconcile disjoint paths on a fresh base and fresh lease; STOP on overlap, conflict or missing atomic guarantee. After publication verify remote HEAD, commit ancestry, exact blobs, only two owned changed paths, preserved independent R552 work and zero test execution.

**Unverified risks:** Windows WPF XAML parsing/compilation; caption line wrapping and contrast; fixed 202px Wide panel and 210/216px Standard/Compact panel heights with existing 118px maximum action scroll viewer; text clipping or scrolling at 1440/1100/1099/1024/1023/640px, 125–200% DPI and high-contrast themes; screen-reader announcement order, readability and keyboard focus continuity; long suggested-action titles and badge semantics. Static inspection does **not** prove rendering, accessibility or successful compilation.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED OR EXECUTED

1. Inspect Wide >=1440px Recommended Actions header, visible muted caption and unmodified row/badge hierarchy.
2. Inspect Standard 1100–1439px and Compact 1024–1099px for caption wrapping, unobscured list rows and scroll controls.
3. Inspect 1023px and 640px widths for graceful wrapping and no unintended horizontal clipping.
4. Inspect 125%, 150%, 200% DPI and standard/high-contrast themes for legibility and fixed-panel containment.
5. Inspect incident-backed rows: badge `#n` remains list position, not risk or confidence; caption remains accurate.
6. Inspect anomaly-backed rows: local risk badge remains unchanged and caption does not imply automated remediation.
7. Inspect baseline-learning fallback: no fabricated active incidents, numeric scores or capture-health claims.
8. Use keyboard and screen reader through Recommended Actions and adjacent Raw/Advanced buttons; ensure no new focus stop or misleading action semantics.
9. Inspect unchanged PPS average/history, operational KPIs, incidents/investigation, Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot, privacy/capture/trust and independent R552 files.
10. Inspect final source/docs blobs, direct-parent commits, exact owned-path diff, expected-SHA publication lease and **zero** builds/tests/replays/CI/runners/benchmarks/capture.

**Next independent UI GA UI-77:** inspect fresh LIVE HEAD, exact approved image, ledger and original WPF consumers; choose one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–76. Acceptance remains deferred until the owner explicitly says **“now it is test time.”**

## GA UI-77 — Live Events: visible keyboard focus across the local filter toolbar

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `bd0c37fc3f8383a61e6bd5fb80e6a69e1927bb47`. Previous GA UI-76 source `77e4f4431f2749a9f3324e6339730b8b55a22588`, publication `63adc5f2eee48b8019f7ae5b713c6a4ee50f041c`. **Exact GA UI-77 source commit:** `5971452d357da0dd9c9c37b5d6772aacc2c3d512`; source XAML blob `369b1f8163c82b1443c00d89987c0b66ad5988c4`. Owned paths only: `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **ZERO** builds, dotnet tests, xUnit, replays, holdouts, CI, GitHub Actions, runners, benchmarks, production capture, running-WPF screenshots or authored/executed tests. All acceptance below is **PLANNED ONLY — UNEXECUTED**.

### Exact approved design reference and initial static divergence review

**FIRST** retrieved and visually inspected the exact ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`. The approved concept depicts navy/graphite surfaces, cyan/teal accents, persistent left navigation, operational KPIs, traffic plot, prioritized incident queue, investigation, a compact Live Events filter row and dense table. Its IP addresses, metrics, rule IDs, timestamps, confidence, Mbps lines and terminal text are **DEMO ONLY**, not verified telemetry, capture health or executable CLI. Preserve the existing explicitly **UNAVAILABLE** visual-only CLI.

Starting HEAD is exactly **one independent R553 cross-subnet SMB2 WRITE request-fanout detection source/tests/docs commit** (`bd0c37fc3f8383a61e6bd5fb80e6a69e1927bb47`) after GA UI-76 publication; comparison shows **no UI-owned path overlap**. Read recent live commits, ledger through UI-76, `MainWindow.xaml`, `Theme.xaml`, `Sidebar.xaml`, and original `MainWindow.DashboardEvents.cs`, `MainWindow.Dashboard.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.Core.cs`, `MainWindow.Settings.cs`, `MainWindow.xaml.cs`, and `MainWindow.Navigation.cs` consumers. The local events producer and filtering remain in `MainWindow.DashboardEvents.cs`; four named filters drive the existing severity/protocol/rule/search projection. `DashboardLiveEventsGrid` is read-only and bounded to 80 displayed rows from up to 500 retained local records. No new shared contract, producer, viewmodel, data source, control handler, settings writer or API is needed.

### One cohesive UI-owned accessibility/visual-consistency enhancement

The GA UI-75 subdued toolbar groups four existing input controls and a Clear filters button. The Clear filters button already inherits `KeyboardFocusVisual` from the theme's `PrimaryButton` / `SecondaryButton` style, while the four inputs have no explicit keyboard-focus visual in their XAML and the theme's custom ComboBox template has no dedicated focus trigger. Assign the **existing** `FocusVisualStyle="{StaticResource KeyboardFocusVisual}"` to exactly four existing controls: `DashboardLiveSeverityFilter`, `DashboardLiveProtocolFilter`, `DashboardLiveRuleFilter`, and `DashboardLiveSearchFilter`. This makes their intended keyboard focus presentation consistent with the already-styled Clear button without changing the shared theme or global controls. The existing 2px `KeyboardFocusBrush` focus-adorner template is reused; no new color, label, button, focus stop or visual control is introduced. This is distinct from GA UI-15's grid-cell focus outline, GA UI-40/56's filter scope/tooltips, and GA UI-75's toolbar grouping.

Source diff: **four attribute additions, zero deletions** in `MainWindow.xaml`. Existing input sizes, filter order, tooltips, AutomationProperties labels/help, ComboBox/TextBox handlers, selection and filtering logic, wrapping `WrapPanel`, grid, status and provenance remain unchanged. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024; local PPS ScottPlot 10-sample average/120-point history; prioritized incidents, investigation, read-only local Live Events 80/500, Cisco/WebView2/ScottPlot, privacy/capture/trust boundaries and independent detection/protocol streams. No fabricated telemetry or capture health.

### Static end review, publication guard and unverified risks

Private source commit `5971452d357da0dd9c9c37b5d6772aacc2c3d512` is a direct child of pinned baseline `bd0c37fc3f8383a61e6bd5fb80e6a69e1927bb47` and changes **only** `Carthago/Views/MainWindow.xaml` (four additions). The private documentation descendant changes **only** this ledger. Re-read LIVE remote HEAD immediately before publication; compare any intervening detection/protocol/UI paths. Publish the complete two-commit chain via **one non-forced atomic GitHub `update_ref` with `expected_sha` lease** on the same branch. If HEAD moved, reconcile only disjoint paths against a fresh HEAD and new expected-SHA lease; STOP on overlap, conflicts or missing atomic guarantee. After publication inspect remote HEAD, direct-parent ancestry, both file blobs, exact owned-path diff, independent R553 preservation and zero test execution.

**Unverified risks:** WPF XAML parsing/compilation; whether WPF actually renders a `FocusVisualStyle` adorner on the custom-templated ComboBoxes and standard TextBoxes; 2px outline visibility/contrast against the toolbar; focus-adorner clipping at the toolbar Border or WrapPanel edges; keyboard vs pointer focus distinctions; tab sequence and assistive reading order; filter popup focus return; high-contrast themes, 125–200% DPI, 1440/1100/1099/1024/1023/640px widths, and disabled/empty states. Static inspection is **not** Windows rendering, accessibility or compilation verification.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED OR EXECUTED

1. At 1440px, keyboard Tab/Shift+Tab across Severity, Protocol, Rule, Search and Clear; inspect intended consistent visible focus outline without new stops.
2. At 1100/1099/1024/1023/640px, inspect wrapped toolbar controls and focus-adorner containment at row and Border edges.
3. At 125%, 150%, 200% DPI, inspect 2px focus outline visibility and control alignment.
4. Inspect standard/high-contrast themes for readable, non-clipped keyboard focus and adequate distinction from hover/selection.
5. Open and close both ComboBox popups using keyboard; inspect focus return, selected value and existing filter semantics.
6. Type and clear both TextBox filters using keyboard; inspect unchanged rule/search projection, caret, focus and tooltip presentation.
7. Use Clear filters and verify existing four-filter reset, no retained-event deletion and unchanged focus order.
8. Inspect read-only grid, frozen first column, empty/no-match states, status/provenance and 80 displayed/500 retained boundaries.
9. Inspect unchanged operational KPIs, PPS average/history, prioritized incidents/investigation, unavailable CLI, Cisco/WebView2/ScottPlot, privacy/capture/trust and independent R553 files.
10. Inspect final source/docs blobs, two direct-parent commits, exact owned-path diff, fresh expected-SHA publication lease and **zero** builds/tests/replays/CI/runners/benchmarks/capture.

**Next independent UI GA UI-78:** inspect fresh LIVE HEAD, exact approved reference, ledger and original WPF consumers; choose one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–77. All acceptance remains deferred until owner explicitly says **“now it is test time.”**

## GA UI-78 — Live Events: subdued horizontal row guides for dense table scanning

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `a4f4f4807a7541dbbba37ba54d6642c53ae1a58a`. Prior GA UI-77 source `5971452d357da0dd9c9c37b5d6772aacc2c3d512`, published documentation HEAD `66cb4863f6051bd4c2f7e9832760cb34199350aa`. **Private source commit:** `9606aee37ec16fc69d4dcb9ea5935acd97199d2c`; updated `MainWindow.xaml` blob `32e7468352981d2f19bc6796a22bd96c224c583b`. Owned paths only: `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. No dotnet builds/tests, xUnit, replays, holdouts, CI, GitHub Actions, runners, benchmarks, production capture, running-WPF screenshots or acceptance tests were executed; **zero authored and zero executed tests**. All scenarios below are **PLANNED ONLY — UNEXECUTED**.

### Approved reference, baseline and original WPF consumers

**FIRST** resolved and visually inspected exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`. The concept has deep navy/graphite surfaces, cyan/teal highlights, restrained red/amber severity, persistent left navigation, operational KPI strip, traffic chart, incident triage and investigation, and a dense events table with subtle horizontal row boundaries. Screenshot IPs, metrics, Mbps series, rule IDs, timestamps, confidence and terminal text are **DEMO ONLY**. The image does not establish live capture, current telemetry or a functioning CLI. The existing CLI is explicitly **UNAVAILABLE**, visual-only.

Compared the live branch with GA UI-77 publication: exactly one intervening independent R554 SMB2 WRITE-to-FTP detection source/tests/docs commit `a4f4f4807a7541dbbba37ba54d6642c53ae1a58a`; no UI-owned overlap. Inspected recent commits, design ledger through UI-77, `MainWindow.xaml`, `Theme.xaml`, `Sidebar.xaml`, and existing `MainWindow.DashboardEvents.cs`, `MainWindow.Dashboard.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.Core.cs`, `MainWindow.xaml.cs`, `MainWindow.Navigation.cs`, `MainWindow.Settings.cs` and `MainWindow.Plots.cs` partials. The Live Events grid is read-only, single-selection, 27px rows, 30px column headers, with first column frozen, recycling virtualization, and no row actions. `MainWindow.DashboardEvents.cs` projects at most 80 displayed events from at most 500 retained local detections using existing four filters and status/provenance text. The global theme already defines `SoftDividerBrush`, alternating row backgrounds and selection/hover backgrounds; `DashboardLiveEventsGrid` alone explicitly suppressed all grid lines.

### One cohesive UI-owned visual-consistency improvement

On the existing `DashboardLiveEventsGrid` only, replace `GridLinesVisibility="None"` with `GridLinesVisibility="Horizontal"` and explicitly set `HorizontalGridLinesBrush="{StaticResource SoftDividerBrush}"`. This restores quiet horizontal row boundaries within the dense local events table, echoing the approved concept while retaining existing alternating row backgrounds, hover/selection colors and the theme's keyboard-only cell focus visual. It is distinct from UI-72's **High-Risk Hosts** row separators, UI-75's **filter toolbar** grouping and UI-77's **filter input** focus visibility; no global DataGrid or other table is changed.

Exactly one XAML attribute value changes and one XAML attribute is added. No new focusable element, command, event handler, binding, viewmodel, telemetry, data source, model, API, rule or shared resource. Preserve original column widths, row/header heights, grid virtualization, first-column freeze, read-only behavior, filters, 80/500 limits, empty state, and status/provenance. Preserve Wide >=1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024; local PPS ScottPlot 10-sample average and bounded 120-point history, prioritized incidents, investigation, Cisco/WebView2/ScottPlot, capture/trust/privacy boundaries and independent detection/protocol streams.

### Static end review, publication guard and deferred risks

Private source commit `9606aee37ec16fc69d4dcb9ea5935acd97199d2c` is a direct child of pinned baseline `a4f4f4807a7541dbbba37ba54d6642c53ae1a58a`, changes only `Carthago/Views/MainWindow.xaml` and retains unrelated R554 files. Its private documentation descendant changes only this ledger. Before publication, re-read LIVE remote HEAD and compare intervening detection/protocol/UI paths. Publish the complete two-commit candidate with exactly **one non-forced atomic GitHub `update_ref` using `expected_sha` lease** on the same branch. If HEAD moved, reconcile only disjoint paths against a fresh base and fresh lease; STOP on overlap, conflicts or missing atomic guarantee. After publication, inspect HEAD, direct-parent ancestry, exact file blobs, owned-path diff, and independent work. Static review does not establish runtime success.

**Unverified risks:** Windows WPF XAML parsing/compilation; actual visibility and thickness of 1px-style horizontal grid lines with 27px rows; interaction with alternating/hover/selected row backgrounds, frozen first column and cell focus adorner; visual density and contrast in standard/high-contrast themes; DPI scaling 125–200%; 1440/1100/1099/1024/1023/640px widths, horizontal/vertical scrolling, virtualization recycling and empty/no-match states. No actual Windows rendering or accessibility checks were performed.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED OR EXECUTED

1. At >=1440px, inspect restrained horizontal guides between existing read-only Live Events rows and unchanged header hierarchy.
2. At 1100/1099/1024/1023/640px, inspect row-guide continuity, frozen Event time column and horizontal scrolling.
3. At 125%, 150% and 200% DPI, inspect line thickness, alignment and dense 27px row readability.
4. Inspect standard/high-contrast themes for divider visibility without overwhelming text or severity labels.
5. Inspect alternating row backgrounds, mouse hover and selected-row contrast against new horizontal guides.
6. Keyboard-navigate grid cells; inspect existing focus adorner, single-row selection and screen-reader reading order.
7. Populate, filter and clear existing events; verify source-driven no-event/no-match overlay and unchanged 80 displayed/500 retained behavior.
8. Scroll virtualized rows vertically/horizontally; verify recycled row guides and unchanged first-column freeze.
9. Inspect unchanged KPIs, local PPS average/history, prioritized incidents, investigation, unavailable CLI, Cisco/WebView2/ScottPlot, privacy/capture/trust and independent R554 files.
10. Inspect final source/docs blobs, direct-parent commits, exact two owned paths, fresh expected-SHA publication lease and **zero** builds/tests/replays/CI/runners/benchmarks/capture.

**Next independent UI GA UI-79:** inspect fresh LIVE HEAD, exact approved image, ledger and original WPF consumers; choose one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–78. Acceptance remains deferred until the owner explicitly says **“now it is test time.”**

## GA UI-79 — Live Events: visually grouped status and provenance footer

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE branch `feature/carthago-reliability-hardening` HEAD: `0ec50f7fa45cb1c580239214356d45a3422d8f86`. Previous GA UI-78 source `9606aee37ec16fc69d4dcb9ea5935acd97199d2c`, publication `383d2f04391dbe36d9ba96ce3b2592d360cc85c3`. **Exact GA UI-79 source commit:** `189f02b3aae63bbbd5c3c06c49c86e5b250dd304`; source XAML blob `78b2c1709ca19889682ecbf55cd967d832a1c311`. Authorized paths only: `Carthago/Views/MainWindow.xaml` and this design ledger. **ZERO** dotnet builds, xUnit tests, replays, holdouts, CI, GitHub Actions, runners, benchmarks, production capture, running-WPF screenshots or authored/executed acceptance tests. All scenarios below are **PLANNED ONLY — UNEXECUTED**.

### Reference, divergence and original consumers

**FIRST** retrieved and visually inspected exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928). The concept uses navy/graphite surfaces, cyan/teal accents, restrained severity, left navigation, KPIs, traffic chart, incident queue, investigation and a compact read-only Live Events table. Screenshot IPs, metrics, rule IDs, timestamps, confidence, Mbps traces and terminal text are **DEMO ONLY**, not observed telemetry or capture health. CLI remains explicitly **UNAVAILABLE** and visual-only.

Compared starting live HEAD with GA UI-78 publication: exactly one disjoint independent R555 external FTP upload-command subnet-fanout rule source/tests/docs commit `0ec50f7fa45cb1c580239214356d45a3422d8f86`; no UI-owned paths changed. Reviewed recent branch commits, design ledger through UI-78, `MainWindow.xaml`, `Theme.xaml`, `Sidebar.xaml`, and the existing `MainWindow.Dashboard.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.Plots.cs`, `MainWindow.Core.cs` and `MainWindow.xaml.cs` consumers. The original `MainWindow.DashboardEvents.cs` updates two named TextBlocks with local shown/retained counts, capture-status caveat, demo provenance and evidence/delivery qualifications; filters remain four local inputs and the grid remains read-only, at most 80 displayed from 500 retained. No new data, binding, shared contract, producer, handler, viewmodel or service is required.

### One cohesive UI-owned visual hierarchy improvement

Within the existing Live Events panel, enclose the **unchanged** `DashboardLiveEventsStatusText` and `DashboardLiveEventsProvenanceText` in one quiet, non-interactive footer `Border` (existing `PillBgBrush`, `SoftDividerBrush`, 1px border, 6px corners, 10×7 padding). Keep both text blocks' names, initial text, existing source-updated values, `AutomationProperties.LiveSetting`, foregrounds, font sizes, wrapping, and the 3px interline gap. The footer visually groups observed-local-count/capture caveats with their provenance without presenting them as verified evidence. This is distinct from UI-13's source status, UI-47's evidence/delivery cell guidance, UI-71's no-rows overlay, UI-75's filter toolbar and UI-78's table row guides. The approved screenshot's dense, quiet table hierarchy remains the design reference, not a telemetry specification.

Only `Carthago/Views/MainWindow.xaml` changes in the source commit; no theme, global control, layout breakpoint, event consumer, filter, row, test, detection or protocol path changes. Preserve Wide ≥1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024; local PPS ScottPlot 10-sample average and bounded 120-point history, prioritized incidents, investigation, Cisco/WebView2/ScottPlot, read-only Live Events 80/500, unavailable CLI, and privacy/capture/trust boundaries.

### Static end review, publication guard and unverified risks

Private source commit `189f02b3aae63bbbd5c3c06c49c86e5b250dd304` is a direct child of pinned baseline `0ec50f7fa45cb1c580239214356d45a3422d8f86` and changes only `Carthago/Views/MainWindow.xaml`; its private documentation descendant changes only this ledger. Before publication, re-read LIVE remote HEAD, compare any intervening rule/protocol/UI changes, and publish the **complete** two-commit candidate via **one non-forced atomic GitHub `update_ref` with `expected_sha` lease** on the same branch. If HEAD moved, reconcile only disjoint paths against a fresh baseline/lease; STOP on overlap, conflict or missing atomic guarantee. After publication inspect final remote HEAD, direct-parent ancestry, both published blobs, exact owned-path diff and independent R555 preservation. Static review does **not** establish compilation, actual rendering, accessibility or correct runtime behavior.

**Unverified risks:** WPF XAML parsing; actual footer visibility and contrast; 1px border appearance at 125–200% DPI and high contrast; the added 14px vertical padding plus 2px border may increase panel height and push lower content down; wrapping of long status/provenance lines at 1440/1100/1099/1024/1023/640px; keyboard and assistive reading order; empty/no-match overlay interaction, horizontal scrolling and virtualization. No running-WPF screenshot or test was executed.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED OR EXECUTED

1. At ≥1440px inspect quiet separation of event rows, footer status and provenance; confirm the footer does not resemble a verified-capture badge.
2. At 1100/1099/1024/1023/640px inspect wrapping, footer border containment and vertical dashboard scrolling.
3. At 125%, 150%, 200% DPI inspect padding, 1px border and text legibility.
4. In standard/high-contrast themes inspect subdued contrast and clear status/provenance hierarchy.
5. With zero events and with non-matching filters inspect the existing empty/no-match overlay and readable footer.
6. With local rows and capture Monitoring/Degraded/Offline inspect unchanged source-driven status text, not inferred capture health.
7. With demo mode enabled inspect unchanged demo-provenance text and no fake events from this presentation change.
8. Keyboard/assistive review: no new focus stop, unchanged grid/filters/reading order and two original named TextBlocks.
9. Inspect unchanged KPIs, PPS average/history, incident queue, investigation, read-only 80/500 events, unavailable CLI, Cisco/WebView2/ScottPlot, privacy/capture/trust and R555 independent files.
10. Inspect exact source/docs blobs, two direct-parent commits, owned-path-only diff, fresh expected-SHA lease and **zero** builds/tests/replays/CI/runners/benchmarks/capture.

**Next independent UI GA UI-80:** inspect fresh LIVE HEAD, exact approved image, ledger and original WPF consumers; choose one new cohesive UI-owned accessibility/readability/visual-consistency improvement outside UI-01–79. All acceptance remains deferred until owner explicitly says **“now it is test time.”**

## GA UI-80 — Prioritized triage: readable local snapshot and dynamic provenance at narrow widths

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `8ba88290449ed56afe1cd11006d5884fa5a9e3cc`. Previous GA UI-79 source `189f02b3aae63bbbd5c3c06c49c86e5b250dd304`, publication `8dac306cc76696f7cb399fe6a4be3cb284376260`. The intervening independent R556 external SMB2 write subnet-fanout detection candidate `8ba88290449ed56afe1cd11006d5884fa5a9e3cc` was already on the branch and remains untouched. **Exact private UI source commit:** `058bbced9ba0f5fb3d3f6033947631625f9f19d9`; updated `MainWindow.xaml` blob `096d72402596addf73a07dc6aa9184cbab73057a`. Owned paths: only `Carthago/Views/MainWindow.xaml` and this ledger. **ZERO** builds, dotnet tests, xUnit, replays, holdouts, CI, GitHub Actions, runners, benchmarks, production capture, running-WPF screenshots, authored or executed acceptance tests. All scenarios below are **PLANNED ONLY — UNEXECUTED**.

### Approved image, starting divergence and original consumers

**FIRST** resolved and visually inspected the exact ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928). Its navy/graphite/cyan/teal security overview uses a persistent left nav, operational KPI strip, network chart, prioritized incident queue, investigation and dense read-only events. Screenshot IPs, metrics, rule IDs, timestamps, confidence, Mbps traces and CLI text are **DEMO ONLY**. The image does not establish live capture, packet reception, telemetry or a functioning CLI; Carthago's companion remains explicitly **UNAVAILABLE** and visual-only.

Reviewed live HEAD and recent commits, ledger through UI-79, `MainWindow.xaml`, `Theme.xaml`, `Sidebar.xaml`, and existing `MainWindow.Dashboard.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.Core.cs`, `MainWindow.Plots.cs`, `MainWindow.Navigation.cs`, `MainWindow.Settings.cs`, and `MainWindow.xaml.cs` partials. The existing `RefreshSocDashboardWorkspace` writer updates `DashboardAnomalyFooterText.Text` with an honest bounded local queue count, unresolved incidents (max 150), anomaly signals (max 160), and conditional `demo data may be included` provenance. The original triage panel uses a fixed 404px dashboard grid with Auto caption/footer rows and a star-sized list row. No new producer, handler, shared API, model, service or viewmodel is required.

### One cohesive UI-owned readability improvement

The long static `LOCAL SNAPSHOT · INCIDENTS BY RISK, THEN SIGNALS` caption previously used `TextTrimming="CharacterEllipsis"`; the source-driven `DashboardAnomalyFooterText` had no wrapping or full-text hover. At narrower panel widths, either may truncate critical ranking or demo-provenance context. Change only these **two existing triage text blocks**: allow the static queue caption to wrap rather than ellipsize, and allow the dynamic footer to wrap while exposing its **actual current Text** in a noninteractive hover tooltip. No new copy, color, data, focus stop, handler, event, selection, filter, navigation, layout breakpoint or evidence claim. The footer's existing `x:Name` and `AutomationProperties.ItemStatus` consumer remain intact. The wrapping is distinct from UI-04's triage content/ordering, UI-51's local-clock timestamp guidance, UI-74's row hover/selection and UI-79's Live Events footer surface.

Source diff: **only** `Carthago/Views/MainWindow.xaml`, 4 additions and 2 deletions. Preserve navy/graphite/cyan/teal, restrained severity, left nav, KPI cards, prioritized incident selection and investigation, local PPS ScottPlot 10-sample average and 120-point history, read-only local Live Events 80 displayed/500 retained, explicitly unavailable visual-only CLI, Wide ≥1440/Standard 1100–1439/Compact 1024–1099 and graceful below 1024, Cisco/WebView2/ScottPlot, privacy/capture/trust and independent rule/protocol streams.

### Static end review, publication lease and remaining risks

Private source commit `058bbced9ba0f5fb3d3f6033947631625f9f19d9` is a direct child of `8ba88290449ed56afe1cd11006d5884fa5a9e3cc`; its comparison changes **only** the XAML file. The private documentation descendant changes **only** this ledger. Recheck LIVE remote HEAD immediately before publication, compare any intervening detection/protocol/UI paths, and publish the **complete** two-commit chain via exactly **one non-forced atomic GitHub `update_ref` with `expected_sha` lease** on the same branch. If moved, reconcile only disjoint paths on a fresh HEAD and lease; STOP on overlap, conflict or missing guarantee. After publication inspect final HEAD, direct-parent ancestry, both file blobs, exact two-file scope and independent R556 preservation.

**Unverified risks:** Windows XAML parsing/compilation; actual text wrapping and contrast; a longer footer may consume more height within the fixed 404px triage grid, reducing the star-sized incident list viewport; scroll/selection focus containment; hover tooltip availability and keyboard/assistive reading order; standard/high-contrast themes, 125–200% DPI and 1440/1100/1099/1024/1023/640px widths. Static source review is not Windows rendering, accessibility verification or test evidence.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED OR EXECUTED

1. At ≥1440px, inspect the triage caption and source-driven footer for readable hierarchy without unnecessary crowding.
2. At 1100/1099/1024/1023/640px, inspect caption/footer wrapping and absence of clipped ranking/demo provenance.
3. At 125%, 150%, 200% DPI, inspect Auto rows, list viewport, vertical scrolling and 404px triage containment.
4. Inspect standard/high-contrast themes for muted text legibility and no color-only meaning.
5. With no incidents/signals, inspect the original honest empty-snapshot footer message without truncation.
6. With bounded unresolved incidents and anomaly signals, inspect exact current counts and the full hover tooltip.
7. With demo mode enabled, inspect the unchanged conditional `demo data may be included` text and its full tooltip; never infer that individual events are live.
8. Keyboard/screen-reader inspection: unchanged ListBox item status, selection/focus, original TextBlock names and no new tab stop.
9. Inspect unchanged KPIs, local PPS averaging/history, incident detail, read-only Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot, privacy/capture/trust and independent R556 files.
10. Inspect published source/docs blobs, direct-parent ancestry, exact owned-path diff, fresh expected-SHA lease and **zero** builds/tests/replays/CI/runners/benchmarks/capture.

**Next independent UI GA UI-81:** inspect fresh LIVE HEAD, exact approved image, ledger and original WPF consumers; choose one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–80. Acceptance remains deferred until the owner explicitly says **“now it is test time.”**

## GA UI-81 — High-Risk Hosts: keyboard-discoverable related-item and activity column guidance

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `e4a3b2a38682a3a4b6c1b7ae2a2064aec632179e`. Previous GA UI-80 source `058bbced9ba0f5fb3d3f6033947631625f9f19d9`, publication `ddaea2f88f042713a1fc50bfe5a7400c10107b17`. One intervening independent R557 outbound Modbus write public-subnet fanout candidate `e4a3b2a38682a3a4b6c1b7ae2a2064aec632179e` (rule source, registration, tests and rule documentation) was already on the branch and is **not modified**. **Exact private UI source commit:** `b94c6e11b4e9bddae86e1dcf1ead7115bb82ffd8`; updated `MainWindow.xaml` blob `405d91a47c2db2fafab6f91319f682d444a57e92`. Owned paths: only `Carthago/Views/MainWindow.xaml` and this ledger. **ZERO** dotnet builds/tests, xUnit, replays, holdouts, CI, GitHub Actions, runners, benchmarks, production capture, running-WPF screenshots, or authored/executed acceptance tests. All scenarios below are **PLANNED ONLY — UNEXECUTED**.

### Approved image, start divergence and source consumers

**FIRST** resolved and visually inspected exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928). The image guides the navy/graphite/cyan/teal visual hierarchy, restrained severity, left navigation, KPIs, traffic chart, prioritized incident queue, investigation and dense local events. Screenshot IPs, rule IDs, confidence, timestamps, Mbps and CLI content are **DEMO ONLY**, never live telemetry, capture health or verified evidence. The CLI remains explicitly **UNAVAILABLE** and visual-only.

Read the live HEAD and recent branch commits, ledger through UI-80, `MainWindow.xaml`, `Theme.xaml`, `Sidebar.xaml`, and original `MainWindow.Dashboard.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.Core.cs` and `MainWindow.xaml.cs` partials. `BuildSocHostRows()` groups unresolved correlated incidents by source IP (fallback to grouped anomaly signals only when no incident hosts exist), limits the panel to five rows, calculates maximum local risk, related-item counts and relative 60-minute activity glyphs. `SocHostVm.ActivityAccessibilityLabel` specifies eight timestamp buckets, not packet traffic or a risk trend. The `KeyboardFocusVisual` resource already exists in `Theme.xaml`. The existing two column-header tooltips were mouse-hover-only; their source-specific explanations were not directly discoverable through keyboard focus.

### One cohesive UI-owned accessibility enhancement

Make only the existing **Items** and **Activity** column-header `TextBlock` elements keyboard-focusable/tab stops; apply the existing `KeyboardFocusVisual` and `ToolTipService.ShowsToolTipOnKeyboardFocus`, and add concise, source-accurate `AutomationProperties.Name` and `AutomationProperties.HelpText` to each. Preserve the exact visible header captions, original hover tooltip text, column widths, host row template, risk/count/activity values, ordering, colors, event handlers and bindings. **Items** is correlated incident count or fallback anomaly signal count, not packet count. **Activity** is eight relative buckets of incident last-update or anomaly creation timestamps across 60 minutes, not a traffic chart, absolute event count or risk trend. This is distinct from UI-29's per-row sparkline description, UI-53's numeric-cell guidance and UI-72's row separators: it exposes existing column-header meaning to keyboard users without introducing commands or producers.

Source diff: **only** `Carthago/Views/MainWindow.xaml` (15 additions, 2 deletions). No viewmodel, theme, global resource, partial, service, shared API, engine, detection/protocol source, rule documentation or tests changed. Preserve Wide ≥1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024; local PPS ScottPlot 10-sample average and bounded 120-point history; prioritized incidents and investigation; read-only local Live Events 80 displayed/500 retained; unavailable CLI; Cisco/WebView2/ScottPlot; privacy/capture/trust boundaries and independent streams.

### Static end review, publication guard and remaining risks

Private source commit `b94c6e11b4e9bddae86e1dcf1ead7115bb82ffd8` is a direct child of pinned baseline `e4a3b2a38682a3a4b6c1b7ae2a2064aec632179e`; comparison shows only the XAML file. Its private documentation descendant changes only this ledger. Before publication, re-read LIVE remote HEAD and compare intervening detection/protocol/UI paths. Publish the **complete** two-commit chain using exactly **one non-forced atomic GitHub `update_ref` with `expected_sha` lease** on the same branch. If moved, reconcile only disjoint paths against a fresh baseline and lease; STOP on conflict, overlap or missing guarantee. After publication inspect final remote HEAD, direct-parent ancestry, both published blobs, two-file ownership diff and preservation of R557.

**Unverified risks:** WPF XAML compilation and actual rendering; whether a focus visual and keyboard-triggered tooltip appear on a focusable `TextBlock` in the custom dashboard; potential extra Tab stops in a dense host panel; keyboard traversal, screen-reader announcement and tooltip dismissal; header focus-ring clipping in 62px/84px columns; high-contrast themes, 125–200% DPI, and 1440/1100/1099/1024/1023/640px widths. Static review is not compilation, rendering, accessibility verification or test evidence.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED OR EXECUTED

1. At ≥1440px, inspect host header focus ring/tooltip appearance without changing the existing visible captions or column alignment.
2. At 1100/1099/1024/1023/640px, inspect focus-ring containment and responsive host panel layout without horizontal clipping.
3. At 125%, 150%, 200% DPI, inspect 62px Items and 84px Activity header focus visuals and text readability.
4. In standard/high-contrast themes, inspect focus indicator contrast and tooltip legibility.
5. Using Tab/Shift+Tab, verify the two new header stops appear in logical order and tooltip guidance is keyboard-discoverable.
6. With assistive technology, inspect the header accessible names/help text and ensure no duplicate or misleading item counts are announced.
7. With unresolved correlated incidents, inspect Items as incident counts and Activity as relative incident-update timestamp buckets.
8. With no incident hosts but anomaly signals, inspect Items as fallback anomaly signal counts and Activity as relative anomaly-creation timestamp buckets.
9. Inspect unchanged local PPS 10-sample/120-point behavior, KPIs, incident queue/investigation, Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot, privacy/capture/trust and independent R557 files.
10. Inspect final source/docs blobs, direct-parent commits, exact two owned paths, fresh expected-SHA publication lease and **zero** builds/tests/replays/CI/runners/benchmarks/capture.

**Next independent UI GA UI-82:** inspect fresh LIVE HEAD, exact approved image, ledger and original WPF consumers; choose one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–81. Acceptance remains deferred until the owner explicitly says **“now it is test time.”**

## GA UI-82 — Local PPS chart: truthful, persistent series key

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `06391978183a8356dd709f0d1c5722bc4249fe59`. Prior GA UI-81 source `b94c6e11b4e9bddae86e1dcf1ead7115bb82ffd8`, publication `06391978183a8356dd709f0d1c5722bc4249fe59`. No intervening detection/protocol changes at the initial read; the independent R557 Modbus candidate already in the baseline remains untouched. **Exact private UI source commit:** `d551064b9bf5b4e3140143cacf8ebd5a55664b28`; updated `MainWindow.xaml` blob `40d88518f5d0abc0b427b36e2b136cbfb380840e`. Owned paths: only `Carthago/Views/MainWindow.xaml` and this ledger. **ZERO** builds, dotnet tests, xUnit, replays, holdouts, CI, GitHub Actions, runners, benchmarks, production capture, running-WPF screenshots, or authored/executed acceptance tests. All scenarios below are **PLANNED ONLY — UNEXECUTED**.

### Reference, live baseline and original consumers

**FIRST** resolved and visually inspected the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928). Its navy/graphite/cyan/teal dashboard includes a visible traffic-series key beneath the chart. The screenshot's Mbps, inbound/outbound traces, rule IDs, confidence, timestamps, IPs and CLI output are **DEMO ONLY**, not Carthago telemetry or evidence. Actual WPF `TrafficPlot` displays only local timer PPS and its ten-sample average; the CLI remains explicitly **UNAVAILABLE** and visual-only.

Reviewed LIVE HEAD, recent branch commits, ledger through UI-81, `MainWindow.xaml`, `Theme.xaml`, `Sidebar.xaml`, and original WPF partials `MainWindow.Dashboard.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.Responsive.cs`, `MainWindow.Core.cs`, `MainWindow.Plots.cs`, `MainWindow.Navigation.cs`, `MainWindow.Settings.cs`, `MainWindow.xaml.cs`. In `RenderTraffic()`, the existing local PPS line is solid blue `#60A5FA`; the ten-sample moving average is dashed amber `#F59E0B` and appears only with more than ten timer samples. ScottPlot already manages its own legend when the average is drawn; this new static key makes series meaning discoverable before that threshold and independently of the plot's native legend. `DashboardTrafficChartTextSummary`, waiting overlay, monitoring status, original series/plot APIs, capture timer and all source consumers remain unchanged.

### One cohesive UI-owned visual/readability improvement

Add a compact wrapping **two-series key** immediately above the existing chart text summary in the chart's footer. Draw two decorative WPF `Line` swatches using the exact plot-series colors and solid/dashed strokes, with explicit visible labels **“Local PPS · solid blue”** and **“10-sample average · dashed amber (11+ samples)”**. Add concise UI Automation context to the containing `WrapPanel` stating that timer samples are not proof of active capture or network-wide traffic. The text does not imply the average is visible before eleven samples. The swatches are noninteractive; there are no new handlers, focus stops, producers, plot data, status claims or simulated traffic. The wrapping key follows the approved screenshot's chart/legend hierarchy without fabricating inbound/outbound or Mbps series. This differs from UI-08 chart placement, UI-10 waiting state, UI-22 accessible current summary, and UI-61 capture-state guidance.

The source-only change is **18 XAML additions, zero deletions** in `Carthago/Views/MainWindow.xaml`; the documentation is the only other changed file. Preserve navy/graphite/cyan/teal, restrained severity, left navigation, real KPI provenance, local PPS 10-sample average and bounded 120-point history, prioritized incidents and investigation, read-only local Live Events 80 displayed/500 retained, explicitly unavailable visual-only CLI, Wide ≥1440/Standard 1100–1439/Compact 1024–1099 and graceful below 1024, Cisco/WebView2/ScottPlot, privacy/capture/trust and independent detection/protocol streams.

### Static end review, publication lease and remaining risks

Private source commit `d551064b9bf5b4e3140143cacf8ebd5a55664b28` is a direct child of the pinned baseline; its comparison changes **only** `MainWindow.xaml`. The private documentation descendant changes **only** this ledger. Recheck LIVE remote HEAD immediately before publication, compare intervening detection/protocol/UI paths, and publish the **complete** two-commit chain with exactly **one non-forced atomic GitHub `update_ref` and `expected_sha` lease** on the same branch. If the remote moved, reconcile only disjoint paths against fresh HEAD; STOP on overlap, conflict or missing lease guarantee. After publication inspect final remote HEAD, direct-parent ancestry, both file blobs, exact two-file ownership diff and independent-stream preservation.

**Unverified risks:** Windows XAML parsing/compilation and actual rendering; static legend may duplicate ScottPlot's own native legend after eleven samples; additional footer height and WrapPanel wrapping at compact/narrow widths; swatch/label alignment and line-dash rendering; color/line-pattern legibility in high contrast and 125–200% DPI; UI Automation announcements on nonfocusable containers. The labels carry meaning without relying solely on color, but accessibility has **not** been verified. Static inspection does not prove WPF behavior.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED OR EXECUTED

1. At ≥1440px, inspect the two legend swatches and labels for hierarchy, matching series colors and line patterns.
2. At 1100/1099/1024/1023/640px, inspect WrapPanel reflow, plot width and no clipped labels.
3. At 125%, 150%, 200% DPI, inspect swatch alignment, footer height and chart-summary containment.
4. In standard/high-contrast themes, inspect color, solid/dashed distinctions and text readability.
5. With zero or one timer sample, inspect the original waiting overlay and the truthful static legend without asserting a plotted series.
6. With 2–10 timer samples, inspect the blue local PPS plot and absence of amber moving-average series.
7. With 11+ timer samples, inspect the dashed amber moving average, native ScottPlot legend and possible visual duplication.
8. Inspect keyboard/assistive reading order and ensure decorative lines add no Tab stops or false monitoring announcement.
9. Inspect unchanged KPI provenance, local PPS 10-sample/120-point behavior, incidents, investigation, read-only Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot, privacy/capture/trust and independent detection/protocol files.
10. Inspect final source/docs blobs, two direct-parent commits, exact two owned paths, fresh expected-SHA lease and **zero** builds/tests/replays/CI/runners/benchmarks/capture.

**Next independent UI GA UI-83:** inspect fresh LIVE HEAD, exact approved image, ledger and original WPF consumers; choose one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–82. Acceptance remains deferred until the owner explicitly says **“now it is test time.”**

## GA UI-83 — Investigation: bounded, readable local tag and rule chips

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `4dc058b6142606b249cceef369095d72013b02a4`. Previous GA UI-82 source `d551064b9bf5b4e3140143cacf8ebd5a55664b28`, publication `8c053c93cbc23b13a522b2c329e3e57cf5635d3c`. **Private UI source commit:** `d296795dd2bb0efaa848bf502fa2619c0175b52d`; new `Carthago/Views/MainWindow.xaml` blob `ae7d6c4a05fe97beba4387d331332d1a94a453f5`. Authorized changed paths: **only** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **ZERO** dotnet builds/tests, xUnit, replays, holdouts, CI/GitHub Actions, runners, benchmarks, production capture, running-WPF screenshots or executed acceptance scenarios. All scenarios below are **PLANNED ONLY — UNEXECUTED**.

### Approved design reference, starting divergence and source consumers

**FIRST** resolved and visually inspected exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928). Its navy/graphite/cyan/teal, restrained severity, left navigation, KPIs, traffic graph, incident investigation and dense event presentation remain the visual reference. Screenshot IPs, rule IDs, confidence, timestamps, Mbps and terminal output are **DEMO ONLY**, not live telemetry or capture health; the WPF CLI remains explicitly **UNAVAILABLE**, visual-only.

Read LIVE remote HEAD, recent commits, this ledger through UI-82, `MainWindow.xaml`, `Theme.xaml`, `Sidebar.xaml`, and original `MainWindow.Dashboard.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.Core.cs`, `MainWindow.xaml.cs`, `MainWindow.Plots.cs` and `MainWindow.DashboardEvents.cs`. Compared previous UI-82 publication to starting HEAD: **23 intervening commits**, changing **22 non-UI files** (independent R558/R559 rule/registry/tests/docs, protocol-inspector work and packet-fixture corrections). None changed the two UI-owned paths. They were present before this candidate and are not modified. Original `DashboardDetailTagsItems` and `DashboardDetailRulesItems` bind to source-driven `ObservableCollection<string>` values populated from selected local incident or anomaly context; the original `WrapPanel` and `ScrollViewer` remain. Related rule IDs are reported links, not detection-quality proof. No consumer, binding, producer, data model, rule registration, viewmodel or event handler is changed.

### One cohesive UI-owned readability improvement

Within the **Incident Investigation** supporting-context area, apply `MaxWidth="180"`, `TextWrapping="Wrap"` and `ToolTip="{Binding}"` to the existing **Tags** and **Related rule IDs** pill `TextBlock` templates. The per-chip width is bounded rather than allowing unusually long source-driven strings to dictate the horizontal layout; wrapping keeps the original text available in the scrollable investigation context, and the hover tooltip exposes the same complete current value. Preserve the existing `Pill` style, typography, color, source text, item counts, ordering, labels, item bindings and original selection/navigation behavior. No new focus stops, controls, network operations, fake values, commands or telemetry. This is distinct from UI-39 investigation heading full-text hover, UI-46/50 event-cell hover, UI-54 action-row hover and UI-81 host-header guidance.

Source-only comparison of `4dc058b6142606b249cceef369095d72013b02a4` to `d296795dd2bb0efaa848bf502fa2619c0175b52d` changes **only** `Carthago/Views/MainWindow.xaml` (**3 additions, 2 deletions**); the documentation descendant changes only this ledger. Preserve Wide ≥1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024; local PPS ScottPlot ten-sample average and bounded 120-point history; prioritized incidents and investigation; read-only local Live Events 80 displayed/500 retained; unavailable visual-only CLI; Cisco/WebView2/ScottPlot; privacy/capture/trust boundaries and independent detection/protocol streams.

### Static end review, publication lease and risks

Source commit `d296795dd2bb0efaa848bf502fa2619c0175b52d` is a direct child of pinned LIVE baseline `4dc058b6142606b249cceef369095d72013b02a4`. Its blob/tree are private until the complete source-plus-ledger chain is published. Recheck LIVE remote HEAD **immediately before** publication, compare any intervening detection/protocol/UI paths and publish the **complete** two-commit chain using exactly **one non-forced atomic GitHub `update_ref` with `expected_sha` lease** on the same branch. If moved, reconcile only disjoint paths on fresh HEAD and lease; **STOP** on overlap, conflict or missing lease guarantee. After publication, inspect remote HEAD, direct-parent ancestry, both published blobs, exact two-file scope and independent-stream preservation.

**Unverified risks:** WPF XAML parsing/compilation; actual wrapping of long or unbroken tag/rule strings; pill-height expansion and vertical scrolling inside the height-limited investigation card; high-contrast and 125–200% DPI readability; hover tooltip behavior and mouse-only tooltip discoverability; screen-reader announcement of source strings; 1440/1100/1099/1024/1023/640px layouts. The UI still displays existing local values, with no new disclosure source, but privacy and accessibility behavior have **not** been runtime-verified. Static source review is not test, rendering or accessibility evidence.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED OR EXECUTED

1. At ≥1440px, inspect ordinary short Tags/Related rule IDs for unchanged pill spacing, hierarchy and source text.
2. At 1100/1099/1024/1023/640px, inspect long-chip wrapping and absence of horizontal overflow or clipped neighboring panels.
3. At 125%, 150% and 200% DPI, inspect pill-height expansion, card containment and vertical scroll reachability.
4. In standard/high-contrast themes, inspect pill borders, text contrast, tooltip contrast and non-color-only meaning.
5. With long or unbroken source-driven tags, inspect the 180px width bound, full displayed value and hover tooltip.
6. With long or unbroken related rule IDs, inspect the same bound, wrapping and complete original identifier.
7. With empty Tags/Rules and fallback “No linked rule,” inspect original empty/fallback behavior and no fabricated evidence.
8. Inspect keyboard and screen-reader reading order: no added Tab stops; unchanged source values and existing group labels.
9. Inspect unchanged local PPS 10-sample/120-point behavior, KPIs, incidents, read-only Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot, privacy/capture/trust and independent R558/R559/protocol/test files.
10. Inspect published source/docs blobs, two direct-parent commits, exact two owned paths, fresh expected-SHA lease and **zero** builds/tests/replays/CI/runners/benchmarks/capture.

**Next independent UI GA UI-84:** inspect fresh LIVE HEAD, exact approved image, ledger and original WPF consumers; choose one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–83. Acceptance remains deferred until the owner explicitly says **“now it is test time.”**

## GA UI-84 — Settings: truthful API-key status and readable configuration guidance

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE `feature/carthago-reliability-hardening` HEAD: `b1644defb012918bacdff12166409229ac10cf59`. Previous UI-83 source `d296795dd2bb0efaa848bf502fa2619c0175b52d`, publication `a18354295ac0825a20d21b8fa69073fb02743957`. **Private GA UI-84 source commit:** `85b062db403d6a2be6cd45af30c86015d1239bb4` (direct child of pinned starting HEAD). **Exact source XAML blob:** `7d9ca3acae14fe04c1db8ea85adb018b3914381e`. Authorized changed paths: **only** `Carthago/Views/MainWindow.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **Zero tests authored or executed; no builds, XAML compilation, xUnit, replays, holdouts, CI/GitHub Actions, runners, benchmarking, capture, running-app screenshots or acceptance execution.** All scenarios below are **PLANNED ONLY — UNEXECUTED**.

### Approved image, live divergence and original WPF consumers

**FIRST** resolved and visually inspected the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`. Its navy/graphite/cyan/teal palette, restrained severity, left navigation, operational KPIs, traffic chart, prioritized incidents, investigation and dense event layout are the visual reference, not executable functionality. Screenshot IPs, Mbps series, confidence, metrics, rule IDs, timestamps and terminal output are **DEMO ONLY**, not live telemetry, detection proof or capture health. The actual WPF CLI remains **UNAVAILABLE**, visual-only.

Read LIVE branch HEAD/recent commits, this ledger through UI-83, `MainWindow.xaml`, `Views/Theme.xaml`, `Sidebar.xaml`, `MainWindow.Settings.cs`, `MainWindow.Dashboard.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.Core.cs`, `MainWindow.Plots.cs`, `MainWindow.Navigation.cs`, `MainWindow.Filters.cs`, `MainWindow.DataEvents.cs` and `MainWindow.xaml.cs`. Compared prior UI-83 publication to starting LIVE HEAD: **40 independent commits**, changing **31 non-UI files** across detection rules, registry, tests and validation/rule documentation. No overlap with either owned UI path; preserve these commits unchanged. The initial private chain was prepared against `19d3b7ecf3b8804b7aa1e846128aad3d7cdc0d52`, but the live branch advanced by **11 disjoint independent commits** before publication. No old candidate was published; this complete candidate was privately reconciled on the fresh baseline and requires a new lease.

The original `MainWindow.Settings.cs` `UpdateApiKeyStatus()` writes `ApiKeyStatusText.Text` from key-configuration checks; `ApplyApiKey_Click` applies a session-only override and refreshes that label. The original `AbuseIpDbApiKey` getter can fall back to an environment key, so the first status branch can label an environment-provided key **“session override active”**. This pre-existing source-provenance limitation is not repaired here; do not claim the status identifies the actual key source, verifies credentials or reports a successful lookup. Original `PasswordBox`, API-key handler, capture-service key storage, preference writers and external lookups remain untouched.

### One cohesive UI-owned accessibility/readability improvement

Within **Settings > Enrichment & Capture** only, add a ninth Auto row below the existing `ApiKeyStatusText`. Keep the original dynamic status text and writer intact; add `TextWrapping="Wrap"` and a dynamic `AutomationProperties.Name` bound to its current Text, plus source-accurate `AutomationProperties.HelpText` explaining configuration-only status and possible environment/session misclassification. Add one small, muted, wrapping **visible non-interactive caption**: “Configuration status only · not a credential validation or lookup result.” The existing warning about requiring an AbuseIPDB key also gains wrapping so its configuration guidance is less likely to be clipped at narrow widths. Reuse existing theme brushes and typography; no secret values are copied to captions, metadata, documentation or tooltips. No new controls with keyboard focus, commands, external requests, preference changes, navigation, capture behavior, handlers, viewmodels, shared APIs or security controls.

This is distinct from UI-68, which clarified the **PasswordBox and session-action controls** but explicitly left the status line unchanged, and from UI-65/66/67/69 Settings guidance on other controls. Source-only comparison from pinned baseline to private source commit changes **only** `MainWindow.xaml` (**13 additions, zero deletions**). The documentation descendant changes **only** this ledger. Preserve Wide ≥1440, Standard 1100–1439, Compact 1024–1099, graceful below 1024; local PPS ScottPlot ten-sample average and bounded 120-point history; prioritized incidents/investigation; read-only Live Events 80 displayed/500 retained; unavailable visual-only CLI; Cisco/WebView2/ScottPlot; privacy/capture/trust boundaries and independent detection/protocol streams.

### Static end review, publication lease and unverified risks

The private source commit is a direct child of starting HEAD; source blob `7d9ca3acae14fe04c1db8ea85adb018b3914381e` changes the existing XAML only. Recheck LIVE remote HEAD **immediately before** publication, compare any intervening detection/protocol/UI paths, and publish the **complete source-plus-ledger two-commit chain** with exactly **one non-forced atomic GitHub `update_ref` and matching `expected_sha` lease** on the existing branch. If moved, reconcile only disjoint paths into a fresh private chain and fresh lease; **STOP** on overlap, conflict or missing lease guarantee. After publication inspect final remote HEAD, direct-parent ancestry, published file blobs, exact two-path diff and preservation of independent streams.

**Risks — UNVERIFIED:** WPF XAML parsing/compilation; actual TextBlock UI Automation dynamic-name/HelpText behavior and announcement order; visibility and contrast of the new caption; warning/status wrapping at 1440/1100/1099/1024/1023/640px, 125–200% DPI and high-contrast themes; Settings ScrollViewer vertical reachability; status source misclassification for environment keys; no validation of credential correctness or lookup success. The note clarifies limitations but does not fix the original status producer or prove privacy, accessibility or runtime behavior. No password, secret or key material is exposed by the new XAML.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED OR EXECUTED

1. At ≥1440px, inspect Settings > Enrichment & Capture warning, dynamic key-status line and muted configuration-only caption for coherent hierarchy.
2. At 1100/1099/1024/1023/640px, inspect the warning/status/caption wrapping, absence of horizontal clipping and continued Settings scrolling.
3. At 125%, 150% and 200% DPI, inspect the extra Auto row, caption visibility, contrast and vertical scroll reachability.
4. In standard/high-contrast themes, inspect warning and caption text contrast without relying solely on color.
5. With no configured key, inspect original “not configured” status plus truthful note; do not infer lookup results.
6. With an environment-provided key, inspect the original possible “session override active” misclassification and the accessibility caveat; do not claim correct source attribution.
7. With a nonempty session override and empty input, inspect original apply/warning handlers and unchanged secret handling, without running any lookup.
8. Inspect keyboard and screen-reader reading order: no new Tab stop, current dynamic status exposed through AutomationProperties.Name, and HelpText describes status limitations.
9. Inspect unchanged local PPS 10-sample/120-point behavior, KPI provenance, incidents, read-only Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot, privacy/capture/trust and all 40 intervening independent commits.
10. Inspect final source/docs blobs, direct-parent commit chain, exact two owned paths, fresh expected-SHA lease and **zero** builds/tests/replays/holdouts/CI/runners/benchmarks/capture.

**Next independent UI GA UI-85:** inspect fresh LIVE HEAD, exact approved image, ledger and original WPF consumers; choose one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–84. Acceptance remains deferred until the owner explicitly says **“now it is test time.”**

## GA UI-85 — Signal Investigation: clipboard and navigation action clarity

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Pinned starting LIVE `feature/carthago-reliability-hardening` HEAD: `2a2fd493522d6183ea55fb46ecb83a2c4037e753`. Previous published GA UI-84 source `85b062db403d6a2be6cd45af30c86015d1239bb4`, documentation/publication `dc04e9810d673cef7f73ec3caff377d2ae651c5c`. Private GA UI-85 source commit `a8aa21565d3d9ebba2dec1f3bc6ebe19defb8bc9`, direct child of pinned starting HEAD; exact changed dialog XAML blob `b192c72607423e7ccda74be71bdd8a76f8b07f44`. Authorized paths: **only** `Carthago/Views/DashboardSignalDetailDialog.xaml` and this ledger. No tests authored or executed; **zero** builds, dotnet/xUnit, XAML compilation, replays, holdouts, CI/GitHub Actions, runners, benchmarking, production capture or running-app screenshots. Acceptance scenarios below are **PLANNED ONLY — UNEXECUTED**.

### Approved reference, divergence and original consumers

**FIRST** resolved and visually inspected exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`: restrained navy/graphite/cyan/teal security dashboard, left navigation, operational KPIs, traffic chart, prioritized incidents, investigation, dense events and illustrative CLI. All screenshot IPs, Mbps lines, rule IDs, metrics, confidence and timestamps are **DEMO ONLY**; no claim of observed telemetry or capture health. The WPF CLI remains explicitly **UNAVAILABLE** and visual-only.

Read live remote branch HEAD, recent commits, ledger through UI-84, `MainWindow.xaml`, `Theme.xaml`, `DashboardSignalDetailDialog.xaml` and its code-behind/model, `MainWindow.Dashboard.cs`, `MainWindow.Navigation.cs`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.Plots.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.Core.cs`, `MainWindow.Settings.cs` and `MainWindow.Filters.cs`. Compared UI-84 publication to starting LIVE HEAD: **39 independent commits**, affecting **14 non-UI paths** across R437 Redis rule/protocol/correlation, tests and validation documentation; neither owned path overlaps. Do not alter or discard these independent commits.

The existing `DashboardSignalDetailDialog.xaml.cs` `CopySummary_Click` calls `Clipboard.SetText(Model.BuildClipboardSummary())`, which includes local title, subtitle, risk, source/destination, protocol, category, detected time, related incident, reasons, tags, rule IDs and recommended actions. It is **not** an evidence-file export or validation; clipboard contents can be shared by users or OS-level clipboard services. `OpenAnomalies_Click` and `OpenIncident_Click` only request navigation; the original `MainWindow.Dashboard.cs` consumer handles the request via `Nav_Anomalies_Click` or `OpenIncidentWorkspace`. Buttons are enabled only for available `AnomalyId` or `IncidentId`. `Close_Click` closes the dialog without requesting navigation. No clipboard, navigation, model, evidence or security implementation is modified.

### One cohesive UI-owned improvement

In the existing **Signal Investigation modal footer**, replace only the generic static caption with source-accurate visible guidance that **Copy Summary writes local investigation context to the system clipboard** and should be reviewed before sharing; the other actions only navigate to existing views. Add descriptive hover/keyboard-focus tooltips, explicit `AutomationProperties.Name`, and tooltip-bound `AutomationProperties.HelpText` to the existing **Copy Summary**, **Open Anomalies**, **Open Incident** and **Close** buttons. Keep original captions, widths, styling, order, handlers, enablement bindings, model, data fields, clipboard contents, modal sizing, scroll behavior and tab order. No new focusable elements, commands, navigation targets, telemetry, capture, network calls, evidence export or remediation. This is distinct from UI-49 (dashboard detail triggers), UI-52 (related-incident button), UI-55 (raw shortcut destinations), UI-68 (API-key session action), and UI-76 (dashboard review-only suggestions).

Static source delta: only `Carthago/Views/DashboardSignalDetailDialog.xaml` in the source commit (one visible caption rewrite and accessibility metadata for four existing buttons). This ledger is the sole documentation change. Preserve Wide ≥1440, Standard 1100–1439, Compact 1024–1099, graceful below 1024; local PPS ScottPlot ten-sample average and 120-point bound; prioritized incidents, read-only Live Events 80 displayed/500 retained, visual-only unavailable CLI, Cisco/WebView2/ScottPlot, privacy/capture/trust and independent detection/protocol streams.

### Publication, static end review and unverified risks

Private source commit is direct child of pinned LIVE HEAD; the complete source-plus-ledger two-commit chain must be published only after **fresh** remote HEAD and concurrent-path comparison, using **one** non-forced atomic GitHub `update_ref` with matching `expected_sha` lease on the **same** branch. If moved, reconcile disjoint paths against fresh HEAD with a fresh lease; **STOP** for overlapping UI changes, conflicts or missing lease guarantee. After publication inspect remote HEAD, direct-parent ancestry, exact owned-path diff and both published blobs. Never publish partially or overwrite independent work.

**Risks — UNVERIFIED:** WPF XAML parsing/compilation; actual tooltip display on hover/keyboard focus; UI Automation Name/HelpText announcements; clipboard warning visibility and line wrapping at 1440/1100/1099/1024/1023/640px; dialog min-size and owner/work-area constraints; footer height reducing scrollable investigation space at 125–200% DPI; standard/high-contrast text and focus presentation; accessibility reading order. Existing clipboard contents can include local network identifiers and context; added text warns of this but does not prevent sharing or prove OS clipboard privacy. Static source review is not compilation, rendering, accessibility or security validation.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED OR EXECUTED

1. At Wide ≥1440px, inspect modal footer caption and four action buttons for original visual hierarchy, widths and ordering.
2. At Standard 1100–1439 and Compact 1024–1099, inspect footer caption wrapping and full keyboard navigation.
3. Below 1024 (including 1023/800/640px), inspect constrained modal width, footer containment and continued scrolling.
4. At 125%, 150% and 200% DPI, inspect footer height, modal minimum dimensions, readable text and scroll reachability.
5. In standard/high-contrast themes, inspect focus outlines, tooltips, captions and contrast.
6. Inspect Copy Summary tooltip, keyboard-focus HelpText and original clipboard contents (host, risk, reasons, tags, rules and actions), without claiming export or evidence verification.
7. Inspect Open Anomalies enabled only with an anomaly ID, navigation to the existing Anomalies view and no capture side effect.
8. Inspect Open Incident enabled only with an incident ID, navigation to existing Incidents workspace/selection, and Close without navigation.
9. Inspect unchanged KPI provenance, local PPS 10-sample/120-point behavior, incident triage, Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot, privacy/capture/trust and independent R437/protocol/test files.
10. Inspect final remote HEAD, direct-parent two-commit ancestry, exact two owned paths, fresh expected-SHA lease, no changes to independent automations, and **zero** tests/builds/replays/CI/runners/benchmarks/capture.

**Next independent UI GA UI-86:** inspect fresh LIVE HEAD, exact approved image, ledger and original WPF consumers; choose one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–85. Acceptance remains deferred until owner explicitly says **“now it is test time.”**

## GA UI-86 — Anomaly triage filter scope and accessible names

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE remote `feature/carthago-reliability-hardening` HEAD: `0f76cfd5835883dcc08d3f973d1277e46a751c99`; previous GA UI-85 publication `57e7d5aef88bfde97f1d82b63b399b1e7090b082`; private UI source commit `b3b0c0262752dcb33485bc9ba5a49eb91ccbc097` (direct child of starting HEAD); source XAML blob `e3e120fd11f4b4406d01ad585c935c2b201ce27a`. Authorized paths **only** `Carthago/Views/AnomaliesPage.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. No test, build, replay, holdout, CI, runner, benchmark or production capture was run; all acceptance scenarios below are **PLANNED ONLY — UNEXECUTED**.

### Approved reference, source provenance and starting divergence

**FIRST** retrieved and visually inspected exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`. Its navy/graphite/cyan/teal SOC palette, left navigation, compact filtering, KPIs, incident triage, investigation and event density guide the existing WPF visual consistency. All screenshot IPs, Mbps curves, rule IDs, timestamps, confidence, sensor counts and health indicators are **DEMO ONLY**, not telemetry. The screenshot's CLI is illustrative; the actual WPF CLI remains explicitly **UNAVAILABLE**, visual-only.

Pinned live remote HEAD, recent commit comparison, ledger through UI-85, `AnomaliesPage.xaml`, `AnomaliesPage.xaml.cs`, `Theme.xaml`, `ResponsiveLayout.cs`, `MainWindow.Navigation.cs`, `MainWindow.Responsive.cs`, `MainWindow.DashboardResponsive.cs` and original event consumers were statically inspected. Since UI-85, 1 independent commit(s) changed 5 non-UI path(s): Carthago.Tests/R561AdvancedAccuracyBatchTests.cs, Carthago/Engine/Rules/Catalog/RuleRegistry.cs, Carthago/Engine/Rules/Expansion/R561_RedisConfigSetRejectedReplyBurstRule.cs, docs/RULE_BATCH_561-561.md, docs/rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md. No UI-owned overlap at preparation. The original `CategoryFilter` and `SeverityFilter` selection handlers update only the anomaly viewmodel and call `ApplyFilter`; `SearchBox_TextChanged` searches local anomaly fields; `OnlyLinkedBox_Changed` requires `HasRelatedIncident`; `ResetFilters_Click` clears these four filter dimensions, not global preferences. `AnomaliesPage.ApplyResponsiveLayout` and `MainWindow` responsive partials govern existing layouts. No handlers or model contracts changed.

### One cohesive UI-owned accessibility improvement

In the existing **Anomaly Triage Queue filter toolbar**, add source-accurate `AutomationProperties.Name`, hover/keyboard-focus `ToolTip`, `ToolTipService.ShowsToolTipOnKeyboardFocus` and tooltip-bound `AutomationProperties.HelpText` to the existing **Category**, **Search**, **Severity**, **Linked only** and **Reset** controls. Guidance distinguishes category/severity restrictions, local queue search without an external lookup, linked-only filtering without creating incident links, and the **queue-only** Reset scope without changing application settings. The five controls retain their original visible text, geometry, styles, focus order, handlers, bindings, filter data and reset behavior. No new controls, focus stops, telemetry, capture, remediation, security control or external service integration. This is separate from UI-65 Settings sensitivity and UI-75/UI-77 Live Events toolbar work.

Source change is exclusively `Carthago/Views/AnomaliesPage.xaml` with five existing-control attribute edits; this ledger is the only documentation change. Preserve Wide ≥1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024; local PPS ScottPlot ten-sample average and bounded 120-point history; operational KPIs, prioritized incidents/investigation, read-only Live Events 80 displayed/500 retained, visual-only unavailable CLI, Cisco/WebView2/ScottPlot, privacy/capture/trust boundaries and independent detection/protocol streams.

### Static end review, publication and risks

Prepare complete source-plus-ledger private two-commit chain. Recheck LIVE remote HEAD **immediately before** publication, compare concurrent detection/protocol/UI paths, and publish **only** via one non-forced atomic `update_ref` with matching `expected_sha` lease on the **same branch**. If moved, reconcile disjoint paths against the new HEAD and fresh lease; STOP on overlap, conflict or missing guarantee. Verify final remote HEAD, direct-parent ancestry, both blobs and exact two-path diff after publication. No branch, PR, history rewrite, force push or independent automation mutation.

**Risks — UNVERIFIED:** WPF XAML parsing/compilation; whether the existing WPF ComboBox and TextBox templates expose the intended automation Name/HelpText and keyboard-triggered tooltips; screen-reader announcement order; long tooltip readability; keyboard focus outline contrast; compact filter widths and clipping at 1440/1100/1099/1024/1023/640px; 125–200% DPI and high-contrast behavior. Static review is not Windows rendering, accessibility or runtime validation.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED OR EXECUTED

1. Inspect all five original anomaly queue filter controls at Wide ≥1440px: captions, selected values, order and no added visible widgets.
2. Inspect Standard 1100–1439px, Compact 1024–1099px and below 1024 (1023/800/640px) for toolbar containment, labels and unchanged horizontal/vertical scroll behavior.
3. At 125%, 150% and 200% DPI, inspect control visibility, tooltip readability, keyboard focus and available scroll.
4. In standard and high-contrast themes, inspect tooltip text, focus visibility and screen-reader labels/help text for all five controls.
5. Change category and severity individually; confirm original local filter semantics and all-categories/all-severities defaults.
6. Enter search text; confirm filtering of local anomaly titles, addresses, reasons, evidence, incident context and rule IDs, with no network lookup.
7. Toggle Linked only; confirm only records with an existing related incident remain, without creating or changing incident links.
8. Select Reset; confirm it clears only anomaly category, severity, search and linked-only filters and does not reset global preferences or detection settings.
9. Inspect unchanged KPI provenance, local PPS 10-sample/120-point behavior, incident triage, Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot, privacy/capture/trust and independent rule/protocol files.
10. Verify final two-commit ancestry, exact two owned paths, source/docs blob hashes, expected-SHA publication lease, and **zero** tests/builds/replays/holdouts/CI/runners/benchmarks/capture.

**Next independent UI GA UI-87:** inspect fresh LIVE HEAD, exact approved image, ledger and original WPF consumers; choose one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–86. Acceptance remains deferred until owner explicitly says **“now it is test time.”**

## GA UI-87 — Incident Queue: clipboard and in-memory Clear action transparency

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE remote `feature/carthago-reliability-hardening` HEAD: `c6a97dcd0a5630ebea62d3a91a694520ef7eb42c`; prior GA UI-86 publication `54a084bda5805ce1170a2570ba31852377f8767b`. Private source commit `e60004eecb893c35ce8910f3070ab6446d002c8e`; source `Carthago/Views/IncidentsPage.xaml` blob `78c3e39db181cbcd986491d3c4c0ef72f1f1ceb6`. Authorized changed paths: **only** `Carthago/Views/IncidentsPage.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **ZERO** builds, dotnet/xUnit tests, replays, holdouts, CI/GitHub Actions, runners, benchmarks, production capture, running-WPF screenshots or executed acceptance scenarios. All scenarios below are **PLANNED ONLY — UNEXECUTED**.

### Approved reference, live divergence and original consumers

**FIRST** resolved and visually inspected exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928). Its deep navy/graphite, cyan/teal navigation, restrained severity, operational KPIs, traffic chart, prioritized incidents, investigation and dense local event presentation remain the design reference. Screenshot IPs, rule IDs, confidence, timestamps, Mbps lines, metrics, sensors and terminal output are **DEMO ONLY**; they are not runtime telemetry or capture health. The WPF CLI remains explicitly **UNAVAILABLE**, visual-only.

Inspected LIVE remote HEAD and recent independent changes, this ledger through UI-86, `IncidentsPage.xaml`, its original `IncidentsPage.xaml.cs` handlers, `Theme.xaml`, `Sidebar.xaml`, `MainWindow.xaml`, `MainWindow.Dashboard.cs`, `MainWindow.Navigation.cs`, `MainWindow.Responsive.cs`, `MainWindow.xaml.cs` and `ResponsiveLayout.cs`. Since GA UI-86, the pinned baseline includes 1 independent commit(s) on non-UI paths, which remain untouched. `MainWindow` instantiates the original `IncidentsPage` and applies its existing `IResponsiveLayoutAware` layout. `CopyJson_Click` serializes only the selected incident's existing `ToExportObject()` and writes it to the system clipboard via `Clipboard.SetText`; without a selection, it returns. `Clear_Click` calls `_vm.All.Clear()`, clears the current selection and updates empty/detail states. It does **not** call an incident-status writer, persistence deletion or global preference reset, and it has no confirmation dialog. New incident updates or reopening the page may repopulate the view. No data producer, consumer, handler, shared API, model, detection rule or capture/privacy control is changed.

Static source note outside this GA's change: the `SearchBox_TextChanged` method exists, but the reviewed XAML and page code-behind do not visibly attach `TextChanged` to `SearchBox`. Search behavior therefore must **not** be asserted as functioning without a later separately authorized investigation. No repair or test was attempted here.

### One cohesive UI-owned accessibility and action-scope improvement

Add source-accurate hover/keyboard-focus `ToolTip`, `ToolTipService.ShowsToolTipOnKeyboardFocus`, explicit `AutomationProperties.Name` and tooltip-bound `AutomationProperties.HelpText` to the two existing **Incident Queue** toolbar buttons **Copy JSON** and **Clear**. Copy guidance distinguishes clipboard transfer from a file export and explains the no-selection no-op. Clear guidance distinguishes an immediate, non-confirmed **in-memory queue clear** from resolving incidents or deleting persisted records, and notes that the list can repopulate. Original captions, widths, ordering, styles, handlers, selection, serialization, clipboard content, event subscriptions, incident statuses, navigation and responsive geometry remain unchanged. No new control, Tab stop, fake value, network call, remediation, telemetry or capture action. This differs from GA UI-85's Signal Investigation modal actions and GA UI-86's Anomaly Triage filter scope.

Source change is only `Carthago/Views/IncidentsPage.xaml` (attributes on two existing buttons); this ledger is the only documentation change. Preserve Wide ≥1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024; navy/graphite/cyan/teal and restrained severity; local PPS ScottPlot ten-sample average and bounded 120-point history; operational KPIs, prioritized incidents and investigation, read-only Live Events 80 displayed/500 retained, visual-only unavailable CLI, Cisco/WebView2/ScottPlot and all privacy/capture/trust boundaries.

### Static end review, publication lease and unverified risks

The source commit is a direct child of the pinned baseline, with only the authorized XAML path; its documentation descendant changes only this ledger. Recheck LIVE remote HEAD immediately before publishing, compare intervening independent detection/protocol/UI paths and publish the **complete** source-plus-docs two-commit chain only via **one non-forced atomic GitHub `update_ref` with matching `expected_sha` lease** on the same branch. If moved, reconcile disjoint paths against fresh HEAD and lease; **STOP** on overlap, conflict or missing guarantee. After publication inspect final HEAD, direct-parent ancestry, both blobs and exact two-path ownership diff.

**Risks — UNVERIFIED:** WPF XAML parsing/compilation; actual keyboard-triggered tooltip behavior, UI Automation Name/HelpText announcements, screen-reader reading order, focus outlines and high-contrast legibility; long tooltip readability at 1440/1100/1099/1024/1023/640px and 125–200% DPI. The original Copy JSON operation may put local incident identifiers/evidence on an OS clipboard accessible to other clipboard consumers. Clear removes the current view contents without confirmation and may repopulate; this change describes but does not change those behaviors. Static inspection is not proof of compilation, accessibility, security or runtime behavior.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED OR EXECUTED

1. At ≥1440px inspect the original Incident Queue Copy JSON and Clear captions, widths, order and unchanged visual hierarchy.
2. At 1100/1099/1024/1023/800/640px inspect toolbar containment, focus and tooltip visibility without new layout overflow.
3. At 125%, 150% and 200% DPI inspect tooltip text, button focus and responsive incident queue/investigation layout.
4. In standard/high-contrast themes inspect keyboard-focus outlines, tooltip contrast and screen-reader accessible names/help text.
5. With no incident selected, inspect Copy JSON no-op and truthful tooltip; no clipboard modification should be claimed without running.
6. With an incident selected, inspect Copy JSON serialization to clipboard, absence of file creation and review of local data disclosure.
7. Inspect Clear without confirmation: in-memory queue/selection empty, no incident-status update or persisted-record deletion.
8. Inspect later incident updates and page reopening for potential queue repopulation; verify original data subscriptions and selection behavior.
9. Inspect unchanged local PPS 10-sample/120-point behavior, KPI provenance, incidents, Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot, privacy/capture/trust and all independent rule/protocol paths.
10. Inspect final source/docs blobs, direct-parent two-commit chain, exact two owned paths, expected-SHA publication lease, and **zero** builds/tests/replays/holdouts/CI/runners/benchmarks/capture.

**Next independent UI GA UI-88:** inspect fresh LIVE HEAD, exact approved image, ledger and original WPF consumers; choose one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–87. Acceptance remains deferred until the owner explicitly says **“now it is test time.”**

## GA UI-88 — Incident Queue: accessible severity and unresolved-status filter guidance

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE remote `feature/carthago-reliability-hardening` HEAD: `b1546fac88e9933b24687dfb1d49e5546a6724cc`; previous GA UI-87 publication: `b1546fac88e9933b24687dfb1d49e5546a6724cc`. Private UI source commit: `22b8d175944f38e152b6ba86ea47d506da164016` (direct child of starting HEAD); source XAML blob: `6f42f1fc343eee232d839d664c1070fd8c7dc03e`; prior XAML blob: `78c3e39db181cbcd986491d3c4c0ef72f1f1ceb6`. Authorized paths **only** `Carthago/Views/IncidentsPage.xaml` and `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. **ZERO** builds, dotnet/xUnit tests, replays, holdouts, CI/GitHub Actions, runners, benchmarks, production capture, running-WPF screenshots or executed acceptance scenarios. All acceptance below is **PLANNED ONLY — UNEXECUTED**.

### Reference fidelity, live divergence and original consumers

**FIRST** resolved and visually inspected the exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928). Its navy/graphite/cyan/teal visual hierarchy, left navigation, operational KPIs, dense prioritized incident triage, investigation, restrained severity, chart and local event presentation remain the reference. The image's IPs, rule IDs, Mbps curves, timestamps, confidence, metrics, sensor state and terminal output are **DEMO ONLY**, never runtime evidence. The actual WPF CLI remains explicitly **UNAVAILABLE** and visual-only.

At the start, inspected live remote branch HEAD and recent commits; ledger through GA UI-87; `IncidentsPage.xaml`, `IncidentsPage.xaml.cs`, `Theme.xaml`, `ResponsiveLayout.cs`, `Sidebar.xaml`, `MainWindow.xaml`, `MainWindow.Navigation.cs`, `MainWindow.Responsive.cs` and original consumers. No independent commits intervened between UI-87 and the pinned starting HEAD at preparation. Original `SeverityFilter.SelectionChanged` sets `_vm.FilterSeverity` and calls `ApplyFilter`; `OnlyUnackedBox_Changed` sets `_vm.OnlyUnacked` and calls `ApplyFilter`. `ApplyFilter` compares severity or accepts All; the checkbox excludes `IsResolved` items, where `IsResolved` means status equals `Resolved` (case-insensitive). Thus acknowledged/investigating incidents are not automatically excluded. These controls filter the existing local `CollectionViewSource` only; no status, persistence, security or detection setting is written. Responsive layout remains governed by the original view and shell partials.

### One cohesive UI-owned improvement

On the existing **Incident Queue** severity ComboBox and **Open incidents only** CheckBox, add concise source-accurate hover and keyboard-focus tooltips, explicit `AutomationProperties.Name` and tooltip-bound `AutomationProperties.HelpText`. Explain that All includes all severities and that Open incidents only excludes **Resolved**, not all acknowledged or investigating cases; neither filter changes incident status or detection settings. Retain visible labels, options, controls, selection/checked handlers, bindings, geometry, styling and focus order. No added focus stop, search behavior, model, event producer, capture, clipboard operation, network request or remediation. This is separate from UI-86's **Anomaly Triage Queue** filters and UI-87's Incident Queue Copy JSON/Clear actions.

**Pre-existing separate finding, not fixed here:** `IncidentsPage.xaml.cs` contains `SearchBox_TextChanged`, but the inspected `IncidentsPage.xaml` does not attach `TextChanged="SearchBox_TextChanged"` and the constructor does not subscribe it. Search may therefore fail to update `_vm.Search`; do not assert that incident search works. This requires a separately scoped UI-owned correction and later runtime verification. GA UI-88 does not modify the search field or handler.

Source-only delta: `Carthago/Views/IncidentsPage.xaml` (10 additions, 2 deletions from private source-commit comparison). This ledger is the sole documentation change. Preserve Wide ≥1440, Standard 1100–1439, Compact 1024–1099, graceful below 1024; local PPS ScottPlot ten-sample average and bounded 120-point history; operational KPIs, prioritized incidents, investigation, read-only local Live Events 80 displayed/500 retained, explicitly unavailable visual-only CLI, Cisco/WebView2/ScottPlot and privacy/capture/trust boundaries.

### Publication, static end review and unverified risks

The private source commit is a direct child of pinned LIVE HEAD; this ledger commit is its direct child. Immediately before publication, recheck LIVE remote HEAD and concurrent changed paths. Publish the **complete** two-commit candidate only through **one** non-forced atomic GitHub `update_ref` with matching `expected_sha` lease on the same branch. If moved, reconstruct against fresh HEAD only for disjoint paths and fresh lease; **STOP** on overlap/conflict or missing guarantee. After publication inspect remote HEAD, direct-parent ancestry, both blobs, exact two owned paths and independent stream preservation. No branch, PR, force push, history rewrite or independent automation mutation.

**Risks — UNVERIFIED:** WPF XAML compilation; ComboBox/CheckBox template exposure of Name/HelpText; keyboard-focus tooltip triggering; screen-reader reading order; tooltip length/legibility; focus contrast in standard and high-contrast themes; containment at 1440/1100/1099/1024/1023/800/640px and 125–200% DPI. Existing incident search wiring remains an unresolved UI finding; this source-only enhancement does not fix or verify it. Static inspection cannot prove rendering, accessibility, filter runtime correctness or privacy/security outcomes.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED OR EXECUTED

1. At Wide ≥1440px, inspect original Incident Queue severity ComboBox and Open incidents only checkbox captions, option order, widths and unchanged visual hierarchy.
2. At Standard 1100–1439px, Compact 1024–1099px and below 1024 (1023/800/640px), inspect both filter controls and tooltip containment.
3. At 125%, 150% and 200% DPI, inspect focus indicators, tooltip readability and queue/investigation scroll reachability.
4. In standard/high-contrast themes, inspect keyboard-triggered tooltip presentation, screen-reader Name/HelpText and tab/focus order.
5. Select All and each Critical/High/Medium/Low severity; verify local filtering and no incident status or detection setting changes.
6. Toggle Open incidents only; verify it excludes only resolved cases, retains acknowledged/investigating unresolved cases and does not mutate incident status.
7. Combine severity and unresolved filters; inspect current selection, empty states, count presentation and existing local view behavior.
8. Separately investigate the pre-existing disconnected SearchBox_TextChanged handler; do not claim search correctness or repair as part of this GA.
9. Inspect unchanged local PPS 10-sample/120-point behavior, KPI provenance, incidents, Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot, privacy/capture/trust and independent detection/protocol paths.
10. Verify final source/docs blobs, direct-parent two-commit ancestry, exact two owned paths, fresh expected-SHA lease and **zero** builds/tests/replays/holdouts/CI/runners/benchmarks/capture.

**Next independent UI GA UI-89:** inspect fresh LIVE HEAD, exact approved image, ledger and original WPF consumers; choose one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–88. Acceptance remains deferred until the owner explicitly says **“now it is test time.”**


## GA UI-89 — Incident Investigation: accessible status-action consequences

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Pinned starting LIVE remote branch `feature/carthago-reliability-hardening` HEAD: `d360e050d32b8844d7719f4d8968e3c60062c905` (GA UI-88 publication). Private source commit: `77a239406e697afe1cd0233ccc2925aa37948e6e` (direct child of pinned HEAD); previous XAML blob: `6f42f1fc343eee232d839d664c1070fd8c7dc03e`; candidate XAML blob: `cb396b48780d7106b701b42daee6ddb63caa471c`. **Authorized paths only:** `Carthago/Views/IncidentsPage.xaml` and this `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`. All acceptance below is **PLANNED ONLY — UNEXECUTED**. **ZERO** builds, dotnet/xUnit tests, replays, holdouts, CI/GitHub Actions, runners, benchmarks, production capture or running-WPF screenshots.

### Approved reference, static starting divergence and original consumers

**FIRST** resolved and visually inspected exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928): navy/graphite surfaces, cyan/teal active accents, restrained severity, left navigation, operational KPIs, traffic chart, prioritized incidents, investigation and dense local Live Events. Screenshot IPs, rule IDs, timestamps, confidence, Mbps, sensor status and CLI output are **DEMO ONLY** and are not inserted or represented as capture-health or observed telemetry. Actual CLI remains **UNAVAILABLE**, visual-only.

At start inspected live remote branch ref and recent branch commits, ledger through GA UI-88, `IncidentsPage.xaml`, its original `IncidentsPage.xaml.cs` partial, `MainWindow.Navigation.cs`, `MainWindow.Responsive.cs`, `ResponsiveLayout.cs`, `Sidebar.xaml` and `Theme.xaml`. Prior UI-88 was already published at the pinned HEAD; no intervening independent commits were present at initial audit. `Ack_Click` returns when `_vm.Selected` is null, otherwise calls `_host.Analytics.UpdateIncidentStatus(id, "Acknowledged")`. `Resolve_Click` similarly requests `"Resolved"`; neither handler presents confirmation. The two existing `SecondaryButton` controls use the shared focus visual and preserve original button dimensions and click handlers. `IncidentsList.SelectionChanged` updates the selected incident; responsive columns are managed by existing page/shell partials. No service, analytics producer, persistence, capture or security control is edited.

### One cohesive UI-owned improvement

On the existing **Incident Investigation** Acknowledge and Resolve action buttons, add concise hover and keyboard-focus `ToolTip`, `ToolTipService.ShowsToolTipOnKeyboardFocus="True"`, explicit `AutomationProperties.Name` and tooltip-bound `AutomationProperties.HelpText`. The guidance distinguishes selected-incident **status updates** from network remediation, explains no-selection no-op and the absence of a confirmation step. Preserve original captions, widths, margins, `SecondaryButton` styles, `Ack_Click`/`Resolve_Click` handlers, focus order, selection, queue, incident status writer and all underlying behavior. No new command, model, API, network request, capture change or security bypass. Distinct from UI-87 Copy JSON/Clear and UI-88 severity/unresolved filtering.

Source-only delta: `Carthago/Views/IncidentsPage.xaml` (8 added attribute lines, 2 existing self-closing lines replaced). This ledger is the only documentation change. Preserve Wide ≥1440, Standard 1100–1439, Compact 1024–1099 and graceful below 1024; local PPS ScottPlot ten-sample average and bounded 120-point history; operational KPIs, prioritized incidents, investigation, read-only local Live Events 80 displayed/500 retained, explicitly unavailable visual-only CLI, Cisco/WebView2/ScottPlot and privacy/capture/trust boundaries.

**Pre-existing separate issue, not changed:** the Incident Queue `SearchBox_TextChanged` handler is defined in code-behind but not wired in inspected XAML or constructor; incident text search may not update its filter. This GA neither fixes nor asserts that search works.

### Publication lease, end divergence review and unverified risks

The private source commit has only the authorized XAML path and is a direct child of pinned starting HEAD; the documentation commit is its direct child. Immediately before publishing, re-read LIVE remote HEAD and compare any concurrent detection/protocol/UI paths. Publish **both commits together** with one non-forced atomic GitHub `update_ref` using matching `expected_sha` on the same branch; if moved, reconstruct against fresh HEAD only when paths are disjoint and use a fresh lease, otherwise **STOP**. After publication inspect final ref, ancestry, published blobs and exact two owned paths. Do not create a branch, PR or automation, rewrite history, or modify independent streams.

**Risks — UNVERIFIED:** WPF XAML parsing/compilation; tooltip and UI Automation Name/HelpText exposure by the existing WPF button templates; screen-reader reading order; keyboard-focus tooltip behavior; high-contrast legibility; long-tooltip containment at 1440/1100/1099/1024/1023/800/640px and 125–200% DPI. The status update is an existing operational action without a confirmation dialog; the text documents but does not change that risk. No static source inspection proves successful status persistence, rendering, accessibility or runtime correctness.

### Acceptance scenarios — PLANNED ONLY; NOT AUTHORED OR EXECUTED

1. At Wide ≥1440px, verify unchanged Acknowledge/Resolve captions, button widths, placement and visual hierarchy.
2. At Standard 1100–1439px, Compact 1024–1099px and below 1024 (1023/800/640px), inspect toolbar containment and tooltip placement.
3. At 125%, 150% and 200% DPI, inspect button focus outlines, tooltips, investigation scrolling and clipped text.
4. With keyboard and screen reader, inspect accessible names/help text, focus order, keyboard-focus tooltips and high-contrast legibility.
5. With no selected incident, inspect that both original handlers return without status request; tooltips remain truthful.
6. With a selected incident, inspect Acknowledge requests `Acknowledged` through the existing analytics status writer without confirmation.
7. With a selected incident, inspect Resolve requests `Resolved` without confirmation and does not invoke capture or remediation commands.
8. Inspect incident selection, queue refresh, filter behavior, status display and the separately unresolved search wiring; do not claim text search correctness.
9. Inspect unchanged local PPS 10-sample/120-point behavior, KPIs, incidents, Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot, privacy/capture/trust and independent detection/protocol paths.
10. Inspect final source/docs blobs, direct-parent two-commit chain, exact two owned paths, expected-SHA publication lease and **zero** builds/tests/replays/holdouts/CI/runners/benchmarks/capture.

**Next independent UI GA UI-90:** inspect fresh LIVE HEAD, exact approved image, ledger and original WPF consumers; choose one distinct UI-owned accessibility/readability/visual-consistency improvement outside UI-01–89. Acceptance remains deferred until the owner explicitly says **“now it is test time.”**


## GA UI-90 — Visible operations-canvas redesign (reference-led)

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Starting LIVE remote branch `feature/carthago-reliability-hardening` HEAD: `51b5f0b8baacdb2a93349dc0c8db09b68ecb2d4f` (R563 detection backlog provenance already present; independent rule/protocol source and docs untouched). Private source commit `88610d8ac9f44697617d4e5b6a829810d9616a7c` (direct child of pinned HEAD). Source tree `ad2950965e9bb24efbf780c40d92ae2ddd08e59a`. Owned source paths: `Carthago/Views/MainWindow.xaml` (candidate blob `a917568ad8e40d1e46642bc6889899805a71644d`), `Carthago/Views/Theme.xaml` (candidate blob `09abcef50403a0c8c85f105bf8a53ad14dbc9b98`), `Carthago/Views/MainWindow.DashboardResponsive.cs` (candidate blob `34686766d0e1862662948c4bdfd24ccd208b5f0d`), and this ledger only. No builds, dotnet/xUnit tests, replays, holdouts, CI/Actions, runners, benchmarks, production capture, or running-WPF screenshots. ALL planned scenarios below are **UNEXECUTED**.

### Approved reference and starting divergence

**FIRST** retrieved and visually inspected exact approved ChatGPT Library screenshot `libfile_b0a34361560c8191b641e432b3e6b15c` (dark 1648×928 SOC composition): cyan left navigation, prominent security title and live-status chip, four operational KPI cards, chart at left, prioritized incident queue at center, investigation at right, dense Live Events beneath. The reference's IPs, metrics, timestamps, Mbps, rule IDs, percentages, confidence and CLI content are **DEMO ONLY**, never live telemetry or asserted capture health. The actual local PPS plot and read-only local Live Events are preserved; the CLI remains explicitly **UNAVAILABLE**, visual-only.

At start inspected LIVE remote HEAD/recent commits, ledger through UI-89, `MainWindow.xaml`, `Theme.xaml`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, `MainWindow.Dashboard.cs`, `MainWindow.DashboardEvents.cs`, `MainWindow.Plots.cs`, `MainWindow.Core.cs`, `MainWindow.xaml.cs` and `Sidebar.xaml`. Original consumers bind `DashboardOverviewKpiItemsControl` and `DashboardKpiItemsControl` to existing observable collections; capture status comes from existing `MonitoringStatusBadge.BorderBrush` and `CaptureStatusText.Text`; existing responsive code positions triage panels. No external consumer assumes the chart or triage panel remains a direct child of `SocDashboardWorkspace` in the inspected UI partials. The chart retains original `TrafficPlot` and status/summary names and existing ScottPlot behavior. No model, capture, analytics, detection, privacy or security writer is changed.

### Before → after: screen-visible transformation

- **Operations hero:** replace the plain one-line heading with a full-width navy/teal gradient hero card, a short cyan keyline, a 30px Security Overview title, truthful local-workspace subtitle, and a bordered capture-state block. Its status dot and text continue to bind to the existing capture pipeline, not a hard-coded monitoring claim.
- **Operational KPI cards:** replace the 102px dense tile presentation with 132px gradient cards, a slim per-metric accent rail, stronger 27px primary values and 46px icon compartments. Reuse the exact existing `SocKpiVm` values, icon, delta, trend, information glyph and accessible labels; no fake sensors/coverage/throughput.
- **Wide visual arrangement (≥1440):** move the original local PPS chart and existing triage grid into one 480px operations canvas. The chart occupies the left ~46% and the existing prioritized queue plus incident investigation divide the right ~54%, producing three visible operational panels in the same horizontal band, closer to the approved screenshot. Keep chart's original local PPS/10-sample legend, 120-point bounded history, empty state and text provenance; retain queue selection and investigation handlers.
- **Standard (1100–1439), Compact (1024–1099), and below 1024:** the operations canvas reflows to chart above triage. The existing Standard side-by-side queue/investigation and Compact vertically stacked queue/investigation layouts remain in control; below 1024 the hero capture-state card moves below the title and the existing narrow KPI panel becomes one column. The shell, sidebar and navigation stay intact.
- **Information hierarchy:** move preference-controlled Additional metrics below the main operations canvas so capture/incident investigation is prioritized before secondary metrics. Apply one restrained `DashboardFocusPanel` surface style to chart, queue and investigation without altering their original content.
- **Unchanged lower workspace:** High-Risk Hosts, Recommended Actions, Raw/Advanced shortcuts, bounded read-only Live Events (80 shown/500 retained), visual-only unavailable CLI and all existing navigation remain. Preserve Cisco/WebView2/ScottPlot integrations, event provenance, security and capture boundaries.

This is a structural WPF composition change across three UI source files, not a tooltip-only GA. **Static visual-impact assessment:** obvious hero, card and panel arrangement changes in source; actual rendering, clipping and perceived visual quality are not verified until owner-authorized tests/screenshots.

### Static end review, publication lease and risks

Only the three owned UI source paths above and this `docs/design/**` ledger are intended to differ. All original `x:Name` for KPI collections, chart, capture status, triage queue, selected signal, Live Events and CLI remain present. New names are `DashboardHeroGrid`, `DashboardHeroStatusCard`, `DashboardFocusGrid`, `DashboardFocusPrimaryRow`, `DashboardFocusSecondaryRow`, `DashboardFocusTrafficColumn`, `DashboardFocusTriageColumn`; the responsive partial references these only. No new UI event handler, API, binding producer, telemetry source, capture path or rule change. Existing `DashboardTrafficChartCaptureStatus` repositioning, dashboard widget preference pipeline and original incident selection handlers remain. Source-only static inspection cannot prove WPF XAML compilation, visual appearance, chart resizing, screen-reader behavior, contrast or correct responsiveness.

**Risks — UNVERIFIED:** (1) 480px Wide three-panel canvas may constrain long incident/investigation details and clip text at 1440px or high DPI; (2) chart plot retains fixed 240px height within a taller card, potentially producing unused vertical space; (3) 132px cards increase vertical scrolling and narrow KPI stack height; (4) hero status wrapping and 3-column density require actual WPF/DPI inspection; (5) WPF style/resource and generated x:Name bindings remain uncompiled. No live capture or accessibility result is claimed.

Publication procedure: prepare source commit and this docs commit privately, recheck LIVE remote HEAD immediately before publish and compare concurrent detection/protocol paths; publish the complete two-commit chain through **one non-forced atomic `update_ref` with `expected_sha` lease** on the same branch. If the ref moves, reconcile only disjoint paths with a fresh lease; STOP on overlap/conflict or unavailable guarantee. After publish inspect final remote HEAD, direct-parent ancestry, changed paths and source/docs blobs. Never create a branch/PR/automation, force push or rewrite history.

### Acceptance scenarios — PLANNED ONLY, UNEXECUTED

1. At 1648px and Wide ≥1440, visually inspect hero, four KPI cards and simultaneous chart/priority queue/investigation panels against approved reference, without comparing demo metrics as live data.
2. At 1440px and 125%, 150%, 200% DPI, inspect triage titles, queue rows, selected incident facts, chart legend, and inner scroll reachability for clipping/overlap.
3. At Standard 1100–1439, inspect chart above side-by-side queue/investigation and the existing responsive summary widgets.
4. At Compact 1024–1099, inspect chart above vertically stacked queue/investigation, KPI 2-column layout and unchanged sidebar navigation.
5. At 1023, 800 and 640px, inspect hero status wrapping, one-column KPIs, chart status repositioning, scrolling and focus reachability.
6. With monitoring paused, offline, degraded and error states, verify the hero status dot/text always mirrors the original capture status, without fabricated packet-flow claims.
7. With zero local PPS samples and later real local timer samples, verify original ScottPlot waiting overlay, 10-sample average, 120-point history and provenance text.
8. With incident and anomaly selections, inspect queue selection, investigation panel updates, original actions, evidence text, keyboard focus and accessible names.
9. Inspect unchanged secondary metrics, high-risk hosts, recommended actions, shortcuts, local Live Events 80/500, explicitly unavailable CLI, Cisco/WebView2/ScottPlot and privacy/capture/trust boundaries.
10. Verify source/docs blobs, exactly four authorized changed paths, direct-parent two-commit ancestry, fresh expected-SHA publication lease and **zero** builds/tests/replays/holdouts/CI/runners/benchmarks/capture.

**Next independent UI GA UI-91:** continue a **meaningful screen-visible** reference-led redesign, prioritizing the lower Dashboard/Live Events information architecture or Incident Queue composition. Never substitute tooltip-only or micro-copy changes for a visual GA. Preserve all owner restrictions and defer runtime acceptance until explicit **“now it is test time.”**


## GA UI-91 — Reference-led Live Events operations band (visual redesign)

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Pinned LIVE remote starting HEAD: `2c8d0fc14f3881e9d2dd530518852c8afa2e61ea`; independent R437 Redis trusted-audit source/tests/docs and the pre-existing UI-90 KPI XAML ordering correction `c23549223b` were already present and were not modified. Prepared private UI source commit `225f994b0238539dbbd4155474aaf3376ebc7d56`, direct child of the pinned HEAD; source tree `96011595fb092013274575e2a3a781f07cf15d57`. No builds, dotnet/xUnit tests, replays, holdouts, CI/Actions, runners, benchmarking, production capture or running-WPF screenshots were executed **by this GA**. All scenarios below are **PLANNED, UNEXECUTED**.

### Reference fidelity and start-of-GA divergence

FIRST retrieved and visually inspected the exact approved ChatGPT Library screenshot `libfile_b0a34361560c8191b641e432b3e6b15c` (1648×928 dark SOC concept). The lower band places a dense local event table below the chart/incident area and a dark CLI companion at the right. The reference's IPs, metrics, rule IDs, timestamps, percentages, confidence and Mbps are DEMO ONLY; none were copied into live source. The actual CLI is **UNAVAILABLE** and remains explicitly non-interactive, not the working terminal shown in the concept.

Reviewed the LIVE branch, latest 12 commits, ledger through UI-90, `MainWindow.xaml`, `Theme.xaml`, `MainWindow.DashboardResponsive.cs`, `MainWindow.Responsive.cs`, and `MainWindow.DashboardEvents.cs` consumers. The existing `DashboardLiveEventsGrid` is populated only by the retained local `DetectionEvent` projection, limited to 80 displayed rows and 500 retained events. Existing severity/protocol/rule/search filters, empty-state text, capture-state-derived status and provenance, and navigation to Raw Detections are reused. `DashboardCliCompanionPanel` remains visual-only, with no dispatcher, process, adapter or telemetry binding. No changed model, service, detection, capture, privacy, trust, security or shared API.

### Before → after: substantial visible composition

- **Lower operations canvas:** formerly the Live Events card spanned the full dashboard width and the 408px CLI card sat below it. Now a named `DashboardLowerGrid` docks Live Events and the CLI side by side on Wide (≥1440px), approximately 2.65:1 with a 12px gutter; Standard 1100–1439, Compact 1024–1099 and below 1024 stack the full-width event stream above the unavailable CLI. This creates the reference's lower two-zone SOC composition without fabricating a working terminal.
- **Event-stream identity:** the previously plain title becomes a larger 20px `Live Events` heading beneath a cyan `LOCAL DETECTION STREAM` eyebrow in a restrained navy gradient header. The original honest subtitle and Raw Detections navigation remain.
- **Operational density:** the read-only table increases from 190px to 300px high, rows from 27px to 34px and column headers from 30px to 38px, improving scanability and showing more observed rows before scrolling. The first time column remains frozen, with horizontal scrolling for narrow content and existing virtualization intact.
- **Severity visual hierarchy:** the severity text column becomes a bounded badge template using only the existing `DashboardEventRowVm.Severity` string, with restrained Critical/High/Medium/Low/Info palettes and neutral fallback. This is a visual classification of reported severity, not independently verified incident impact.
- **Filter and provenance bands:** a distinct `FILTER LOCAL EVENTS` toolbar and blue-toned footer create clear functional layers. All four existing filters and their event handlers remain unchanged; the footer still displays the source-driven row/retention/capture caption and evidence/delivery caveats.
- **Theme ownership:** four new UI-only style/gradient resources are isolated in `Theme.xaml`; the responsive partial positions the two existing cards without new event producers, handlers or bindings.

**Static visual-impact assessment:** source shows a significant screen-visible two-column lower layout, taller event grid, distinct header/toolbar/footer zones and severity pills. Actual WPF rendering, DPI behavior, layout clipping and screen-reader experience remain **UNVERIFIED**.

### Owned files, source provenance and end-of-GA static review

Owned source paths:
1. `Carthago/Views/MainWindow.xaml` — blob `5dabf655b7b5668d9ac272870a6af0b4a3822400`.
2. `Carthago/Views/Theme.xaml` — blob `95ca08dafa58c1c6b796e13d1007218c0d605d15`.
3. `Carthago/Views/MainWindow.DashboardResponsive.cs` — blob `226f276108bca4a54daddf3f5548ad2317de0ca9`.
4. `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` — documentation only.

Static source review: the existing named Live Events grid, four filters, empty-state, status/provenance, CLI, chart, KPI, triage and investigation controls remain; the new names are `DashboardLowerGrid`, `DashboardLowerPrimaryRow`, `DashboardLowerSecondaryRow`, `DashboardLowerEventsColumn`, `DashboardLowerCliColumn`. The responsive partial references only the new lower row/column definitions and original named panels. No new binding producer or event handler, and no change to event retention, source values, rule severity, capture, ScottPlot, Cisco or WebView2. Independent commits since UI-90 touch R437 trusted-audit source/tests/docs, validation documentation and the separate UI-90 KPI ordering correction, not the new lower band.

**Risks — UNVERIFIED:** at exactly 1440px, the event table may need horizontal scrolling beside the CLI; at 125–200% DPI, row labels, badges and toolbar may clip or overflow; the 300px grid increases overall vertical scroll; some reported severity values may use neutral fallback; generated WPF names and new resource references are uncompiled; the unavailable CLI may leave unused vertical space beside the event grid. These require owner-authorized WPF visual inspection. No success or accessibility claim is inferred from static source.

Publication protocol: create the private source/docs direct-parent chain, re-read LIVE remote HEAD and concurrent changes immediately before publication, publish the **complete** chain via exactly one non-forced atomic `update_ref` with `expected_sha` lease on `feature/carthago-reliability-hardening`; stop on overlap or missing lease guarantee. Verify resulting branch HEAD, ancestry and exactly four owned changed paths.

### Acceptance scenarios — PLANNED ONLY, UNEXECUTED

1. At 1648px Wide, compare lower event-stream/CLI side-by-side composition, header, filters, severity badges and footer to the approved reference without copying demo content.
2. At 1440px Wide and 125%, 150%, 200% DPI, inspect CLI width, event-column scroll, frozen time column, badge clipping and panel gutters.
3. At Standard 1100–1439, verify full-width Live Events above the unavailable CLI with no horizontal card overlap.
4. At Compact 1024–1099 and below 1024 (including 800/640), verify vertical stacking, filter wrap, keyboard reachability and preserved outer scrolling.
5. Verify the existing local detection stream still shows at most 80 rows from at most 500 retained events and preserves source-driven empty/no-match messages.
6. Verify Critical, High, Medium, Low, Info and unknown reported severities display the intended non-authoritative pill colors without changing underlying severity.
7. Verify severity/protocol/rule/search and Clear filters retain original handlers, results and no-capture/no-export behavior.
8. Verify event time, source, destination, rule, protocol, evidence presence/count and delivery metadata remain read-only, accurately attributed and horizontally scrollable.
9. Verify the CLI is visibly UNAVAILABLE and does not execute commands, and existing PPS ScottPlot, triage/investigation, Cisco/WebView2, capture/privacy/trust boundaries are unchanged.
10. Verify source/docs blobs, exactly four owned paths, direct-parent ancestry, expected-SHA atomic publication and **zero** GA builds/tests/replays/holdouts/CI/runners/benchmarks/capture.

**Next independent GA UI-92:** redesign Incident Queue / Investigation screen composition at section scale, not tooltip micro-edits. Maintain reference-led visual impact and all ownership/test restrictions.


## GA UI-92 — Incident operations visual architecture: triage and investigation

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Approved reference: ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c`, visually inspected before repository work (1648×928 dark SOC concept). **Starting live branch HEAD:** `6099bfa8c9bff2150caadc7dbf89f332752a1a42`; the latest prior design ledger GA was UI-91 (publication `3cd94a6a25de849a90f63997106a49047f13421d`). The intervening 22 independent commits concerned Redis trusted-audit source/tests/config and validation documentation; no prior UI-owned paths changed. **Prepared UI source commit:** `c9db9e94d311b6c83583f43a3976cb844b640b98`, direct child of starting HEAD; **source tree:** `e17b34a81e1dc37c6770e5215d2367c38f9c6713`. This entry is documentation only and must publish together with source via one atomic expected-SHA lease.

### Visual intent and approved reference mapping

The screenshot shows a deep-navy SOC with prominent top-level identity, cyan information hierarchy, concise operational KPIs, a prioritized incident list and an adjacent investigation pane. GA UI-90/91 already addressed the Overview and local Live Events/CLI band; GA UI-92 extends the *same visible language* to both real incident workspaces. Screenshot metrics, IPs, throughput, rule IDs, times, confidence, CLI output and monitoring-health labels are **DEMO ONLY** and are not inserted into application data or used to assert capture health.

**Before → after (screen-visible, not tooltip-only):**
- **Both Incidents and Incident Queue:** previously opened directly on a KPI strip without an operational hero. Each now begins with a full-width gradient **incident operations banner** (29px title, cyan section eyebrow, descriptive subtitle, status chip bound to existing `ActiveIncidentCount` or `QueueCountLabel`). Existing KPI, queue and investigation sections move down one explicit Grid row; no producer or navigation contract changes.
- **KPI visual system:** five Incidents metrics and the existing Incident Queue KPI template now use the same navy gradient, 124px minimum-height tile, more deliberate padding and 13px corner geometry. All counts/deltas remain bound to their original viewmodels; severity accents remain source-derived, not synthetic.
- **Triage and investigation composition:** both workspaces adopt coherent, softly graded panels with 17px padding and quiet teal borders. Their primary headers become distinct **cyan eyebrow → 20px title → source-accurate subtitle → action controls** vertical zones. This moves buttons below titles, reducing competition for horizontal space in the two-column workspace and making the actions more visible without changing click handlers.
- **Incidents queue rows:** existing risk score, severity, status, timestamp, title and source are retained but now sit inside bounded dark case cards with an explicit source-severity color rail and cyan-selected border. The existing `ListBoxItem` selection remains the binding source for the new visual state.
- **Supporting evidence:** timeline, related anomalies, affected hosts and response checklist in Incidents, and the corresponding triage support panels in Incident Queue, adopt the shared panel treatment. Their data templates and source bindings remain intact.
- **Shared visual ownership:** seven new incident-only brushes/styles in `Theme.xaml`; no global replacement of other page styles. No new working CLI, new sensors, detection telemetry, simulated incidents or new actions.

### Responsive composition and static end review

Existing responsive contracts are reused without changing their code: Wide ≥1440 uses the existing five-column Incidents KPI strip and side-by-side triage/investigation; Standard 1100–1439 uses three KPI columns and the existing adaptive panel placement; Compact 1024–1099 and below 1024 use the existing two-column KPI and stacked-panel behavior. The hero is deliberately vertically composed, with wrapping text and a left-aligned bound status chip, to avoid a fixed-width secondary hero column. Incident Queue KPI `WrapPanel` and the existing 900px horizontally scrollable tabular queue are preserved.

Static source review covered `IncidentsPage.xaml`, `IncidentQueuePage.xaml`, their `.xaml.cs` consumers and `IResponsiveLayoutAware` implementations, `MainWindow.Navigation.cs`, `Theme.xaml`, the prior UI-90/91 dashboard changes and ledger. The original `x:Name` references for KPI grids, primary/supporting row and column definitions, list selections, filters, investigation bodies, empty states, actions and response controls remain. No `Click` or event handler was added, removed or renamed. Existing severity converter, status/selection bindings and queue pagination remain. Only two page root row indices changed to accommodate the new banners; the responsive partials still operate on their original named elements. No model, service, detection, protocol, capture, trust/privacy, telemetry, workflow, test or shared API path changed.

**Owned paths and exact source blob provenance:**
1. `Carthago/Views/Theme.xaml` — `0dea075161829e52278fe9af4408d31084b7e5d7`.
2. `Carthago/Views/IncidentsPage.xaml` — `c9483df877aaa9a9db4fd4823e063d9e2e5a6050`.
3. `Carthago/Views/IncidentQueuePage.xaml` — `e8ac3695916d2784f26f8352af4f0cb7baf6aed3`.
4. `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` — this documentation update.

**Static visual-impact assessment:** source introduces two prominent new screen headers, six enlarged/restyled KPI types, cohesive two-pane panel framing, stacked action zones and severity-coded selectable case cards. This is a visible section-scale change on both incident screens; **actual WPF rendering, compilation, accessibility and DPI behavior are UNVERIFIED**. No tests or running screenshots were produced.

**Risks — UNVERIFIED:** additional hero and KPI height increases vertical scrolling; 29px hero titles and status chips may need DPI-specific wrapping; fixed-width queue filters, incident list status badges and the 900px Incident Queue table can still require scrolling on narrow widths; queue selection template and new StaticResource resolution have not been compiled; source-severity color rail inherits converter fallback semantics; stacked action buttons may increase header height; the previously identified Incidents text-search event wiring issue remains unmodified. Preserve existing privacy and clipboard boundaries.

### Planned acceptance — ALL UNEXECUTED

1. At 1648px, visually compare both new hero banners, KPI hierarchy, panel surfaces and selected-case treatment with the approved reference; ignore its demo values.
2. At 1440px and 125%, 150% and 200% DPI, inspect queue row rails, selected border, action placement, status chips and all case text for clipping.
3. At Standard 1100–1439, inspect three-column Incidents KPIs, adaptive queue/investigation placement and supporting panels.
4. At Compact 1024–1099, inspect two-column Incidents KPIs, stacked workspace, title wraps and keyboard reachability.
5. Below 1024 (1023/800/640px), inspect hero vertical flow, queue filter reachability, table horizontal scrolling and full-page scrolling.
6. Verify the five Incidents KPI values and Incident Queue KPI values remain bound to existing local source/viewmodel state without demo data.
7. Verify case selection updates the adjacent investigation, severity rails and selected borders, with unchanged source severity/status and no synthetic impact claims.
8. Verify Copy JSON, Clear, Acknowledge, Resolve, queue pagination, filters, notes, investigation actions and navigation preserve original handlers and safety semantics.
9. Verify timeline, affected hosts, evidence, related anomalies, checklist, local PPS/Live Events 80/500, unavailable CLI, Cisco/WebView2/ScottPlot and capture/privacy/trust boundaries remain unchanged.
10. Verify exact source/docs blobs, only four authorized paths, direct-parent commit chain, one non-forced expected-SHA lease and **zero** builds/tests/replays/holdouts/CI/runners/benchmarks/capture.

**Next UI GA UI-93:** continue a substantial reference-led **Anomalies workspace** visual redesign (section architecture, evidence density and responsive layout), never tooltip-only micro-edits. Keep SOURCE CANDIDATE — UNVERIFIED until explicit owner authorization: **“now it is test time.”**

**Publication reconciliation:** initial starting HEAD `6099bfa8c9bff2150caadc7dbf89f332752a1a42`; additional disjoint independent changes through `adb7c642c388d9013dad33cb2c69dfbac7959ece` were preserved. The final GA UI-92 source commit is `c9db9e94d311b6c83583f43a3976cb844b640b98`, directly parented to the reconciled live HEAD. No independent files were overwritten.


## GA UI-93 — Anomaly Intelligence: reference-led visual operations workspace

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Exact approved ChatGPT Library reference `libfile_b0a34361560c8191b641e432b3e6b15c` was retrieved and visually inspected FIRST, before any GitHub inspection or source work. Starting live feature-branch HEAD: `395f01162c771c13cca004c7c64115fe1ff2f4b3`. Prior GA UI-92 publication: `91ab8a05e2ac4ec1e886d69f9ebc52d9ccac7eae`. Independent intervening commits harden Redis pinned mTLS/audit source/tests and validation docs; their files and schedules remain untouched. Prepared private **source commit `886b99fa46385d5902942f1f39ec0dba309564b0`**, direct child of starting HEAD; source tree `d7e59b5d2b66523dabe02f3dd5dc1f3f10a46d8b`. The source and this documentation must be published together through exactly one non-forced expected-SHA lease. No builds, tests, replays, holdouts, CI/Actions, runners, benchmarks, capture or running-WPF screenshots were executed by this GA.

### Approved-reference mapping, provenance and visible before → after

The approved 1648×928 screenshot shows dark navy/graphite operations cards, cyan hierarchy, strong page identity, prominent numerical tiles, a priority triage queue and adjacent investigation with layered evidence. Its IPs, rule IDs, timestamps, confidence, Mbps, status claims and CLI content are **DEMO ONLY**. No screenshot values were copied into real application data. Existing local capture, analytics, privacy/trust and detection producers are unchanged.

- **Page identity:** formerly the Anomalies screen began abruptly with five small KPI tiles. Now a full-width navy/teal **Anomaly Intelligence** gradient hero introduces the behavior-analytics workflow, a cyan operations eyebrow and a **RECENT LOCAL SNAPSHOT** count bound to the existing `RawSignalCount` viewmodel property. This count describes a bounded local anomaly snapshot, not a global sensor or network total.
- **KPI architecture:** the five existing metrics become taller 124px gradient cards with larger values, consistent padding and restrained color rails. Existing values, deltas, labels and source bindings remain. The Baseline Confidence card's previous five permanently green bars are replaced by a single neutral cyan/teal accent and an explicit local-baseline-not-rule-coverage caption; the static full-green graphic could otherwise imply an unsupported perfect baseline state.
- **Queue/filter architecture:** previously category, search, severity, linked-only and Reset were compressed into one five-column grid inside a 45%-width triage pane. The new dark filter band provides a **full-width search row** and a **wrapping control row** for category, severity, linked-only and Reset. Existing names, handlers, option values, bindings and keyboard controls are retained. Wrapping is source-designed to improve reachability as the queue pane narrows, but is not yet visually verified.
- **Triage and investigation:** both primary panels now use coherent dark gradient surfaces, 17px padding, teal borders and **cyan eyebrow → 20px title → context subtitle → separator** hierarchy. The original queue, pagination, selected-anomaly detail, evidence, navigation and action handlers remain in place.
- **Evidence readability:** existing investigation fact cards adopt darker navy surfaces with quiet borders and more deliberate padding. Entity History, Baseline Drift/Peer Group and Analyst Actions supporting panels adopt the same panel geometry and stronger titled-section hierarchy. Existing baseline/model/evidence data and disabled states are unchanged.
- **Responsive contract:** existing `AnomaliesPage.ApplyResponsiveLayout` still controls 5/3/2 KPI columns and Wide/Standard two-pane versus Compact stacked primary/supporting panels; the new hero is vertically composed and filter controls wrap. Below 1024px, a 162px category selector and 158px severity selector may still require careful reachability review. No responsive C# or shared API edits were necessary.

**Static visual-impact assessment:** the source changes a full page header, five metric cards, primary panel geometry, filter arrangement, evidence surfaces and three supporting sections. This is a section/screen-scale visual redesign, not tooltip-only. Actual WPF rendering, XAML parsing, keyboard accessibility, DPI behavior and clipping are **UNVERIFIED**.

### Ownership, source provenance and start/end divergence review

- `Carthago/Views/AnomaliesPage.xaml`: source blob `97e22abe5c4bbe675057d544a8303e5ba43bc5a8` (previous `e3e120fd11f4b4406d01ad585c935c2b201ce27a`).
- `Carthago/Views/Theme.xaml`: source blob `c5492c0f9aa953f38af83da43b01daa3dfec33e8` (previous `0dea075161829e52278fe9af4408d31084b7e5d7`). Seven new `AnomalyOps*` resources are page-specific, leaving the incident/dashboard visual systems intact.
- `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`: documentation only, committed as direct child of the source commit.

Start review inspected live branch/recent commits, ledger through UI-92, `AnomaliesPage.xaml`, `AnomaliesPage.xaml.cs` including `ApplyResponsiveLayout`, the incident-page responsive precedent, and shared `Theme.xaml`. End static source review found the original named KPI grid, primary/supporting row/column definitions, `QueuePanel`, `InvestigationPanel`, `AnomaliesList`, filters, pagination, evidence and empty-state controls still present exactly once. The original filter/selection/navigation handler names, analytics producers, `SinkHost` consumers and responsive partial contract remain. Only two UI-owned files plus this ledger are intended to differ. No Engine/Models/Services, detection/protocol, telemetry/capture/trust/privacy, tests, workflows, runners, project file, rule/protocol docs or independent automation settings were modified. No new working CLI, adapters, fake telemetry or monitoring claims.

**Risks — UNVERIFIED:** the taller hero/KPIs/filter band increase vertical scrolling; at 1440px the left 45%-width pane may wrap filter controls into multiple rows; 125–200% DPI and widths below 1024 may still clip fixed-width selectors, long queue rows or investigation facts; new WPF StaticResource references and grid-row shifts have not been compiled; source severity converter fallback and baseline health wording require visual/accessibility review. The approved screenshot's demonstration data must never be treated as observed capture.

### Planned acceptance scenarios — ALL UNEXECUTED

1. At 1648px compare hero, five KPI cards, queue, investigation and evidence hierarchy to the approved reference without using demo data as facts.
2. At Wide 1440px and 125%, 150%, 200% DPI inspect panel proportions, filter wrapping, selected-row highlight and evidence fact-card truncation.
3. At Standard 1100–1439 inspect existing three-column KPI reflow and queue/investigation layout, with full-width search remaining usable.
4. At Compact 1024–1099 inspect two-column KPI cards, stacked panels, wrapped filters and supporting analysis sections.
5. At 1023/800/640px inspect outer scrolling, combo reachability, hero wrapping, page headers and keyboard focus.
6. Confirm `RawSignalCount`, five KPI values/deltas and baseline health remain bound to original local sources, without simulated coverage or false always-green indicators.
7. Confirm category, severity, search, linked-only, Reset, pagination and queue selection retain original handlers, options and state transitions.
8. Confirm selected anomaly investigation, baseline comparison, model explanation, top ML signals, tags, related rule IDs, evidence and analyst action buttons retain original content and disabled states.
9. Confirm independent Incident Queue, Overview local PPS ScottPlot (10-sample average/120-point history), Live Events 80/500, visual-only UNAVAILABLE CLI, Cisco/WebView2, privacy/trust/capture boundaries remain unchanged.
10. Verify published source/docs blob SHAs, exactly three authorized changed paths, source→docs direct-parent ancestry, one non-forced expected-SHA publication and **zero** builds/tests/replays/holdouts/CI/runners/benchmarks/capture.

**Next UI GA UI-94:** continue reference-led screen-visible redesign with Anomalies evidence/queue density or Settings operational composition after fresh live-head, ledger and consumer audit. Never substitute tooltip micro-edits; keep all changes **SOURCE CANDIDATE — UNVERIFIED** until the owner explicitly says **“now it is test time.”**


## GA UI-94 — Settings operations: full-width visual configuration architecture

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (1672×941 dark SOC screenshot) was retrieved and visually inspected **before GitHub inspection**. Starting live branch HEAD: `210c029df97c00ac5d104441ad16e3fc7021ab73`. Prior design publication GA UI-93: `e28fb36b93d4c8bb83a825c613c0539401d48820`. Intervening independent R563 Modbus and R564 Redis commits were already present and are preserved. Private source commit `537f03c7af9d76b80a005ea862b1a934e960b070` is a direct child of `210c029df97c00ac5d104441ad16e3fc7021ab73`, with source tree `b9c784ddce6c62ae4be2fd426e68a52c930478f7`. Source and this ledger entry must publish together through one non-forced atomic expected-SHA lease.

### Approved reference and visible before → after

The reference uses a deep-navy SOC shell, cyan information hierarchy, prominent page identity and layered operational cards. Its IPs, throughput, sensor counts, incident counts, rule IDs, confidence, timestamps and capture-health indicators are **DEMO ONLY** and have not been introduced into application data.

- **Full-width Settings shell:** previously a centered max-800px form with a small plain title; now a full-width graphite/navy operations workspace with a 29px title, cyan **APPLICATION PREFERENCES / LOCAL CONFIGURATION** eyebrow and accurate configuration context. No fake monitoring status is displayed.
- **Four visual sections:** Detection Sensitivity, Enrichment & Capture, Dashboard & Sections and developer-only Demo Mode retain their existing GroupBoxes/handlers but use dedicated dark gradient cards, 20px headings, cyan section eyebrows, teal divider lines, 14px corner geometry and consistent padding. This is a screen-visible layout redesign, not tooltip-only.
- **Wide ≥1440:** Detection Sensitivity and Enrichment & Capture appear side by side in a 0.95:1.45 two-column grid, followed by a full-width Dashboard & Sections card and the full-width demo card if enabled. The capture panel has more room for its existing 300px BPF and masked-key controls.
- **Standard 1100–1439:** cards stack in one column and dashboard section toggles use two columns.
- **Compact 1024–1099:** stacked cards and two-column dashboard toggles. **Below 1024:** dashboard toggles become one column, and the sensitivity/capture label columns narrow from 160px to 130px for control reachability.
- **Behavior boundaries:** all existing controls, x:Names, bindings, click/selection handlers, session-only API-key masking, WHOIS/reputation options, BPF semantics, preference Save/Reset scope, immediate dashboard toggle persistence, presets, developer demo visibility and original runtime filter effects remain unchanged in source. No working CLI, new capture, synthetic telemetry, network lookup, or fabricated security-health signal.

### Static start/end divergence and provenance

Start review inspected the live branch, recent commits, ledger through UI-93, `MainWindow.xaml`, `Theme.xaml`, `MainWindow.Settings.cs`, `MainWindow.Responsive.cs`, Settings navigation and the existing Dashboard responsive pattern. End source review found the original `SaveSettings_Click`, `ResetSettings_Click`, `ApplyApiKey_Click`, `DashboardSectionToggle_Changed`, `SensitivityCombo_SelectionChanged` and demo handlers still referenced. The existing responsive dispatcher now invokes a Settings-only layout method; no other responsive consumer, service, engine, rule, protocol, capture/trust/privacy, test, workflow, runner, project or shared API was edited.

**Owned paths / source blobs:**
1. `Carthago/Views/MainWindow.xaml` — `bbf03c09cdae81a4e5c15ed91f26be8d237715d0` (prior `5dabf655b7b5668d9ac272870a6af0b4a3822400`).
2. `Carthago/Views/Theme.xaml` — `1dc73eb447f7ea12e75c4ba3ea91c7aa25568e3b` (prior `c5492c0f9aa953f38af83da43b01daa3dfec33e8`).
3. `Carthago/Views/MainWindow.Settings.cs` — `1d7a390bf49ebcc2bd969df03db9387f721a8b15` (prior `ffc4b7f7fdcfc6ed53fb8fe42b832334eb5c34b8`).
4. `Carthago/Views/MainWindow.Responsive.cs` — `01605d572744938443ecb455f42dde1a813a6b70` (prior `1a4b6bcfbaf89a1f39d3e665f28e5da65395f31d`).
5. `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` — this entry.

**Static visual-impact assessment:** full-width hero, four visibly restyled cards, a new side-by-side Wide configuration composition, responsive stacked layouts and 3/2/1 dashboard-toggle density. **WPF compilation, runtime rendering, keyboard behavior, screen-reader semantics, high-DPI behavior and screenshots remain UNVERIFIED.** No tests/builds/replays/holdouts/CI/Actions/runners/benchmarks/production capture were executed.

**Risks — UNVERIFIED:** at 1440px and high DPI, the narrower sensitivity card's three-column factor explanation may crowd; existing fixed-width 300px BPF/password and 220px sensitivity controls may need scrolling at 640px; custom GroupBox templates may affect focus/automation header semantics or contrast; 3-column dashboard checkboxes may have uneven row heights; the pre-existing API-key status ambiguity between environment and session overrides remains.

### Planned acceptance — ALL UNEXECUTED

1. Visually compare the full-width Settings hero, cyan hierarchy, dark section cards and spacing with the approved 1672px screenshot, ignoring its DEMO values.
2. At Wide 1440px and 125%, 150%, 200% DPI, inspect side-by-side sensitivity/capture cards, factor comparison, BPF/key controls and gutters.
3. At Standard 1100–1439, inspect single-column cards and two-column dashboard toggles.
4. At Compact 1024–1099, inspect stacked configuration, section title wrapping and keyboard reachability.
5. Below 1024 (1023, 800, 640), inspect single-column toggles, 130px label widths, masked credentials, full scrolling and absence of clipping.
6. Verify Save/Reset preserve original preference scope, messages, no-confirmation behavior and active Npcap filter reapplication.
7. Verify dashboard toggles still persist immediately, and presets apply/reset without deleting incidents or retained events.
8. Verify WHOIS, AbuseIPDB, session-only key override, BPF and auto-start controls retain their original behavior and source-accurate status.
9. Verify developer demo remains explicitly SIMULATED and source-gated; local PPS ScottPlot, Live Events 80/500, unavailable CLI, Cisco/WebView2 and capture/privacy/trust boundaries remain untouched.
10. Verify exactly five authorized paths, source→docs direct-parent ancestry, one non-forced expected-SHA publication and **zero** builds/tests/replays/holdouts/CI/runners/benchmarks/capture.

**Next independent GA UI-95:** continue reference-led, screen-visible improvement to evidence density or navigation consistency after a fresh live-head and consumer audit; never revert to tooltip-only batches. No tests until the owner explicitly authorizes **“now it is test time.”**


## GA UI-95 — Cross-screen security operations navigation shell

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** Exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` was retrieved and **visually inspected first**, before any GitHub inspection. It depicts a dark left navigation rail, strong Carthago brand identity, cyan active navigation and distinct SOC panel hierarchy. Its IPs, throughput, incident/rule counts, timestamps, confidence and CLI text are **DEMO ONLY**. No screenshot data or implied capture-health state was added. Starting live feature-branch HEAD `fc5846abd0d4d9940a6462f8795f2f3668a3a448`, with prior UI GA-94 publication `7f4139f23b2a3aef757e0f2d05eba97f0733dca2`; independent R565 detection source/tests/docs already existed and were not touched. Private source commit `a9d5e039998472dc6a99fc4476cfa561b08e3d87` (source tree `ef3ed8e94ba137820e422f014c580bef343916ff`) is a direct child of that starting HEAD. Source and this ledger must be published together in one non-forced expected-SHA branch update.

### Reference mapping and visible before → after

- **Navigation shell:** previously a mostly flat dark left column with a plain header; now a layered navy/graphite gradient rail with a teal-tinted brand header, clearer 18px Carthago wordmark, cyan secondary identity and a refined bordered brand glyph. The footer receives a matching dark gradient. This changes the visible application shell on every screen without altering navigation destinations.
- **Primary navigation:** previously small unframed Unicode icons and relatively tight rows; now all **20 existing sidebar glyphs** (19 named destinations plus the existing inert Collapse visual) have consistent 26px dark framed icon surfaces in 28px grid slots. The 42px minimum row height, aligned text, tighter but deliberate gutters and stronger section labels create a more legible, repeated navigation rhythm.
- **Active/hover hierarchy:** previously `SetActiveNavButton` assigned a local `Background` value, which could override theme-driven hover/active styling; now it only maintains the existing `Tag="Active"` and `AutomationProperties.ItemStatus` selection cues. The UI-owned `NavButton` template supplies a visible cyan selection rail, navy/teal active gradient, outlined selected row, hover and pressed surfaces. Original click handlers, keyboard focus visual and selected-nav mapping remain.
- **Section organization:** WORKSPACE, ADVANCED / FORENSICS, PLATFORM and SETTINGS retain their original order, scroll position model, filter expanders and destination names. Four sidebar-specific dividers and cyan section headings distinguish groups without hiding any page or creating new functionality.
- **Responsive fidelity:** existing MainWindow shell widths (Wide 216, Standard 200, Compact 60) and thresholds remain unchanged. The existing compact glyph-only navigation, brand text/footer collapse, 320px temporary filter drawer, and scrollable navigation are preserved in source; icon frames and nav padding were sized for the 60px rail. Actual rendering and high-DPI reachability remain unverified.
- **No synthetic operations:** no monitoring/capture health, new badges, telemetry, CLI execution, network requests or source-level incident/protocol changes. The existing `Collapse` visual remains inert; this GA does not claim it works.

**Static visual-impact assessment:** a persistent, cross-screen visual shell refresh affecting brand, all 20 icon presentations, active/hover rows, group rhythm and footer. Unlike UI-01–89 micro-edits, the visible navigation system is restructured across every workspace. This is source inspection only; **actual WPF appearance has not been rendered or validated**.

### Ownership, provenance and static divergence review

Initial inspection: live branch ref and recent commits, ledger through UI-94, `Sidebar.xaml`, `Sidebar.xaml.cs`, `Theme.xaml`, `MainWindow.xaml`, `MainWindow.Navigation.cs`, `MainWindow.Responsive.cs`, and all existing sidebar event handlers, filter consumers, navigation keys and active-state controls. End static source review: all 19 named nav controls and original click handlers remain; the 20 original glyph strings are retained within new icon frames; all four sections and filter expanders retain their names/order; active selection continues to use `Tag` and automation item status. No new C# APIs, handlers, services or dependencies.

**UI-owned source blobs (previous → new):**

1. `Carthago/Views/Sidebar.xaml`: `1868699ec454733b0c56bd93fdc72bb165316a1c` → `eacc8dc348f0b57ae182f82df21697bf92d0d96e`.
2. `Carthago/Views/Sidebar.xaml.cs`: `30cf0d63ff32818861a52a3ccd399c8753c6f3c2` → `0c422f0d0b189390870376a8ec4f594614e09181`.
3. `Carthago/Views/Theme.xaml`: `1dc73eb447f7ea12e75c4ba3ea91c7aa25568e3b` → `9ea915a3d3f6975209011cd8dfe800d8e6d97662`.
4. `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md`: this documentation-only entry.

**Ownership boundaries:** only `Carthago/Views/**` and `docs/design/**`. No `Engine/**`, `Models/**`, `Services/**`, rule/protocol files/docs, telemetry/capture/trust/privacy, tests, workflows, runners, `Carthago.csproj`, shared APIs or independent automations were modified. Local PPS ScottPlot (10-sample average, 120-point history), prioritized incidents, investigation, read-only Live Events (80 shown/500 retained), visual-only UNAVAILABLE CLI, Cisco and WebView2 are untouched.

**Risks — UNVERIFIED:** new WPF template/resource resolution and icon alignment have not been compiled; active-versus-hover trigger precedence, keyboard focus, 60px Compact icon centering, 200px Standard long-label clipping, filter drawer expansion, high-contrast/DPI and 19-button scrolling require Windows visual verification. The existing inert Collapse visual and settings destinations that share the Settings view remain unchanged. Removing the previous code-behind background assignment is intended to permit theme active/hover styling; its runtime effect is unverified.

### Planned acceptance scenarios — ALL UNEXECUTED

1. At 1648px compare brand, active rail, icon framing and dark section hierarchy with the approved screenshot; treat all screenshot data as demo only.
2. At Wide >=1440 and 125%, 150%, 200% DPI inspect 216px sidebar, title fit, active gradients, icon alignment, footer and navigation scroll.
3. At Standard 1100–1439 inspect 200px sidebar, long labels, active/hover contrast and section separators.
4. At Compact 1024–1099 inspect 60px glyph-only rail, centered 26px frames, hidden headings/footer and navigation focus/scroll.
5. Below 1024 (1023/800/640) inspect compact rail and existing 320px temporary traffic/detection/sink filter drawers for clipping and dismissal.
6. Verify each named navigation destination, current selection, hover/pressed states, focus visual, tooltips and automation item status with keyboard and pointer.
7. Verify filter expanders and Apply/Clear controls retain original events and are reachable in full/compact modes.
8. Confirm `Collapse` remains inert (no false functionality claim), settings routes retain existing destinations and no synthetic incident/capture badges appear.
9. Confirm Dashboard PPS ScottPlot, Live Events 80/500, prioritized incidents/investigation, UNAVAILABLE visual-only CLI, Cisco/WebView2, and privacy/trust/capture boundaries remain unchanged.
10. Verify exact four authorized paths, source/docs direct-parent ancestry, single non-forced expected-SHA publication and **zero** builds/tests/replays/holdouts/CI/Actions/runners/benchmarks/capture.

**Next UI GA UI-96:** a fresh reference-led, screen-visible operations enhancement after live-head/ledger/consumer audit; prioritize content readability or visual information architecture without repeating navigation or tooltip-only batches. All changes remain **SOURCE CANDIDATE — UNVERIFIED** until the owner explicitly says **“now it is test time.”**


## GA UI-96 — Host Integrity: local inventory evidence workspace redesign

**2026-11-02 · SOURCE CANDIDATE — UNVERIFIED.** The exact approved ChatGPT Library image `libfile_b0a34361560c8191b641e432b3e6b15c` was retrieved and visually inspected **before** GitHub source inspection. Starting LIVE feature-branch HEAD: `02d9440207a6af995242da24334684b3000a505c`. Prior UI publication GA UI-95: `323828de3d49b3894205ba650d40d134d344fc82`. The subsequent independent verification ledger, UI chart-redraw, R566 Redis detection and CSA session/archive/export candidate commits were already on the live branch; none was changed. This UI-owned milestone follows GA UI-95 and does **not** repeat the navigation, incident, anomaly, dashboard, Live Events or Settings redesigns.

### Approved reference mapping and screen-visible before → after

The approved image shows a dark navy/graphite SOC shell, cyan operational hierarchy, large high-signal KPI cards, organized investigation panels and dense readable evidence tables. Its sensor counts, Mbps, rule IDs, incident confidence, timestamps, IPs and CLI output are **DEMO ONLY**. No screenshot values or capture-health indicators were introduced.

- **Page composition:** formerly a small 18px heading and cramped horizontal score/risk/rescan row above a flat tabbed grid. Now a full-width navy/teal gradient hero with 28px page title, cyan local-inventory eyebrow, existing dynamic scan summary, and a dedicated rescan action surface. The hero does not claim active monitoring or a successful scan.
- **Three evidence-grounded metric cards:** the original code-behind's `HostScoreText`, `HostRiskText` and `ScanTimeText` are redistributed into prominent dark cards labeled **Highest Observed Score**, **Highest Observed Risk**, and **Scan Provenance**. The values remain produced by the existing local driver/software scan; the score is a maximum of scanned records, not a whole-device assurance or live capture metric. Before any successful scan, the XAML placeholders are neutral (em dash / Not scanned) rather than a synthetic score of zero or `Info` risk.
- **Inventory investigation panel:** a new layered dark evidence surface gives the existing two tabs a shared title, provenance explanation, consistent padding and clearer section hierarchy. Driver and software tables retain all original columns, read-only/virtualized behavior, horizontal and vertical scrolling, original context menus and existing suspicious-only filters. Table rows become 38px and headers 42px with alternating dark surfaces and restrained borders.
- **Responsive layout:** Wide >=1440 and Standard 1100–1439 show three metric cards across; Compact 1024–1099 stacks the scan-provenance card beneath two metric cards and moves each suspicious-only filter beneath its tab heading; below 1024 the same compact layout applies, with a further single-column three-card stack when actual page width falls below 700px. Hero rescan action moves beneath the summary in Compact. Existing MainWindow responsive dispatch is reused through the UI-only `IResponsiveLayoutAware` interface; no shared contract changed.
- **No operational invention:** no new telemetry, score computation, detection, driver scan, uninstall action, command, capture source, security policy, network request, synthetic badge or persistence change. This milestone improves a previously under-styled local inventory screen rather than making another tooltip-only change.

### Static ownership and consumer/divergence review

At start, inspected the live remote branch SHA and recent commits, ledger through GA UI-95, exact reference image, `HostIntegrityPage.xaml`, `HostIntegrityPage.xaml.cs`, `MainWindow.Navigation.cs`, `MainWindow.Responsive.cs`, `MainWindow.xaml`, `ResponsiveLayout.cs` and existing `Theme.xaml` styles. The navigation creates `HostIntegrityPage` on demand and already calls `ApplyResponsiveLayoutTo(HostIntegrityFrame.Content)`. The original code-behind writes the same five scan/action/filter controls and reads the same two DataGrid selections. The new responsive method only repositions named UI elements and does not call scan or data services.

Source commit ancestry (all private until one atomic publication): `02d9440207a6af995242da24334684b3000a505c` → `105aa408188c7612edf1c068d2c1cd0d578e4c12` (page architecture) → `9733dd17196c47b74f0e8bfd26be5a54a4f6ddfa` (responsive UI) → `021c90f19c48ed05d6ca0e71685b6599bc850bfe` (WPF-supported typography source correction). Final source tree: `85fb557a7924c1665fcba6743bfc35a6ebf1bb1f`.

**Authorized source paths / blobs:**
1. `Carthago/Views/HostIntegrityPage.xaml` — `2576e26de1bddc21f61d624078be162e104dd801` (prior `0622533d4f689b1bc8ca173113975000460a5534`).
2. `Carthago/Views/HostIntegrityPage.xaml.cs` — `2d8ef8787c5fb6b5c75b0ac20f7a04eb63d42a73` (prior `4a99043fd62ee91fb84afd66b1d068457602937d`).
3. `docs/design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md` — this entry.

**Static end review:** original `SummaryText`, `ScanTimeText`, `HostScoreText`, `HostRiskText`, `RescanButton`, `IntegrityTabControl`, `DriversGrid`, `AppsGrid`, both suspicious-only checkboxes and all original click/checked/unchecked/context-menu handlers are retained. All original DataGrid columns and bindings are preserved. Only two `Carthago/Views/**` files plus this `docs/design/**` ledger change. No Engine, Models, Services, rules/protocols, telemetry/capture/trust/privacy, tests, benchmarks, workflows, runners, project files, shared APIs, or independent automation settings changed.

**Static visual-impact assessment:** major full-screen visual reorganization of an existing page, including a 28px gradient hero, separate action surface, three KPI cards, a structured evidence workspace, taller dark tables and explicit compact reflow. This is source inspection, **not** a rendered WPF screenshot or a verified layout.

**Risks — UNVERIFIED:** new WPF resources and DataGrid style inheritance require compilation; 3-card Standard widths, hero rescan reflow, scan-timestamp wrapping, 700px nested breakpoint, 125–200% DPI, tab-header visibility, keyboard navigation and horizontal evidence scrolling require actual Windows visual verification. The existing local scan can fail or be incomplete; no new health claims are made. Existing context-menu uninstall/open-location actions remain available and unchanged. At small window heights the evidence grid may be short; users may need scrolling or resizing.

### Planned acceptance scenarios — ALL UNEXECUTED

1. Compare hero, dark/cyan hierarchy, three cards and evidence surface against the approved screenshot while ignoring all DEMO metrics.
2. At Wide >=1440 and 125%, 150%, 200% DPI inspect three metric cards, rescan action, title wrapping and table height.
3. At Standard 1100–1439 inspect three-card density, dynamic scan-summary text and scan-time provenance.
4. At Compact 1024–1099 inspect two metric cards plus stacked scan card, rescan action and both filter placements.
5. At 1023, 800, 700 and 640px inspect the additional actual-width <700 single-column stack, no clipping and accessible tab headers.
6. Verify the initial neutral unscanned placeholders and existing successful-scan summary, highest-score/risk values and scan times.
7. Verify Rescan, driver/app suspicious-only toggles, both grid selections and all original context-menu actions retain their exact behavior.
8. Verify all original driver and software columns, bindings, read-only virtualization, horizontal scrolling, keyboard focus and screen-reader labels.
9. Verify Dashboard local PPS ScottPlot 10-sample average/120-point history, Live Events 80/500, prioritized incidents, visual-only UNAVAILABLE CLI, Cisco/WebView2 and privacy/capture/trust boundaries remain unaffected.
10. Verify published three-path change scope, source→docs parent ancestry, one non-forced expected-SHA branch update, and **zero** builds/tests/replays/holdouts/CI/Actions/runners/benchmarks/production capture.

**Next UI GA UI-97:** after fresh live-head/reference/consumer audit, deliver another cohesive screen-visible operations redesign (consider Threat Feed evidence density or Integrations configuration architecture). Do not repeat tooltip-only batches. All UI changes remain **SOURCE CANDIDATE — UNVERIFIED** until explicit owner authorization: **“now it is test time.”**
