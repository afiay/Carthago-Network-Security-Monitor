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
