# CARTHAGO SOC workspace integration

**Approved direction:** Integrate the ten analyst capabilities into the existing WPF application and reuse real producers. Branch `feature/carthago-reliability-hardening` only. No separate browser application or unconnected showcase pages.

## Goals and boundaries

- A finding can be followed from overview to its exact incident, host/flow, detection, and available evidence, without opening a second window.
- Monitoring health has a dedicated, accessible first-class destination showing actual source and UI-delivery counters. Zero, unavailable, paused, degraded, and error states must not be conflated.
- Preserve the existing live capture, rule behavior, privileges, privacy controls, WPF layout model, 3-second chart redraw cadence, and 80-displayed/500-retained Live Events limits.
- Never create values for unknown sensor inventory, detection coverage, host process attribution, geolocation precision, packet evidence, or incident outcomes.
- Introduce functional milestones in sequence. A navigation label is not a claim that its backing feature exists.
- UI source changes remain unverified until the owner separately authorizes Windows WPF builds, manual renders, and runtime tests.

## Integration map

| Capability | Primary location | Context entry point and underlying contract |
| --- | --- | --- |
| Monitoring Health | Overview / Operations navigation | Current capture source, capture-flow and delivery snapshots; source labels distinguish Npcap parse failures from ETW drops and UI queue drops |
| Network Investigation Explorer | Live Traffic | Source/destination host and flow selection; direct actions from Incidents and Anomalies using actual identifiers |
| Advanced Traffic Analytics | Analytics | Existing ScottPlot PPS/protocol/top-talker series; separate inbound/outbound only after direction-aware capture producer is verified |
| Incident Timeline | Incidents | Selected incident chronology plus explicit related events and evidence, no inferred linkage by matching IP alone |
| Geographic Threat Explorer | Analytics map | Source-linked IP context; approximate geolocation clearly labeled; private IPs never mapped to invented public coordinates |
| Global Investigation Search | Main command header | IP, domain, rule, port, and incident pivots using real view/filter contracts with bounded searches |
| Detection Coverage Center | Detection Rules / Overview | Rule registration, enabled/executed/validated states, each with its own defensible denominator |
| Analyst Workflow Management | Incident Queue / Incidents | Existing case status, notes, false-positive feedback and actual persistence; later ownership only with identity contract |
| Customizable Workspace | Settings | Persisted preferences, responsive density, saved filters and accessible keyboard navigation |
| Secure Reporting | File / Incidents / Analytics | Existing session and multi-sheet Excel export augmented with source-bound scope and access checks; web RBAC remains separate |

## Delivery strategy

1. **Operational foundation:** Monitoring Health page, explicit Overview shortcut and sidebar navigation, source-accurate counters, and a route back to Live Traffic. The page refreshes through the existing monitoring status ticker and never adds packet-path work.
2. **Investigation pivots:** Dedicated flow/host exploration, contextual incident/anomaly/traffic links, preserved time and selection, with bounded read-only evidence.
3. **Analytics and map:** Historical time-range controls and efficient series; location precision and separate local/public address representation.
4. **Triage and coverage:** Search, trustworthy rule coverage, and case history/assignment when supported by identity/persistence contracts.
5. **Operator preferences and reporting:** User-controlled layout, integrated export/report routes, and role-enforced complementary statistics only after authorization design.

## Current implementation milestone

**SOC-01 — 2026-11-09 — SOURCE CANDIDATE / UNVERIFIED.** The first milestone adds a Monitoring Health workspace to the operations sidebar, a contextual Overview hero shortcut, and a link back to Live Traffic. It uses the existing `TrafficCaptureService.GetCaptureFlowSnapshot()` and `GetCaptureSourceHealth()` snapshots through `MainWindow.UpdateMonitoringHeader` rather than a new capture subscription. Npcap parse errors, ETW source drops and the UI queue's drops are presented as distinct counters. Last analysis is labeled historical rather than a live heartbeat; paused/offline views disclose that nonzero counters are retained session observations.

The first milestone intentionally changes only monitoring-health presentation and navigation. It does **not** establish multi-sensor inventory, network-wide traffic visibility, complete PCAP reconstruction, or verified detection accuracy. Later milestones remain pending until implemented and verified separately.

**SOC-02 — SOURCE CANDIDATE / UNVERIFIED.** A Network Investigation Explorer now connects retained in-memory traffic and detections through a bounded search, a sidebar entry, selected-source/destination actions in Live Traffic and Raw Detections, and a global header search. A matched address means matching source/destination fields only; it does not establish incident correlation or prove complete flow history. The page also links directly to Analytics/Geographic Context, Live Traffic and Raw Detections. Exact IP matching, text matching and all navigation are currently source-only and require owner-authorized WPF runtime verification.

**SOC-03 — SOURCE CANDIDATE / UNVERIFIED.** The Detection Rules navigation now opens a dedicated Detection Coverage Center backed by `RuleCatalog.HealthSnapshots()` and the existing rule catalog validator and runtime/telemetry stores. The Overview hero, Settings sensitivity section and Network Investigation Explorer provide contextual routes to it. It distinguishes current runtime alert mode, process-local evaluation counters, structural catalog findings and telemetry kinds observed since process start. Explicitly **not** reported as proof of replay-test success or detection accuracy. Rule snapshots run on a background task on first open or manual refresh; capture and detection behavior are unchanged. WPF build and runtime verification remain owner-gated.

**SOC-04 — SOURCE CANDIDATE / UNVERIFIED.** The existing Incidents chronology and analyst feedback remain authoritative. Selected-case source IP and destination host actions now open the local Network Investigation Explorer inside MainWindow, without asserting that matching retained traffic belongs to that incident. The explorer's global search accepts `port:443`-style exact source/destination port queries and additional recorded detection event, flow, correlation and destination-host identifiers. The source-only checkpoint does not change incident matching or persistence.

**SOC-05 — SOURCE CANDIDATE / UNVERIFIED.** Analytics provides immediate 30/60/120-second time-window controls over the already retained local PPS samples, changing chart axes only and preserving the original one-second sample and three-second redraw cadence. The existing geographic map now supports clicking a plotted IP marker to open that address in Network Investigation. Display labels explicitly say IP geography is approximate; invalid coordinates, local, shared and representative reserved addresses are rejected rather than plotted as real world positions. No new geolocation source or host-precise guarantee is introduced.

**SOC-06 — SOURCE CANDIDATE / UNVERIFIED.** Incident Queue's existing triage, status and selected-case timeline stay in place; a new source-IP pivot routes to the Network Explorer without conflating case membership and address matches. Analytics, the full Incidents workspace and Incident Queue now offer the existing multi-sheet Excel export from their task context. A deliberate confirmation names retained-data coverage and sensitive free-text limitations before the native file dialog. All routes invoke the existing local exporter and scope/redaction implementation; there is no new report backend or unverified RBAC claim.

**SOC-07 — SOURCE CANDIDATE / UNVERIFIED.** The Network Investigation Explorer now supports explicit save/open/remove of up to 10 text pivots (IP, domain, rule ID, port query). This uses the existing atomic local preferences file, normalizes oversized/duplicate entries, and deep-copies bookmarks in `AppPreferences.Clone()`. Bookmarks never save evidence rows or capture packets; sensitive identifiers in the query itself persist only after the analyst chooses Save current. Workspace Settings provides a contextual link to manage saved searches. Existing Dashboard section visibility controls remain authoritative.

No WPF build, test, runner job, live capture or rendered screenshot was performed for SOC-01; all runtime and accessibility acceptance checks remain unexecuted under the owner's standing instruction.

## Alternatives considered

- **Integrated WPF workspaces (selected):** Existing navigation, filters, privacy and data bindings remain authoritative; contextual drill-downs reduce duplicated UI.
- **Separate SOC hub:** Faster to draw but duplicates navigation and creates disconnected analytical state; rejected.
- **UI-only demonstration screens:** Easy to produce but risks claiming functionality without data; rejected.
