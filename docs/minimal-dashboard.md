# Carthago Minimal Dashboard

Carthago now uses a minimal, settings-driven dashboard instead of showing every security surface on the main screen.

## Concept

The dashboard is a configurable security workspace. On first launch, or after resetting the dashboard, the main view can be empty by design.

The default message is:

> Your dashboard is empty
>
> Enable sections or add widgets from Settings to build your security workspace.

Raw telemetry, rule detections, sink delivery logs, Cisco tools, and other forensic data remain available from the Advanced / Forensics navigation area. They are no longer forced into the primary dashboard.

## Dashboard & Sections settings

Open **Settings → Dashboard & Sections** to activate dashboard sections:

- Incidents
- Anomalies
- Statistics
- Timeline
- Baseline learning
- ML-assisted scoring
- Recommended actions
- Raw/Advanced shortcuts
- Cisco section
- External delivery
- Forensics shortcuts
- Developer demo section

Disabled sections do not render on the main dashboard. They can still remain accessible from navigation when they are advanced/forensic views.

The section checkboxes apply immediately. The normal **Save Settings** button still persists the rest of the settings form, such as sensitivity, enrichment, capture filter, and auto-start behavior.

## Adding widgets

From the dashboard toolbar:

1. Choose a widget from the widget picker.
2. Choose a metric when adding a statistics card.
3. Select **Add widget**.

If no dashboard sections are active, the Add widget action safely enables the Statistics section and adds a basic Active Incidents statistics card.

## Statistics customization

Statistics are user-selected instead of hardcoded.

Supported metrics include:

- Active incidents
- Critical incidents
- High incidents
- New anomalies in 15 minutes
- New anomalies in 1 hour
- Highest risk host
- Threat feed hits
- Baseline confidence
- ML-assisted anomaly count
- Suppressed incidents
- False positive count
- Confirmed suspicious count
- Raw detections count
- External delivery failures
- Cisco critical events
- Demo incident count

Each statistics card stores its selected metric and selected time window in dashboard preferences under the widget settings dictionary:

- `MetricKey`
- `TimeWindow`

The card supports common windows such as `15m`, `1h`, `24h`, and `7d`. Time-window-aware metrics, such as New anomalies, recalculate from the selected window.

## Reordering widgets

Widgets support two reorder paths:

- Drag a widget card and drop it onto another widget card.
- Use the left/right arrow buttons as a safe fallback.

The widget order is persisted through `AppPreferences.Dashboard.Widgets[].Order`.

## Recommended layouts

Recommended layouts can be applied from the dashboard toolbar or Settings:

### Minimal Security Overview

- Active incidents
- High/Critical incidents
- New anomalies 15m
- Incident queue
- Anomaly timeline

### SOC Analyst View

- Incident queue
- Highest-risk incident
- Recommended actions
- Timeline
- High-risk hosts

### Network Admin View

- Cisco status
- External delivery
- Raw/forensics shortcuts
- Active incidents
- Threat feed hits

### Demo View

Available only when demo mode is enabled.

- Demo controls
- Active incidents
- Incident queue
- Timeline
- Recommended actions

## Resetting the dashboard

Use **Reset dashboard** in Settings to return to the minimal empty state.

This does not remove incidents, anomalies, raw traffic, capture settings, sink settings, or demo data. It only resets dashboard preferences.

## Persistence

Dashboard settings are stored inside the existing application preferences file:

- `AppPreferences.Dashboard.UseMinimalDashboard`
- `AppPreferences.Dashboard.ShowEmptyDashboardByDefault`
- `AppPreferences.Dashboard.Widgets`
- section activation flags
- selected preset id
- per-widget settings such as `MetricKey` and `TimeWindow`

Old preference files load safely. Missing dashboard configuration is normalized to a minimal empty dashboard.

## Demo mode integration

The Developer Demo Mode section and Demo Controls widget are visible only when demo mode is available.

- Debug builds enable demo mode automatically.
- Release builds require `--demo-mode`.
- Demo data remains labeled and can be cleared without deleting real incidents.

## Known limitations

- Widget resize is represented through persisted column/row span and preset sizing. Freeform resize handles are not implemented yet.
- WPF UI automation tests are not included; behavior is covered through model/service tests where practical.
- The minimal dashboard is designed for current in-memory analytics snapshots. Long-term historical dashboard analytics should be backed by a dedicated store if the product later needs time-range analytics across restarts.

## Serious anomaly workspace design pass

The Anomalies view now follows the same minimal, anomaly-first direction as the dashboard:

- The left panel is a focused anomaly timeline with baseline status, filters, linked-incident filter, risk score circles, severity badges, and a clear selected state.
- The right panel is a serious SOC-style signal detail surface with one dominant finding, a risk-score indicator, grouped evidence fields, reasons, rule IDs, tags, guidance, and linked-incident context.
- Raw detections and traffic remain outside this view in Advanced / Forensics; the anomaly page only shows analyst-ready evidence.
- Long host and destination values are wrapped inside field cards so the view stays readable on smaller screens.
- The action area is limited to Copy JSON and Clear so the view remains calm and operational rather than noisy.

Validation checklist for this design pass:

1. Open Anomalies with and without demo mode.
2. Confirm the first anomaly is selected automatically when data exists.
3. Confirm category/severity filters still work.
4. Confirm Ctrl+F focuses anomaly search.
5. Confirm Copy JSON still exports the selected anomaly.
6. Confirm the count footer updates after filter/search/clear.
7. Confirm the view remains readable when the app window is resized.


## Grouped anomaly timeline

The anomaly workspace now collapses similar anomaly signals by category, source host, destination, protocol, and port. This prevents repeated ML/baseline windows from overwhelming the analyst while preserving the latest signal details, grouped occurrence count, exportable evidence, and raw/advanced telemetry access.

ML-assisted anomaly evidence is shown in a readable form: model name, confidence, score, top feature drivers, and analysis window appear as evidence chips. Raw feature values remain available under Raw feature values for deeper review.


## Elegant responsive UI pass

The dashboard shell now uses a calmer enterprise dark theme, larger readable cards, responsive command bars, and safer wrapping rules for narrow windows. The main shell, sidebar, dashboard canvas, anomaly workspace, and incident workspace use shared card, command-bar, and input styles instead of scattered one-off styling. Advanced/raw views remain available, but the default visual priority is now anomaly triage, incident context, and user-selected widgets.

Design intent:

- serious SOC-style visual hierarchy;
- responsive WPF layouts using grids, wrap panels, and scroll viewers;
- compact navigation groups;
- readable technical values such as IPv6 hosts and rule IDs;
- dashboard customization controls that wrap instead of overflowing;
- consistent cards, pills, controls, scrollbars, and data grids across the project.
