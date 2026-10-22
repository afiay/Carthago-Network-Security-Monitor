# Carthago v8 SOC Dashboard Workspace

This pass converts the main dashboard from generic widget cards into a focused SOC workspace while preserving the existing settings-driven dashboard preference model.

## Goals

- Match the dark, serious, anomaly-first console direction.
- Keep raw traffic, raw detections, delivery logs, PCAP-style workflows, and forensics shortcuts accessible without dominating the default dashboard.
- Keep production data data-bound. No fake production rows are added.
- Keep developer demo data limited to `--demo-mode` through the existing analytics/demo pipeline.
- Preserve the existing hidden legacy KPI/plot controls so the older analytics update pipeline continues to compile and run.

## Dashboard structure

The recommended layout now projects enabled dashboard widgets into a richer workspace:

1. KPI strip
   - Active incidents
   - High-risk hosts
   - New anomalies in the last 15 minutes
   - Threat feed hits
   - Baseline confidence

2. Anomaly timeline
   - Recent anomaly signals from the analytics host.
   - Risk score, severity, host, destination, protocol, and timestamp are derived from `AnomalySignal`.

3. Signal details
   - Selected anomaly details.
   - Related incident context when correlation exists.
   - Reasons, tags, rule IDs, and investigation actions.

4. Lower workspace
   - High-risk hosts table.
   - Recommended actions from the highest-risk incident.
   - Raw / advanced shortcuts.

5. Collapsed layout manager
   - Keeps the existing widget preference collection visible on demand.
   - Keeps safe reorder/remove actions available without cluttering the normal SOC view.

## Data binding rules

The workspace is projected from existing runtime data:

- `Incident` snapshots from `AnalyticsHost.GetRecentIncidents(...)`.
- `AnomalySignal` snapshots from `AnalyticsHost.GetRecentAnomalies(...)`.
- baseline status from `AnalyticsHost.GetBaselineStatus()`.
- raw detections from the existing `_alerts` collection.
- dashboard preferences from `PreferencesService.Current.Dashboard`.

No production rows are hardcoded. Empty states remain empty until monitoring or demo mode produces data.

## Navigation preservation

The dashboard shortcuts route to existing views:

- Raw Traffic -> `Nav_LiveTraffic_Click`
- Raw Detections -> `Nav_Alerts_Click`
- PCAP Explorer -> Raw Traffic fallback
- Forensics Workspace -> Raw Detections fallback
- Investigate Host / View Related Incident -> incident workspace

## Packaging constraints

Generated folders and local secrets must remain excluded:

- no `bin/`
- no `obj/`
- no `.env`
