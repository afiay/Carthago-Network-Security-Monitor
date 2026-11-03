# Carthago v13 SOC dashboard visual alignment

This pass continues the anomaly-first SOC dashboard alignment against the reference image.

## Scope

- Tightened the top command bar so monitoring state, capture source, last analysis, and operator actions read as one enterprise SOC header.
- Reworked KPI tiles with panel menu glyphs, info glyphs, compact value/delta grouping, enclosed status icons, and stable trend text.
- Improved signal-details visual hierarchy with a dynamically colored risk ring and severity stripe.
- Prevented long signal detail values from wrapping vertically by using no-wrap text, ellipsis, and tooltips.
- Added compact section header affordances to High-Risk Hosts, Recommended Actions, and Raw / Advanced Shortcuts.
- Preserved data binding to incidents, anomalies, baseline status, detections, and demo-mode analytics.

## Non-goals

- No fake production data was added.
- No generated `bin/` or `obj/` output is included.
- No `.env` file is included.
