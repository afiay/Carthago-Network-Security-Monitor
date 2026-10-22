# v17 SOC visual alignment pass

This pass aligns the WPF dashboard more closely with the provided reference screenshot.

## Changes

- Reduced sidebar width and rebuilt the sidebar as a compact icon-led SOC navigation rail.
- Reworked the top KPI strip as five inline, equal-width cards.
- Reduced KPI height, padding, icon size, and typography so Baseline Confidence stays inline.
- Restored compact sparkline/baseline indicator text inside KPI cards.
- Reduced the main triage workspace height so lower widgets appear in the same viewport like the reference.
- Converted the lower widgets area to a fixed three-column grid.
- Tightened anomaly timeline rows, detail cards, host rows, recommended actions, and shortcut tiles.
- Added a WPF-safe dark ComboBox template so capture source and filters no longer render as default white controls.
- Kept all dashboard values data-bound to existing incidents, anomalies, baseline, and threat feed state.
- No fake production data added.
