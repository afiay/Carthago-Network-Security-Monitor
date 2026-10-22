# Carthago v20 SOC reference alignment pass

This pass continues aligning the WPF shell and dashboard to the SOC reference screenshot.

## Changes

- Tightened the top command header proportions.
- Kept the five KPI cards inline and tuned card height, padding, value size, icon boxes, and sparkline space.
- Increased the main triage workspace height so the anomaly timeline, signal details, and lower widgets align closer to the reference.
- Added a WPF-safe dark CheckBox template so native white checkboxes no longer break the dark SOC style.
- Strengthened the dark ComboBox styling for the capture-source selector.
- Added active sidebar state, so the selected navigation row remains highlighted like the reference.
- Tuned sidebar typography and spacing.
- Added a dedicated timeline item style for anomaly rows.

## Constraints preserved

- No generated `bin/` or `obj/` files.
- No `.env` secrets.
- No fake production data.
- Dashboard remains bound to the existing analytics/anomaly/incident state.
- Demo data remains controlled by `--demo-mode`.
