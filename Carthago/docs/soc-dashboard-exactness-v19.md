# Carthago v19 SOC exactness pass

This pass continues visual alignment of the local-first SOC dashboard toward the reference layout.

## Changes

- Flattened the top command area into a shell-like header with a subtle bottom divider instead of a rounded card.
- Kept the five KPI cards inline while improving their reference-like proportions, icon boxes, and sparkline visibility.
- Tuned main triage and lower widget heights so the anomaly timeline, signal details, and lower cards sit closer to the reference viewport rhythm.
- Strengthened dark ComboBox rendering by forcing foreground inheritance inside the WPF template.
- Tightened shortcut tile text and lower-card spacing to avoid wrap artifacts.

## Data behavior

No fake production data was added. The dashboard remains bound to the existing incident, anomaly, baseline, detection, and demo-mode pipelines.

## Packaging

The delivered packages exclude `bin/`, `obj/`, and `.env`.
