# Carthago SOC dashboard visual alignment v10

This pass aligns the default dashboard more closely with the target SOC workspace screenshot.

## Changes

- The dashboard command strip is collapsed by default so the page opens directly into the SOC workspace.
- The default window size is widened to better fit the five-card KPI strip, the triage workspace, and three lower widgets.
- KPI cards are slightly wider and remain responsive through the existing wrapping layout.
- Anomaly rows and recommended-action rows now use one-line truncation with ellipsis instead of growing vertically.
- High-risk host rows keep a compact host label and expose the full host value by tooltip.
- Long IPv6 and DNS labels are shortened deterministically to prevent vertical wrapping.

## Data behavior

No fake production data was added. The dashboard continues to project runtime data from the existing analytics, incident, anomaly, baseline, and threat-detection pipelines. Demo data remains controlled by `--demo-mode`.
