# v21 — No-inner-scroll anomaly timeline fix

This pass removes the nested scrollbars from the dashboard anomaly timeline and keeps the SOC dashboard closer to the reference layout.

## Changes

- Disabled the anomaly timeline ListBox vertical and horizontal inner scrollbars.
- Added a WPF-safe stretched ListBoxItem template so anomaly rows measure against the available viewport instead of creating a horizontal scrollbar.
- Made anomaly rows compact enough to show five rows without an inner scroll.
- Added ellipsis and tooltips for long IPv6, destination, and rule text.
- Changed anomaly ordering to prioritize highest-risk signals first, then newest signals.
- Prevented the New Anomalies KPI from showing zero when anomaly signals exist outside the strict 15-minute window.
- Preserved data binding and demo-mode behavior.

No fake production data was added.
