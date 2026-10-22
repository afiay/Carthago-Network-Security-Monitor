# v18 SOC dashboard density alignment

This pass tightens the dashboard toward the provided reference screenshot without introducing fake production data.

## Changes

- Reduced KPI card height, padding, icon size, and sparkline text size so all five cards remain inline and visually closer to the reference.
- Reduced the main anomaly/signal workspace height so the lower widgets are visible in the first viewport.
- Tightened anomaly rows, detail cards, risk score ring, and lower cards.
- Added icon-led shortcut tiles to better match the reference.
- Forced the capture-source ComboBox through the dark theme template to prevent a white native Windows control surface.
- Collapsed the internal layout-manager expander from the default dashboard viewport; customization remains available through the top Customize button/settings path.

## Data behavior

The dashboard remains data-bound to the existing incidents, anomaly projections, baseline status, threat-feed projections, and demo-mode path. This pass does not add fake production data.
