# KPI inline alignment v15

This pass updates the dashboard KPI strip to match the reference more closely.

## Changes

- Replaced the KPI `WrapPanel` with a 5-column `UniformGrid` so the five primary KPI cards stay inline.
- Removed fixed KPI tile width and let each card size to the available row width.
- Reduced KPI padding, text sizing, icon sizing, and sparkline height slightly so the cards feel tighter and closer to the target screenshot.
- Preserved existing data binding and anomaly-first behavior.

## Files changed

- `Views/MainWindow.xaml`
- `Views/Theme.xaml`
