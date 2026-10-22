# KPI exact inline alignment v16

This pass makes the top SOC KPI strip match the reference layout more closely.

## Changes

- Keeps the five primary KPI cards in one inline row using a fixed 5-column `UniformGrid`.
- Reduces KPI card padding, minimum height, icon size, value size, trend height, and card spacing.
- Prevents the Baseline Confidence card from wrapping into a second row at normal desktop widths.
- Keeps all KPI values data-bound to the existing dashboard projection.
- Does not add fake production data or change demo-mode behavior.

## Files changed

- `Views/MainWindow.xaml`
- `Views/Theme.xaml`
