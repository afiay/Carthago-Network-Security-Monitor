# SOC dashboard high-risk host layout fix (v9)

This pass fixes the compressed High-Risk Hosts card that could appear when the lower SOC widgets were forced into a three-column grid on narrower windows.

## Changed

- Replaced the lower fixed three-column dashboard grid with a wrapping layout so the High-Risk Hosts, Recommended Actions, and Raw / Advanced Shortcuts cards can move to the next row instead of shrinking into unreadable columns.
- Reduced the High-Risk Hosts table column widths and shortened `Incidents` to `Inc.`.
- Added a compact host display label for very long IPv6 / DNS values.
- Preserved the full host value in the row tooltip.
- Disabled wrapping for host and trend cells so values use ellipsis instead of breaking vertically.

## Preserved

- No fake production data.
- Existing incident/anomaly-driven host projection.
- Existing demo-mode behavior.
- Existing raw/advanced shortcut navigation.
- Existing dashboard settings and widget preference pipeline.
