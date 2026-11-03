# Carthago v14 SOC visual-alignment pass

This pass continues the dashboard alignment toward the compact anomaly-first SOC reference.

## Changed areas

- Compact left navigation matching the reference grouping: Security View, Advanced / Forensics, Platform, Settings.
- Sidebar now uses icon-led one-line rows instead of verbose description rows.
- Navigation active state is tracked in the sidebar code-behind.
- Added PCAP Explorer and Forensics Workspace shortcuts to the sidebar while routing them to the existing advanced/raw views.
- Lower dashboard widgets were narrowed so High-Risk Hosts, Recommended Actions, and Raw / Advanced Shortcuts can sit in one row at the target desktop width.
- Raw / Advanced shortcut cards now use icon-led tiles similar to the reference.
- KPI delta wording now follows the reference style: “vs 15m ago”.

## Product constraints preserved

- No fake production data was added.
- Existing demo-mode behavior remains the only path for demo data.
- Existing raw/advanced pages remain accessible.
- Existing dashboard preferences and empty dashboard behavior are preserved.
- No generated `bin/`, `obj/`, or `.env` files are included in the package.
