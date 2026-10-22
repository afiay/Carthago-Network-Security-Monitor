# Package Audit

## Scope
- Reviewed the remaining compatibility warnings on `net8.0-windows`.
- Confirmed the JSONL detection journal remains authoritative and runtime artifacts stay outside source control.

## Findings
- `SnmpSharpNet 0.9.7` still produces `NU1701`.
- `ScottPlot.WPF 5.1.58` still brings in `SkiaSharp.Views.WPF 3.119.0`, which also produces `NU1701`.

## What Changed
- SNMP usage is now isolated behind [ISnmpClientAdapter](../Carthago/Services/Cisco/ISnmpClientAdapter.cs) and [SnmpSharpNetClientAdapter](../Carthago/Services/Cisco/SnmpSharpNetClientAdapter.cs).
- Cisco neighbor discovery now depends on the adapter instead of direct `SnmpSharpNet` calls across the service surface.
- Replay benchmarking is now a first-class local tool, with outputs written to `build-verify/`.

## Why `NU1701` Still Remains
- `SnmpSharpNet` does not ship a modern `net8.0-windows` target in the currently restored version.
- `ScottPlot.WPF` restores a package graph that still warns on `SkiaSharp.Views.WPF 3.119.0` in this environment.
- These warnings are intentionally not suppressed. They remain visible in build output until the packages are replaced or upgraded to a fully compatible combination.

## Risk Posture
- SNMP risk is now contained to one adapter boundary, which keeps the rest of the detection platform decoupled from the legacy package.
- Charting still builds and runs, but the chart stack remains a compatibility debt item until the WPF/Skia combination is upgraded cleanly.

## Recommended Next Package Actions
1. Replace `SnmpSharpNet` with a modern .NET SNMP package when network/package research is available.
2. Re-evaluate the ScottPlot/Skia WPF package combination and move to a no-warning set when a validated version matrix is available.
3. After those two items are complete, enable warning-as-error mode for CI.
