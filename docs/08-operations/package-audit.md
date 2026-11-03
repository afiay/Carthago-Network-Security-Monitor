# Package Audit

> **Historical audit, not a current restore result.** The compatibility warnings below describe an earlier package state. Current package declarations should be checked before using them as an operational finding; no restore/build was executed for this documentation migration.

## Scope
- Reviewed the remaining compatibility warnings on `net8.0-windows`.
- Confirmed the JSONL detection journal remains authoritative and runtime artifacts stay outside source control.

## Findings
- The earlier `SnmpSharpNet 0.9.7` dependency produced `NU1701`. The current project instead declares `Lextm.SharpSnmpLib 12.5.7`; its current restore status has not been verified here.
- `ScottPlot.WPF 5.1.58` still brings in `SkiaSharp.Views.WPF 3.119.0`, which also produces `NU1701`.

## What Changed
- SNMP usage is isolated behind [ISnmpClientAdapter](../../Carthago/Services/Cisco/ISnmpClientAdapter.cs) and the current [SharpSnmpClientAdapter](../../Carthago/Services/Cisco/SharpSnmpClientAdapter.cs).
- Cisco neighbor discovery now depends on the adapter instead of direct `SnmpSharpNet` calls across the service surface.
- Replay benchmarking is now a first-class local tool, with outputs written to `build-verify/`.

## Why `NU1701` Still Remains
- The former `SnmpSharpNet` dependency did not ship a modern `net8.0-windows` target in the earlier audited version. This does not establish a warning for the current SharpSnmpLib package.
- `ScottPlot.WPF` restores a package graph that still warns on `SkiaSharp.Views.WPF 3.119.0` in this environment.
- These warnings are intentionally not suppressed. They remain visible in build output until the packages are replaced or upgraded to a fully compatible combination.

## Risk Posture
- SNMP integration remains behind one adapter boundary, limiting package-specific coupling.
- Charting still builds and runs, but the chart stack remains a compatibility debt item until the WPF/Skia combination is upgraded cleanly.

## Recommended Next Package Actions
1. Reassess SNMP dependency compatibility against the current `Lextm.SharpSnmpLib` declaration, rather than repeating the obsolete replacement recommendation.
2. Re-evaluate the ScottPlot/Skia WPF package combination and move to a no-warning set when a validated version matrix is available.
3. After those two items are complete, enable warning-as-error mode for CI.
