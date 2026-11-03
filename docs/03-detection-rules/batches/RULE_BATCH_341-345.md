# R341–R345 — Windows administration and remote-execution provenance

**CANDIDATE — UNVERIFIED.** Five consecutive rules, **70 advanced xUnit cases authored (14 per rule), ZERO executed**. Static source inspection only. The current PacketHandler/TrafficRecord capture path does not expose authenticated Task Scheduler, WAC gateway identity, WinRM command execution, WMI permanent subscription or MMC20 DCOM operation outcomes. No attack-positive events invented.

**R341 — ScheduledTaskRemoteCreationPattern (14 unexecuted cases):** `SCHEDULED_TASK_AUDIT_UNAVAILABLE`. Remote scheduled-task creation requires authenticated Task Scheduler RPC operation, principal, target and accepted creation result. Generic port 445, process descriptions, protocol strings and untrusted Info cannot independently establish the behavior.

**R342 — WindowsAdminCenterExposureProbe (14 unexecuted cases):** `WINDOWS_ADMIN_CENTER_IDENTITY_UNAVAILABLE`. Windows Admin Center exposure requires verified gateway identity, externally originated parsed request and endpoint/response evidence; port or path alone is insufficient. Generic port 6516, process descriptions, protocol strings and untrusted Info cannot independently establish the behavior.

**R343 — PowerShellRemotingEncodedCommand (14 unexecuted cases):** `WINRM_COMMAND_AUDIT_UNAVAILABLE`. PowerShell remoting encoded-command attribution requires trusted WinRM operation and process command-line audit; Info text and port 5985/5986 are insufficient. Generic port 5985, process descriptions, protocol strings and untrusted Info cannot independently establish the behavior.

**R344 — WMIEventSubscriptionRemotePattern (14 unexecuted cases):** `WMI_SUBSCRIPTION_AUDIT_UNAVAILABLE`. Remote WMI permanent event subscription requires authenticated namespace operation, filter/consumer binding, principal, target and result audit. Generic port 135, process descriptions, protocol strings and untrusted Info cannot independently establish the behavior.

**R345 — DCOMMMC20LateralIndicator (14 unexecuted cases):** `DCOM_MMC20_AUDIT_UNAVAILABLE`. MMC20 DCOM lateral execution requires validated COM activation, authenticated remote principal and ExecuteShellCommand invocation/outcome. Generic port 135, process descriptions, protocol strings and untrusted Info cannot independently establish the behavior.

Source: `Carthago/Engine/Rules/Expansion/R341_ScheduledTaskRemoteCreationPatternRule.cs`, `Carthago/Engine/Rules/Expansion/R342_WindowsAdminCenterExposureProbeRule.cs`, `Carthago/Engine/Rules/Expansion/R343_PowerShellRemotingEncodedCommandRule.cs`, `Carthago/Engine/Rules/Expansion/R344_WMIEventSubscriptionRemotePatternRule.cs`, `Carthago/Engine/Rules/Expansion/R345_DCOMMMC20LateralIndicatorRule.cs`. Tests: `Carthago.Tests/R341AdvancedAccuracyBatchTests.cs` through `Carthago.Tests/R345AdvancedAccuracyBatchTests.cs`, using existing `NetworkBatch321325Context`.

Each rule has six behavior-specific negative theory cases and eight invariants: spoofed Info, duplicate ID, out-of-order observations, independent sources, missing source, contradictory typed transport, secret-bearing metadata non-emission and original confidence/threshold/Alert profile. **All authored, NONE executed.** No authenticated positive telemetry, field accuracy, precision or emitted-alert recall is claimed. R343 previously had a synthetic replay positive based on Info/WinRM port; this new fail-closed contract is incompatible with that legacy expectation and must be reconciled only after a trusted WinRM/process audit producer and analyst review at authorized test time. Do not edit existing replay labels or frozen evidence.

No builds, dotnet, xUnit, replay, benchmark, frozen holdout, CI, GitHub Actions or runner. Single deferred verifier `scripts/verify-all-rule-batches.ps1` unchanged; PowerShell 5.1-safe. No TLS decryption or full TCP reassembly. Preserve confidence floors, thresholds, modes, approvals, baseline readiness, privacy and architecture. R102 frozen V1 FAILED 4/6, immutable; V2 pending independent licensed PCAP and analyst approval.

**Next R346–R350 then R351–R355.**
