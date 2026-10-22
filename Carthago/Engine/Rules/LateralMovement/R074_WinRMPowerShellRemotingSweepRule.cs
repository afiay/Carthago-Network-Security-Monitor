// SPDX-License-Identifier: MIT
// File: Engine/Rules/LateralMovement/R074_WinRMPowerShellRemotingSweepRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R074_WinRMPowerShellRemotingSweepRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R074",
            Name: "WinRM / PowerShell Remoting Sweep",
            Category: "LateralMovement",
            Description: "Concrete telemetry-driven rule for WinRM / PowerShell Remoting Sweep. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R074.Enabled",
            EnabledByDefault: true);
    }
}
