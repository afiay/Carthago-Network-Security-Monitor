// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R001_PortScanRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R001_PortScanRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R001",
            Name: "Port Scan",
            Category: "Network",
            Description: "Port scan against multiple destination ports",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R001.Enabled",
            EnabledByDefault: true);
    }
}
