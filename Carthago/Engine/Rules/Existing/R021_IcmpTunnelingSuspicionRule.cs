// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R021_IcmpTunnelingSuspicionRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R021_IcmpTunnelingSuspicionRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R021",
            Name: "ICMP Tunneling Suspicion",
            Category: "ICMP",
            Description: "Possible ICMP tunneling",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R021.Enabled",
            EnabledByDefault: true);
    }
}
