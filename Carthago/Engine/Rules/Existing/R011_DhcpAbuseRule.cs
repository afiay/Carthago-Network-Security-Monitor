// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R011_DhcpAbuseRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R011_DhcpAbuseRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R011",
            Name: "DHCP Abuse",
            Category: "Network",
            Description: "Suspicious DHCP activity",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R011.Enabled",
            EnabledByDefault: true);
    }
}
