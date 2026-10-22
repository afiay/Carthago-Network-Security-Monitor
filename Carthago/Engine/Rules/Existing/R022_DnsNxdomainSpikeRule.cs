// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R022_DnsNxdomainSpikeRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R022_DnsNxdomainSpikeRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R022",
            Name: "DNS NXDOMAIN Spike",
            Category: "DNS",
            Description: "NXDOMAIN spike detected",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R022.Enabled",
            EnabledByDefault: true);
    }
}
