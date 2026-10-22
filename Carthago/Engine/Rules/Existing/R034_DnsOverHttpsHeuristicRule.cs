// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R034_DnsOverHttpsHeuristicRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R034_DnsOverHttpsHeuristicRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R034",
            Name: "DNS-over-HTTPS Heuristic",
            Category: "DNS",
            Description: "DNS-over-HTTPS heuristic",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R034.Enabled",
            EnabledByDefault: true);
    }
}
