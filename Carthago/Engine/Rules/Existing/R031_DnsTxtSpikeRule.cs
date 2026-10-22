// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R031_DnsTxtSpikeRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R031_DnsTxtSpikeRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R031",
            Name: "DNS TXT Spike",
            Category: "DNS",
            Description: "DNS TXT query spike",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R031.Enabled",
            EnabledByDefault: true);
    }
}
