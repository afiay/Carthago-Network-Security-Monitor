// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R003_ThreatFeedHitRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R003_ThreatFeedHitRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R003",
            Name: "Threat Feed Hit",
            Category: "Threat Intel",
            Description: "Traffic matched threat feed intelligence",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R003.Enabled",
            EnabledByDefault: true);
    }
}
