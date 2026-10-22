// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R016_ReputationAbuseIpdbRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R016_ReputationAbuseIpdbRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R016",
            Name: "Reputation / AbuseIPDB",
            Category: "Threat Intel",
            Description: "Destination reputation match",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R016.Enabled",
            EnabledByDefault: true);
    }
}
