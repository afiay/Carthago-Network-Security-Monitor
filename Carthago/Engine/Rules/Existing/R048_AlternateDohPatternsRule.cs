// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R048_AlternateDohPatternsRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R048_AlternateDohPatternsRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R048",
            Name: "Alternate DoH Patterns",
            Category: "DNS",
            Description: "Alternate DNS-over-HTTPS pattern",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R048.Enabled",
            EnabledByDefault: true);
    }
}
