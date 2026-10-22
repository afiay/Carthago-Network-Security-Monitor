// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R019_EncodedLongUriRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R019_EncodedLongUriRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R019",
            Name: "Encoded / Long URI",
            Category: "HTTP",
            Description: "Encoded or unusually long URI",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R019.Enabled",
            EnabledByDefault: true);
    }
}
