// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R036_HeavyEgressToSingleExternalHostRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R036_HeavyEgressToSingleExternalHostRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R036",
            Name: "Heavy Egress to Single External Host",
            Category: "Exfiltration",
            Description: "Heavy egress to one external host",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R036.Enabled",
            EnabledByDefault: true);
    }
}
