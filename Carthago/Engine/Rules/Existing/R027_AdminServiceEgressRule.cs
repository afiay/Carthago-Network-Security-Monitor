// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R027_AdminServiceEgressRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R027_AdminServiceEgressRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R027",
            Name: "Admin Service Egress",
            Category: "Egress",
            Description: "Administrative service exposed outbound",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R027.Enabled",
            EnabledByDefault: true);
    }
}
