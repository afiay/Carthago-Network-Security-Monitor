// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R043_SniHttpHostMismatchRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R043_SniHttpHostMismatchRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R043",
            Name: "SNI / HTTP Host Mismatch",
            Category: "HTTP",
            Description: "SNI and HTTP Host mismatch",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R043.Enabled",
            EnabledByDefault: true);
    }
}
