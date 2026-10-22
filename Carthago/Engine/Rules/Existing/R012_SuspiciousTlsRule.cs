// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R012_SuspiciousTlsRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R012_SuspiciousTlsRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R012",
            Name: "Suspicious TLS",
            Category: "TLS",
            Description: "Suspicious TLS behavior",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R012.Enabled",
            EnabledByDefault: true);
    }
}
