// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R037_Ja4DriftPerSniRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R037_Ja4DriftPerSniRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R037",
            Name: "JA4 Drift per SNI",
            Category: "TLS",
            Description: "JA4 drift for an SNI",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R037.Enabled",
            EnabledByDefault: true);
    }
}
