// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R041_Ja4FanOutSweepRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R041_Ja4FanOutSweepRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R041",
            Name: "JA4 Fan-Out Sweep",
            Category: "TLS",
            Description: "JA4 fan-out sweep",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R041.Enabled",
            EnabledByDefault: true);
    }
}
