// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R017_InternalHostSweepRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R017_InternalHostSweepRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R017",
            Name: "Internal Host Sweep",
            Category: "Reconnaissance",
            Description: "Internal host sweep behavior",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R017.Enabled",
            EnabledByDefault: true);
    }
}
