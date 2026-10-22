// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R030_InternalAdminLateralSweepRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R030_InternalAdminLateralSweepRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R030",
            Name: "Internal Admin Lateral Sweep",
            Category: "Lateral Movement",
            Description: "Internal admin lateral sweep",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R030.Enabled",
            EnabledByDefault: true);
    }
}
