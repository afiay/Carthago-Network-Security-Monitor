// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R002_FloodDosRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R002_FloodDosRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R002",
            Name: "Flood / DoS",
            Category: "Network",
            Description: "Flood or denial-of-service behavior",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R002.Enabled",
            EnabledByDefault: true);
    }
}
