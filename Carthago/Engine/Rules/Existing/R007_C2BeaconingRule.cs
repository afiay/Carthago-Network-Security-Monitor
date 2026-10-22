// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R007_C2BeaconingRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R007_C2BeaconingRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R007",
            Name: "C2 Beaconing",
            Category: "Behavior",
            Description: "Command-and-control beaconing pattern",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R007.Enabled",
            EnabledByDefault: true);
    }
}
