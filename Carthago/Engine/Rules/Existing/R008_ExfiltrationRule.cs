// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R008_ExfiltrationRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R008_ExfiltrationRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R008",
            Name: "Exfiltration",
            Category: "Exfiltration",
            Description: "Possible data exfiltration behavior",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R008.Enabled",
            EnabledByDefault: true);
    }
}
