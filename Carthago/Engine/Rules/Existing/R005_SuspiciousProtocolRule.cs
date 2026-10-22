// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R005_SuspiciousProtocolRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R005_SuspiciousProtocolRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R005",
            Name: "Suspicious Protocol",
            Category: "Protocol",
            Description: "Suspicious or unexpected protocol usage",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R005.Enabled",
            EnabledByDefault: true);
    }
}
