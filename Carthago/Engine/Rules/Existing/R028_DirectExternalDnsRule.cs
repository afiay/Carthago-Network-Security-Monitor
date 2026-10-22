// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R028_DirectExternalDnsRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R028_DirectExternalDnsRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R028",
            Name: "Direct External DNS",
            Category: "DNS",
            Description: "Direct external DNS resolver usage",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R028.Enabled",
            EnabledByDefault: true);
    }
}
