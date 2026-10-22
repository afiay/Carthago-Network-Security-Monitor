// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R032_SuspiciousEmptyHttpUserAgentRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R032_SuspiciousEmptyHttpUserAgentRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R032",
            Name: "Suspicious / Empty HTTP User-Agent",
            Category: "HTTP",
            Description: "Suspicious or empty User-Agent",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R032.Enabled",
            EnabledByDefault: true);
    }
}
