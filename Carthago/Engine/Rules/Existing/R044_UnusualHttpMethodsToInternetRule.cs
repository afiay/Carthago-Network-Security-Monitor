// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R044_UnusualHttpMethodsToInternetRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R044_UnusualHttpMethodsToInternetRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R044",
            Name: "Unusual HTTP Methods to Internet",
            Category: "HTTP",
            Description: "Unusual HTTP methods to internet",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R044.Enabled",
            EnabledByDefault: true);
    }
}
