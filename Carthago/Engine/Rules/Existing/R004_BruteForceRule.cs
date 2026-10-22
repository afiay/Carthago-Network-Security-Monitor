// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R004_BruteForceRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R004_BruteForceRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R004",
            Name: "Brute Force",
            Category: "Identity",
            Description: "Repeated authentication attempts",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R004.Enabled",
            EnabledByDefault: true);
    }
}
