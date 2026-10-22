// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R049_SuspiciousSniShapeRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R049_SuspiciousSniShapeRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R049",
            Name: "Suspicious SNI Shape",
            Category: "TLS",
            Description: "Suspicious SNI shape",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R049.Enabled",
            EnabledByDefault: true);
    }
}
