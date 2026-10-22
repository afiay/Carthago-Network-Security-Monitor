// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R014_CleartextCredentialsRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R014_CleartextCredentialsRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R014",
            Name: "Cleartext Credentials",
            Category: "Payload",
            Description: "Cleartext credential exposure",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R014.Enabled",
            EnabledByDefault: true);
    }
}
