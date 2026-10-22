// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R023_TlsToPublicIpWithoutSniRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R023_TlsToPublicIpWithoutSniRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R023",
            Name: "TLS to Public IP Without SNI",
            Category: "TLS",
            Description: "TLS to public IP without SNI",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R023.Enabled",
            EnabledByDefault: true);
    }
}
