// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R024_RareNovelTlsFingerprintRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R024_RareNovelTlsFingerprintRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R024",
            Name: "Rare / Novel TLS Fingerprint",
            Category: "TLS",
            Description: "Rare TLS fingerprint",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R024.Enabled",
            EnabledByDefault: true);
    }
}
