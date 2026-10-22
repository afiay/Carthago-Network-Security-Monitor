// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R042_UncommonQuicAlpnRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R042_UncommonQuicAlpnRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R042",
            Name: "Uncommon QUIC ALPN",
            Category: "QUIC",
            Description: "Uncommon QUIC ALPN",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R042.Enabled",
            EnabledByDefault: true);
    }
}
