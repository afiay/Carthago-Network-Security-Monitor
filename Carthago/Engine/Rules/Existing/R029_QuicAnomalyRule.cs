// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R029_QuicAnomalyRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R029_QuicAnomalyRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R029",
            Name: "QUIC Anomaly",
            Category: "QUIC",
            Description: "QUIC anomaly detected",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R029.Enabled",
            EnabledByDefault: true);
    }
}
