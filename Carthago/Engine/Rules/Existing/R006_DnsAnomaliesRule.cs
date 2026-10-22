// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R006_DnsAnomaliesRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R006_DnsAnomaliesRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R006",
            Name: "DNS Anomalies",
            Category: "DNS",
            Description: "DNS anomaly detected",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R006.Enabled",
            EnabledByDefault: true);
    }
}
