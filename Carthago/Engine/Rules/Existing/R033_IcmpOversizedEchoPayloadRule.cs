// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R033_IcmpOversizedEchoPayloadRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R033_IcmpOversizedEchoPayloadRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R033",
            Name: "ICMP Oversized Echo Payload",
            Category: "ICMP",
            Description: "Oversized ICMP echo payload",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R033.Enabled",
            EnabledByDefault: true);
    }
}
