// SPDX-License-Identifier: MIT
// File: Engine/Rules/Health/R051_PacketCaptureDropSurgeRule.cs
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Health
{
    public sealed class R051_PacketCaptureDropSurgeRule : DetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R051",
            Name: "Packet Capture Drop Surge",
            Category: "Detection-engine health",
            Description: "Packet capture drop counter increased above threshold.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R051.Enabled",
            EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (context.HealthSnapshot.CaptureDropDelta <= 0)
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(RuleEvaluationResult.Match(Descriptor.RuleId, CreateHealthEvent(context, $"Capture drop surge detected: {context.HealthSnapshot.CaptureDropDelta} packets dropped before DetectionEvent creation.")));
        }

        private DetectionEvent CreateHealthEvent(RuleEvaluationContext context, string summary) => new()
        {
            RuleId = Descriptor.RuleId,
            RuleName = Descriptor.Name,
            TimestampUtc = context.TimestampUtc,
            Severity = Descriptor.DefaultSeverity,
            SourceIp = "carthago-engine",
            DestinationIp = "carthago-local",
            Protocol = "health",
            Summary = summary,
            Description = summary,
            Evidence = summary
        };
    }
}
