// SPDX-License-Identifier: MIT
// File: Engine/Rules/Health/R052_SinkQueueBackpressureRule.cs
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Health
{
    public sealed class R052_SinkQueueBackpressureRule : DetectionRuleBase
    {
        private readonly HealthCounterTransition _transition = new();

        public override RuleDescriptor Descriptor => new(
            RuleId: "R052",
            Name: "Sink Queue Backpressure",
            Category: "Detection-engine health",
            Description: "Sink delivery queue is blocked or backpressured.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R052.Enabled",
            EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!HealthEvidenceGate.IsFresh(context)
                || !_transition.Observe(context.HealthSnapshot.SinkBackpressureCount, context.HealthSnapshot.TimestampUtc))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(RuleEvaluationResult.Match(Descriptor.RuleId, CreateHealthEvent(context, $"Sink backpressure observed. Count={context.HealthSnapshot.SinkBackpressureCount}.")));
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
