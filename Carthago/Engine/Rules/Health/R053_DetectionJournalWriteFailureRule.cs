// SPDX-License-Identifier: MIT
// File: Engine/Rules/Health/R053_DetectionJournalWriteFailureRule.cs
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Health
{
    public sealed class R053_DetectionJournalWriteFailureRule : DetectionRuleBase
    {
        private readonly HealthCounterTransition _transition = new();

        public override RuleDescriptor Descriptor => new(
            RuleId: "R053",
            Name: "Detection Journal Write Failure",
            Category: "Detection-engine health",
            Description: "Mandatory detection journal failed to persist events.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R053.Enabled",
            EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!HealthEvidenceGate.IsFresh(context)
                || !_transition.Observe(context.HealthSnapshot.JournalWriteFailureCount, context.HealthSnapshot.TimestampUtc))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(RuleEvaluationResult.Match(Descriptor.RuleId, CreateHealthEvent(context, $"Detection journal write failure observed. Count={context.HealthSnapshot.JournalWriteFailureCount}.")));
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
