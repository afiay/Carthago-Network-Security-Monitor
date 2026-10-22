// SPDX-License-Identifier: MIT
// File: Engine/Rules/Health/R050_RuleExecutionGapRule.cs
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Health
{
    public sealed class R050_RuleExecutionGapRule : DetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R050",
            Name: "Rule Execution Gap",
            Category: "Detection-engine health",
            Description: "Rule evaluation has stopped or exceeded the allowed gap.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R050.Enabled",
            EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var last = context.HealthSnapshot.LastEvaluationUtc;
            if (last.HasValue && (context.TimestampUtc - last.Value).TotalSeconds <= 10)
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            if (!last.HasValue)
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(RuleEvaluationResult.Match(Descriptor.RuleId, CreateHealthEvent(context, $"Rule execution gap detected: {(context.TimestampUtc - last.Value).TotalSeconds:F0}s since last evaluation.")));
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
