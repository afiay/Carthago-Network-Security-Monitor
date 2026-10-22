// SPDX-License-Identifier: MIT
// File: Engine/Rules/Health/R056_TimeSkewClockJumpRule.cs
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Health
{
    public sealed class R056_TimeSkewClockJumpRule : DetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R056",
            Name: "Time Skew / Clock Jump",
            Category: "Detection-engine health",
            Description: "Local clock skew or jump exceeded threshold.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R056.Enabled",
            EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (System.Math.Abs(context.HealthSnapshot.ClockSkew.TotalSeconds) < 60)
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(RuleEvaluationResult.Match(Descriptor.RuleId, CreateHealthEvent(context, $"Clock jump/skew detected: {context.HealthSnapshot.ClockSkew.TotalSeconds:F0}s.")));
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
