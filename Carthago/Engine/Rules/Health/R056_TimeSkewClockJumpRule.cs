// SPDX-License-Identifier: MIT
// File: Engine/Rules/Health/R056_TimeSkewClockJumpRule.cs
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Health
{
    public sealed class R056_TimeSkewClockJumpRule : DetectionRuleBase
    {
        private readonly ClockSkewEpisodeTransition _transition = new();

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
            if (!HealthEvidenceGate.IsFresh(context)
                || !_transition.Observe(context.HealthSnapshot.ClockSkew, context.HealthSnapshot.TimestampUtc))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));

            // Do not include exact clock offsets or host identifiers in the alert.
            const string summary = "Clock skew exceeded the existing 60-second health threshold.";
            return ValueTask.FromResult(RuleEvaluationResult.Match(Descriptor.RuleId, new DetectionEvent
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
                Evidence = "Fresh health snapshot; skew threshold crossed."
            }));
        }
    }
}
