// SPDX-License-Identifier: MIT
// File: Engine/Rules/Health/R055_ThreatFeedStaleRule.cs
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Health
{
    public sealed class R055_ThreatFeedStaleRule : DetectionRuleBase
    {
        private readonly HealthFeedStalenessTransition _transition = new();

        public override RuleDescriptor Descriptor => new(
            RuleId: "R055",
            Name: "Threat Feed Stale",
            Category: "Detection-engine health",
            Description: "Threat feed has not been refreshed within the configured interval.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R055.Enabled",
            EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var lastFeed = context.HealthSnapshot.LastThreatFeedUpdateUtc;
            if (!HealthEvidenceGate.IsFresh(context)
                || !_transition.Observe(lastFeed, context.HealthSnapshot.TimestampUtc))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(RuleEvaluationResult.Match(Descriptor.RuleId, CreateHealthEvent(context, $"Threat feed stale: last update {lastFeed.Value:O}.")));
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
