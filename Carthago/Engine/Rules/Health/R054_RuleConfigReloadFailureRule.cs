// SPDX-License-Identifier: MIT
// File: Engine/Rules/Health/R054_RuleConfigReloadFailureRule.cs
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Health
{
    public sealed class R054_RuleConfigReloadFailureRule : DetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R054",
            Name: "Rule Config Reload Failure",
            Category: "Detection-engine health",
            Description: "Rule configuration reload failed; previous config remains active.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R054.Enabled",
            EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (context.HealthSnapshot.ConfigReloadFailureCount <= 0)
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(RuleEvaluationResult.Match(Descriptor.RuleId, CreateHealthEvent(context, $"Rule config reload failure observed. Count={context.HealthSnapshot.ConfigReloadFailureCount}.")));
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
