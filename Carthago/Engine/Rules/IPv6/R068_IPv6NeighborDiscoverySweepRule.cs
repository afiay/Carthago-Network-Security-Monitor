// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Engine.Rules.IPv6
{
    public sealed class R068_IPv6NeighborDiscoverySweepRule : TelemetryDetectionRuleBase
    {
        private readonly Ipv6DistinctWindow _state = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R068", Name: "IPv6 Neighbor Discovery Sweep", Category: "IPv6",
            Description: "Distinct unicast ICMPv6 neighbor solicitations in a bounded configured window.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R068.Enabled", EnabledByDefault: true);
        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Ipv6BatchEvidence.NeighborSolicitation(context.Record, out var source, out var target))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            var threshold = RuleEngine.GetRuleIntSetting(Descriptor.RuleId, "Threshold", 15, 1, int.MaxValue);
            var seconds = RuleEngine.GetRuleIntSetting(Descriptor.RuleId, "WindowSeconds", 300, 1, 86400);
            var matched = _state.Observe(source, target, context.TimestampUtc, threshold,
                TimeSpan.FromSeconds(seconds));
            return ValueTask.FromResult(matched
                ? RuleEvaluationResult.Match(Descriptor.RuleId,
                    Ipv6BatchEvidence.Alert(Descriptor, context,
                        "IPv6 neighbor solicitation contacted many distinct unicast targets."))
                : RuleEvaluationResult.NoMatch(Descriptor.RuleId));
        }
    }
}
