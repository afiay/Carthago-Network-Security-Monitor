// SPDX-License-Identifier: MIT
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services.Baseline;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.AssetInventory;
using Carthago.Models;

namespace Carthago.Engine.Rules.IPv6
{
    public sealed class R067_RogueIPv6RouterAdvertisementRule : TelemetryDetectionRuleBase
    {
        private readonly AssetConflictTracker _state = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R067", Name: "Rogue IPv6 Router Advertisement", Category: "IPv6",
            Description: "Corroborated router-advertisement source identity change; does not establish authorization.",
            DefaultSeverity: SeverityLevel.High, ConfigKey: "Rules.R067.Enabled", EnabledByDefault: true);
        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Ipv6BatchEvidence.RouterAdvertisement(context.Record, out var router, out var mac)
                || BaselineStore.Current.IsLearningMode || !BaselineStore.Current.Readiness.IsReady)
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            // Never persist a raw MAC in the durable baseline. A ready baseline
            // gates an in-memory, per-rule corroborated identity transition.
            var matched = _state.Observe(router, mac, context.TimestampUtc);
            return ValueTask.FromResult(matched
                ? RuleEvaluationResult.Match(Descriptor.RuleId,
                    Ipv6BatchEvidence.Alert(Descriptor, context,
                        "IPv6 router advertisement identity changed after corroborated observations."))
                : RuleEvaluationResult.NoMatch(Descriptor.RuleId));
        }
    }
}
