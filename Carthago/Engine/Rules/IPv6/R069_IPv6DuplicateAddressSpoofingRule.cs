// SPDX-License-Identifier: MIT
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.AssetInventory;
using Carthago.Models;
using Carthago.Services.Baseline;

namespace Carthago.Engine.Rules.IPv6
{
    public sealed class R069_IPv6DuplicateAddressSpoofingRule : TelemetryDetectionRuleBase
    {
        private readonly AssetConflictTracker _state = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R069", Name: "IPv6 Duplicate Address / Spoofing", Category: "IPv6",
            Description: "Corroborated conflicting IPv6 neighbor-advertisement identity; not proof of spoofing.",
            DefaultSeverity: SeverityLevel.High, ConfigKey: "Rules.R069.Enabled", EnabledByDefault: true);
        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Ipv6BatchEvidence.NeighborAdvertisement(context.Record, out var address, out var mac)
                || BaselineStore.Current.IsLearningMode || !BaselineStore.Current.Readiness.IsReady)
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            var matched = _state.Observe(address, mac, context.TimestampUtc);
            return ValueTask.FromResult(matched
                ? RuleEvaluationResult.Match(Descriptor.RuleId,
                    Ipv6BatchEvidence.Alert(Descriptor, context,
                        "Conflicting IPv6 neighbor-advertisement source identity corroborated."))
                : RuleEvaluationResult.NoMatch(Descriptor.RuleId));
        }
    }
}
