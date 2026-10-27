// SPDX-License-Identifier: MIT
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.AssetInventory
{
    public sealed class R057_NewDeviceAppearedOnNetworkRule : TelemetryDetectionRuleBase
    {
        private readonly AssetNoveltyTracker _tracker = new();

        public override RuleDescriptor Descriptor => new(
            RuleId: "R057",
            Name: "New Device Appeared on Network",
            Category: "AssetInventory",
            Description: "Corroborated local-link inventory observation; no unauthorized-device assertion.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R057.Enabled",
            EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(RuleEvaluationContext context,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!AssetInventoryClaimEvidence.TryRead(context, out var claim)
                || !(_tracker.Observe(claim.Mac, context.TimestampUtc, silentFirst: false)))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(RuleEvaluationResult.Match(Descriptor.RuleId,
                AssetInventoryClaimEvidence.Event(Descriptor, context, claim.Ip,
                    "A previously unseen local device was corroborated by two ARP claims; review inventory.")));
        }
    }
}
