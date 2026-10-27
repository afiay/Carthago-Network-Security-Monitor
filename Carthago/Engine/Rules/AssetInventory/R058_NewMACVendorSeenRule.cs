// SPDX-License-Identifier: MIT
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.AssetInventory
{
    public sealed class R058_NewMACVendorSeenRule : TelemetryDetectionRuleBase
    {
        private readonly AssetNoveltyTracker _tracker = new();

        public override RuleDescriptor Descriptor => new(
            RuleId: "R058",
            Name: "New MAC Vendor Seen",
            Category: "AssetInventory",
            Description: "Corroborated local-link inventory observation; no unauthorized-device assertion.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R058.Enabled",
            EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(RuleEvaluationContext context,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!AssetInventoryClaimEvidence.TryRead(context, out var claim)
                || !(claim.GloballyAdministered && _tracker.Observe(claim.Oui, context.TimestampUtc, silentFirst: true)))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(RuleEvaluationResult.Match(Descriptor.RuleId,
                AssetInventoryClaimEvidence.Event(Descriptor, context, claim.Ip,
                    "A new globally administered MAC vendor prefix was corroborated; verify inventory enrichment.")));
        }
    }
}
