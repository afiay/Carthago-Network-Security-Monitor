// SPDX-License-Identifier: MIT
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.AssetInventory
{
    public sealed class R059_SameMACUsingMultipleIPsRule : TelemetryDetectionRuleBase
    {
        private readonly AssetConflictTracker _tracker = new();

        public override RuleDescriptor Descriptor => new(
            RuleId: "R059",
            Name: "Same MAC Using Multiple IPs",
            Category: "AssetInventory",
            Description: "Corroborated local-link inventory observation; no unauthorized-device assertion.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R059.Enabled",
            EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(RuleEvaluationContext context,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!AssetInventoryClaimEvidence.TryRead(context, out var claim)
                || !(_tracker.Observe(claim.Mac, claim.Ip, context.TimestampUtc)))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(RuleEvaluationResult.Match(Descriptor.RuleId,
                AssetInventoryClaimEvidence.Event(Descriptor, context, claim.Ip,
                    "A local MAC claimed multiple private IP addresses; verify aliases and DHCP state.")));
        }
    }
}
