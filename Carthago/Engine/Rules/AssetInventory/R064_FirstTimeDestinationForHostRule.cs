// SPDX-License-Identifier: MIT
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.AssetInventory
{
    public sealed class R064_FirstTimeDestinationForHostRule : TelemetryDetectionRuleBase
    {
        private readonly AssetNetworkState _state = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R064", Name: "First-Time Destination for Host", Category: "AssetInventory",
            Description: "Evidence-driven asset observation, not an authorization verdict.",
            DefaultSeverity: SeverityLevel.Low, ConfigKey: "Rules.R064.Enabled",
            EnabledByDefault: true);
        public override async ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context,CancellationToken cancellationToken=default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!AssetNetworkEvidence.Outbound(context,out var host,out var destination))
                return RuleEvaluationResult.NoMatch(Descriptor.RuleId);
            var matched=await AssetNetworkBaseline.Observe(_state,context,"host_destination",host,destination,8,cancellationToken).ConfigureAwait(false);
            return matched ? RuleEvaluationResult.Match(Descriptor.RuleId,
                AssetNetworkEvidence.Alert(Descriptor,context,"New public destination corroborated against a ready persisted baseline."))
                : RuleEvaluationResult.NoMatch(Descriptor.RuleId);
        }
    }
}
