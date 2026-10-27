// SPDX-License-Identifier: MIT
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.AssetInventory
{
    public sealed class R065_FirstTimeASNForHostRule : TelemetryDetectionRuleBase
    {
        private readonly AssetNetworkState _state = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R065", Name: "First-Time ASN for Host", Category: "AssetInventory",
            Description: "Evidence-driven asset observation, not an authorization verdict.",
            DefaultSeverity: SeverityLevel.Low, ConfigKey: "Rules.R065.Enabled",
            EnabledByDefault: true);
        public override async ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context,CancellationToken cancellationToken=default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!AssetNetworkEvidence.Outbound(context,out var host,out _)
                || !AssetNetworkEvidence.Asn(context.Record.WhoisASN,out var asn))
                return RuleEvaluationResult.NoMatch(Descriptor.RuleId);
            var matched=await AssetNetworkBaseline.Observe(_state,context,"host_asn",host,asn,3,cancellationToken).ConfigureAwait(false);
            return matched ? RuleEvaluationResult.Match(Descriptor.RuleId,
                AssetNetworkEvidence.Alert(Descriptor,context,"New destination ASN corroborated against a ready persisted baseline."))
                : RuleEvaluationResult.NoMatch(Descriptor.RuleId);
        }
    }
}
