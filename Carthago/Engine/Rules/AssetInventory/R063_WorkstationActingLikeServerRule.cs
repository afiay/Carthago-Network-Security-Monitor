// SPDX-License-Identifier: MIT
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.AssetInventory
{
    public sealed class R063_WorkstationActingLikeServerRule : TelemetryDetectionRuleBase
    {
        private readonly AssetNetworkState _state = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R063", Name: "Workstation Acting Like Server", Category: "AssetInventory",
            Description: "Evidence-driven asset observation, not an authorization verdict.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R063.Enabled",
            EnabledByDefault: true);
        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context,CancellationToken cancellationToken=default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!AssetNetworkEvidence.Inbound(context,out var host,out var peer,out var port)
                || !_state.FanIn(host+":"+port,peer,context.TimestampUtc))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(RuleEvaluationResult.Match(Descriptor.RuleId,
                AssetNetworkEvidence.Alert(Descriptor,context,"Internal endpoint received initiations from five distinct peers; verify approved role.")));
        }
    }
}
