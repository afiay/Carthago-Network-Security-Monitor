// SPDX-License-Identifier: MIT
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.AssetInventory
{
    public sealed class R062_NewServiceOpenedOnInternalHostRule : TelemetryDetectionRuleBase
    {
        private readonly AssetNetworkState _state = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R062", Name: "New Service Opened on Internal Host", Category: "AssetInventory",
            Description: "Evidence-driven asset observation, not an authorization verdict.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R062.Enabled",
            EnabledByDefault: true);
        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context,CancellationToken cancellationToken=default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!AssetNetworkEvidence.ServerReply(context,out var host,out var port)
                || !_state.Service(host,port,context.TimestampUtc))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(RuleEvaluationResult.Match(Descriptor.RuleId,
                AssetNetworkEvidence.Alert(Descriptor,context,"New internal service port corroborated by two server responses; verify inventory.")));
        }
    }
}
