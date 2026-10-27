// SPDX-License-Identifier: MIT
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.AssetInventory
{
    public sealed class R061_SensitiveHostCommunicatingExternallyRule : TelemetryDetectionRuleBase
    {
        
        public override RuleDescriptor Descriptor => new(
            RuleId: "R061", Name: "Sensitive Host Communicating Externally", Category: "AssetInventory",
            Description: "Evidence-driven asset observation, not an authorization verdict.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R061.Enabled",
            EnabledByDefault: true);
        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context,CancellationToken cancellationToken=default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!AssetNetworkEvidence.Outbound(context,out _,out _) || !AssetNetworkEvidence.SensitiveSource(context.Record))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(RuleEvaluationResult.Match(Descriptor.RuleId,
                AssetNetworkEvidence.Alert(Descriptor,context,"Corroborated sensitive-service source initiated public egress; review host role.")));
        }
    }
}
