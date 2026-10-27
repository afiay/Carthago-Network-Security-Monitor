// SPDX-License-Identifier: MIT
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.IPv6
{
    public sealed class R070_Teredo6to4ISATAPTunnelUseRule : TelemetryDetectionRuleBase
    {
        private readonly Ipv6SequenceState _state = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R070", Name: "Teredo / 6to4 / ISATAP Tunnel Use", Category: "IPv6",
            Description: "Corroborated IPv6 transition-protocol use, not a policy-violation verdict.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R070.Enabled", EnabledByDefault: true);
        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Ipv6BatchEvidence.Transition(context.Record, out var kind, out var flow))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            var matched = _state.Observe(kind + ":" + flow, context.TimestampUtc);
            return ValueTask.FromResult(matched
                ? RuleEvaluationResult.Match(Descriptor.RuleId,
                    Ipv6BatchEvidence.Alert(Descriptor, context,
                        "Repeated IPv6 transition-protocol traffic corroborated on one flow."))
                : RuleEvaluationResult.NoMatch(Descriptor.RuleId));
        }
    }
}
