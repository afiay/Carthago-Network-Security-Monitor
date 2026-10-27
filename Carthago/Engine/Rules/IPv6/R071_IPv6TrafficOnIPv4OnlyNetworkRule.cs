// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.Baseline;
namespace Carthago.Engine.Rules.IPv6
{
    public sealed class R071_IPv6TrafficOnIPv4OnlyNetworkRule : TelemetryDetectionRuleBase
    {
        private readonly Ipv6SequenceState _state = new();
        private readonly Func<bool> _approved;
        public R071_IPv6TrafficOnIPv4OnlyNetworkRule()
            : this(() => RuleEngine.GetRuleIntSetting("R071", "Ipv4OnlyApproved", 0, 0, 1) == 1) { }
        internal R071_IPv6TrafficOnIPv4OnlyNetworkRule(Func<bool> approved)
            => _approved = approved ?? throw new ArgumentNullException(nameof(approved));
        public override RuleDescriptor Descriptor => new(
            RuleId:"R071", Name:"IPv6 Traffic on IPv4-Only Network", Category:"IPv6",
            Description:"Two corroborated IPv6 flows under explicitly approved IPv4-only policy.",
            DefaultSeverity:SeverityLevel.Medium, ConfigKey:"Rules.R071.Enabled", EnabledByDefault:true);
        public override ValueTask<RuleEvaluationResult> EvaluateAsync(RuleEvaluationContext c, CancellationToken token=default)
        {
            token.ThrowIfCancellationRequested();
            if (!_approved() || BaselineStore.Current.IsLearningMode || !BaselineStore.Current.Readiness.IsReady
                || !NetworkBatch071075Evidence.Ipv6Policy(c.Record, out var flow)
                || !_state.Observe(flow, c.TimestampUtc))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(RuleEvaluationResult.Match(Descriptor.RuleId,
                NetworkBatch071075Evidence.Alert(Descriptor,c,"Corroborated IPv6 flow under approved IPv4-only policy.")));
        }
    }
}
