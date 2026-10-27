// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;
namespace Carthago.Engine.Rules.IPv6
{
    public sealed class R072_SuspiciousMulticastDiscoveryBurstRule : TelemetryDetectionRuleBase
    {
        private readonly NetworkBatch071075Window _state = new();
        public override RuleDescriptor Descriptor => new(
            RuleId:"R072", Name:"Suspicious Multicast Discovery Burst", Category:"IPv6",
            Description:"Bounded structured IPv6 mDNS, LLMNR or SSDP discovery burst.",
            DefaultSeverity:SeverityLevel.Medium, ConfigKey:"Rules.R072.Enabled", EnabledByDefault:true);
        public override ValueTask<RuleEvaluationResult> EvaluateAsync(RuleEvaluationContext c, CancellationToken token=default)
        {
            token.ThrowIfCancellationRequested();
            if (!NetworkBatch071075Evidence.Multicast(c.Record,out var source,out var service))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            var threshold=RuleEngine.GetRuleIntSetting("R072","Threshold",20,1,int.MaxValue);
            var seconds=RuleEngine.GetRuleIntSetting("R072","WindowSeconds",60,1,86400);
            if (!_state.Observe(source+":"+service,c.TimestampUtc.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture),
                c.TimestampUtc,threshold,TimeSpan.FromSeconds(seconds)))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(RuleEvaluationResult.Match(Descriptor.RuleId,
                NetworkBatch071075Evidence.Alert(Descriptor,c,"IPv6 multicast discovery exceeded the configured observation threshold.")));
        }
    }
}
