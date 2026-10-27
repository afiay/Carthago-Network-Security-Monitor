// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;
namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R074_WinRMPowerShellRemotingSweepRule : TelemetryDetectionRuleBase
    {
        private readonly NetworkBatch071075Window _state = new();
        public override RuleDescriptor Descriptor => new(
            RuleId:"R074", Name:"Win RMPower Shell Remoting Sweep", Category:"LateralMovement",
            Description:"Distinct internal TCP initiations with typed service evidence; authorization not inferred.",
            DefaultSeverity:SeverityLevel.High, ConfigKey:"Rules.R074.Enabled", EnabledByDefault:true);
        public override ValueTask<RuleEvaluationResult> EvaluateAsync(RuleEvaluationContext c, CancellationToken token=default)
        {
            token.ThrowIfCancellationRequested();
            if (c.Record.DestinationPort is not (5985 or 5986))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            if (!NetworkBatch071075Evidence.Tcp(c,c.Record.DestinationPort!.Value,out var source,out var destination))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            var threshold=RuleEngine.GetRuleIntSetting("R074","Threshold",5,1,int.MaxValue);
            var seconds=RuleEngine.GetRuleIntSetting("R074","WindowSeconds",300,1,86400);
            if (!_state.Observe(source+":"+c.Record.DestinationPort.Value,destination,c.TimestampUtc,threshold,TimeSpan.FromSeconds(seconds)))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(RuleEvaluationResult.Match(Descriptor.RuleId,
                NetworkBatch071075Evidence.Alert(Descriptor,c,"Internal host initiated classified administrative connections to distinct internal endpoints.")));
        }
    }
}
