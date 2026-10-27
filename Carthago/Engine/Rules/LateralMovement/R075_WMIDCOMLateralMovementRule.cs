// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;
namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R075_WMIDCOMLateralMovementRule : TelemetryDetectionRuleBase
    {
        private readonly NetworkBatch071075Window _state = new();
        public override RuleDescriptor Descriptor => new(
            RuleId:"R075", Name:"WMIDCOMLateral Movement", Category:"LateralMovement",
            Description:"Distinct internal TCP initiations with typed service evidence; authorization not inferred.",
            DefaultSeverity:SeverityLevel.High, ConfigKey:"Rules.R075.Enabled", EnabledByDefault:true);
        public override ValueTask<RuleEvaluationResult> EvaluateAsync(RuleEvaluationContext c, CancellationToken token=default)
        {
            token.ThrowIfCancellationRequested();
            var app=c.Record.ApplicationProtocol;
            if (!(string.Equals(app,"WMI",StringComparison.OrdinalIgnoreCase)
                || string.Equals(app,"DCOM",StringComparison.OrdinalIgnoreCase)))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            if (!NetworkBatch071075Evidence.Tcp(c,135,out var source,out var destination))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            var threshold=RuleEngine.GetRuleIntSetting("R075","Threshold",3,1,int.MaxValue);
            var seconds=RuleEngine.GetRuleIntSetting("R075","WindowSeconds",300,1,86400);
            if (!_state.Observe(source+":135:"+app.ToUpperInvariant(),destination,c.TimestampUtc,threshold,TimeSpan.FromSeconds(seconds)))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(RuleEvaluationResult.Match(Descriptor.RuleId,
                NetworkBatch071075Evidence.Alert(Descriptor,c,"Internal host initiated classified administrative connections to distinct internal endpoints.")));
        }
    }
}
