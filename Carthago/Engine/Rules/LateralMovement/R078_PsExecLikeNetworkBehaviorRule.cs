// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R078_PsExecLikeNetworkBehaviorRule : TelemetryDetectionRuleBase
    {
        private readonly NetworkBatch076080Sequence _sequence = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R078", Name: "PsExec-Like Network Behavior", Category: "LateralMovement",
            Description: "Attributable typed lateral-movement telemetry; authorization and operator intent not inferred.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R078.Enabled", EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext c, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var r = c.Record;
            if (r.DestinationPort is not (135 or 445)
                || !NetworkBatch076080Evidence.InternalTcp(c, r.DestinationPort.Value, out var src, out var dst))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            var share = r.DestinationPort == 445 &&
                NetworkBatch076080Evidence.Classification(r, "SMB", "ADMIN_SHARE");
            var control = NetworkBatch076080Evidence.Classification(r, "DCE/RPC", "SVCCTL");
            if (!share && !control)
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            var seconds = RuleEngine.GetRuleIntSetting("R078", "WindowSeconds", 120, 1, 86400);
            if (!_sequence.Observe(src + "|" + dst, share, r.Id, c.TimestampUtc, TimeSpan.FromSeconds(seconds)))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(NetworkBatch076080Evidence.Result(Descriptor, c,
                "Classified SMB administrative-share use followed by remote service control on the same internal target; tool identity not inferred."));
        }
    }
}
