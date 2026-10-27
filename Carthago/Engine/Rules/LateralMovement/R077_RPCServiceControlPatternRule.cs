// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R077_RPCServiceControlPatternRule : TelemetryDetectionRuleBase
    {
        private readonly NetworkBatch071075Window _observations = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R077", Name: "RPC Service Control Pattern", Category: "LateralMovement",
            Description: "Attributable typed lateral-movement telemetry; authorization and operator intent not inferred.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R077.Enabled", EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext c, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (c.Record.DestinationPort is not (135 or 445)
                || !NetworkBatch076080Evidence.InternalTcp(c, c.Record.DestinationPort.Value, out var src, out var dst)
                || !NetworkBatch076080Evidence.Classification(c.Record, "DCE/RPC", "SVCCTL"))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            var threshold = RuleEngine.GetRuleIntSetting("R077", "Threshold", 2, 2, 4096);
            var seconds = RuleEngine.GetRuleIntSetting("R077", "WindowSeconds", 120, 1, 86400);
            if (!_observations.Observe(src + "|" + dst, c.Record.Id.ToString("N"),
                c.TimestampUtc, threshold, TimeSpan.FromSeconds(seconds)))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(NetworkBatch076080Evidence.Result(Descriptor, c,
                "Repeated classified remote service-control requests on an internal target; authorization unknown."));
        }
    }
}
