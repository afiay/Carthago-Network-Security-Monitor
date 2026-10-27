// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R080_KerberosTGSRequestSpikeRule : TelemetryDetectionRuleBase
    {
        private readonly NetworkBatch071075Window _observations = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R080", Name: "Kerberos TGS Request Spike", Category: "LateralMovement",
            Description: "Attributable typed lateral-movement telemetry; authorization and operator intent not inferred.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R080.Enabled", EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext c, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var r = c.Record;
            if (!NetworkBatch076080Evidence.InternalKerberos(c, out var src, out var dst)
                || !NetworkBatch076080Evidence.Classification(r, "KERBEROS", "TGS_REQ"))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            var threshold = RuleEngine.GetRuleIntSetting("R080", "Threshold", 60, 2, 4096);
            var seconds = RuleEngine.GetRuleIntSetting("R080", "WindowSeconds", 60, 1, 86400);
            if (!_observations.Observe(src + "|" + dst, r.Id.ToString("N"),
                c.TimestampUtc, threshold, TimeSpan.FromSeconds(seconds)))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(NetworkBatch076080Evidence.Result(Descriptor, c,
                "High rate of classified Kerberos service-ticket requests to one internal KDC; legitimate bulk requests possible."));
        }
    }
}
