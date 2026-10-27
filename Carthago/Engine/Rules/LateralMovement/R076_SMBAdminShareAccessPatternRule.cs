// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R076_SMBAdminShareAccessPatternRule : TelemetryDetectionRuleBase
    {
        private readonly NetworkBatch071075Window _observations = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R076", Name: "SMB Admin Share Access Pattern", Category: "LateralMovement",
            Description: "Attributable typed lateral-movement telemetry; authorization and operator intent not inferred.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R076.Enabled", EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext c, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!NetworkBatch076080Evidence.InternalTcp(c, 445, out var src, out var dst)
                || !NetworkBatch076080Evidence.Classification(c.Record, "SMB", "ADMIN_SHARE"))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            var threshold = RuleEngine.GetRuleIntSetting("R076", "Threshold", 2, 2, 4096);
            var seconds = RuleEngine.GetRuleIntSetting("R076", "WindowSeconds", 120, 1, 86400);
            if (!_observations.Observe(src + "|" + dst, c.Record.Id.ToString("N"),
                c.TimestampUtc, threshold, TimeSpan.FromSeconds(seconds)))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(NetworkBatch076080Evidence.Result(Descriptor, c,
                "Repeated classified SMB administrative-share requests on one internal target; authorization unknown."));
        }
    }
}
