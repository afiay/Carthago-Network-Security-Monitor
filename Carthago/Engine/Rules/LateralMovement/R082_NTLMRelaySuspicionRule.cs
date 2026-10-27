// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R082_NTLMRelaySuspicionRule : TelemetryDetectionRuleBase
    {
        private readonly NetworkBatch071075Window _requests = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R082",
            Name: "NTLM Relay Suspicion",
            Category: "LateralMovement",
            Description: "Attributable typed protocol or structured HTTP evidence; no free-text Info-based detection.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R082.Enabled",
            EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var r = context.Record;
            if (!NetworkBatch081085Evidence.Ntlm(context, out var source, out var target)
                || !NetworkBatch076080Evidence.Classification(r, "NTLM", "RELAY_CORROBORATED"))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            var threshold = RuleEngine.GetRuleIntSetting("R082", "Threshold", 8, 2, 4096);
            var windowSeconds = RuleEngine.GetRuleIntSetting("R082", "WindowSeconds", 120, 1, 86400);
            if (!_requests.Observe(source + "|" + target, r.Id.ToString("N"),
                context.TimestampUtc, threshold, TimeSpan.FromSeconds(windowSeconds)))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(NetworkBatch081085Evidence.Match(Descriptor, context,
                "Repeated independently classified NTLM relay correlation on one internal pair; authorization unknown."));
        }
    }
}
