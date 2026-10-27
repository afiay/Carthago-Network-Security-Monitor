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
    public sealed class R083_LLMNRNBNSPoisoningAttemptRule : TelemetryDetectionRuleBase
    {
        private readonly NetworkBatch071075Window _responses = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R083",
            Name: "LLMNR / NBNS Poisoning Attempt",
            Category: "LateralMovement",
            Description: "Attributable typed protocol or structured HTTP evidence; no free-text Info-based detection.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R083.Enabled",
            EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var r = context.Record;
            if (!NetworkBatch081085Evidence.NameServiceConflict(context,
                out var responder, out var peer, out var service))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            var threshold = RuleEngine.GetRuleIntSetting("R083", "Threshold", 2, 2, 4096);
            var windowSeconds = RuleEngine.GetRuleIntSetting("R083", "WindowSeconds", 60, 1, 86400);
            if (!_responses.Observe(responder + "|" + peer + "|" + service, r.Id.ToString("N"),
                context.TimestampUtc, threshold, TimeSpan.FromSeconds(windowSeconds)))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(NetworkBatch081085Evidence.Match(Descriptor, context,
                "Repeated parser-corroborated conflicting local name-service responses; unauthorized poisoning not established."));
        }
    }
}
