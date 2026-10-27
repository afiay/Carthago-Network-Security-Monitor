// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Payloads
{
    public sealed class R091_NmapMasscanZgrabUserAgentRule : TelemetryDetectionRuleBase
    {
        private readonly NetworkBatch081085Dedup _seen = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R091", Name: "Nmap / Masscan / Zgrab User-Agent", Category: "Payloads",
            Description: "Only structured, attributable HTTP evidence can raise a candidate; raw packet notes are excluded.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R091.Enabled", EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!NetworkBatch091095Evidence.ScannerAgent(c) || !_seen.First(context.Record.Id, context.TimestampUtc))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(NetworkBatch091095Evidence.Alert(
                Descriptor, context, "Self-declared scanner User-Agent in a structured HTTP request; legitimacy and scanner identity unverified."));
        }
    }
}
