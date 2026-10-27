// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Payloads
{
    public sealed class R093_SuspiciousPowerShellDownloadCradleOverHTTPRule : TelemetryDetectionRuleBase
    {
        private readonly NetworkBatch081085Dedup _seen = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R093", Name: "Suspicious PowerShell Download Cradle over HTTP", Category: "Payloads",
            Description: "Only structured, attributable HTTP evidence can raise a candidate; raw packet notes are excluded.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R093.Enabled", EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!NetworkBatch091095Evidence.PowerShellCradle(context) || !_seen.First(context.Record.Id, context.TimestampUtc))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(NetworkBatch091095Evidence.Alert(
                Descriptor, context, "Structured HTTP request target combines a PowerShell launcher, retrieval, and invocation; execution unverified."));
        }
    }
}
