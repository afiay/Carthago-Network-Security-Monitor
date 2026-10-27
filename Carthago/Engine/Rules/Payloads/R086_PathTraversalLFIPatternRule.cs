// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Payloads
{
    public sealed class R086_PathTraversalLFIPatternRule : TelemetryDetectionRuleBase
    {
        private readonly NetworkBatch081085Dedup _seen = new();

        public override RuleDescriptor Descriptor => new(
            RuleId: "R086", Name: "Path Traversal / LFI Pattern", Category: "Payloads",
            Description: "Structured request evidence only; does not establish execution or malicious intent.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R086.Enabled", EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext c, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!NetworkBatch086090Evidence.TryTarget(c, out var target)
                || !NetworkBatch086090Evidence.Traversal(target)
                || !_seen.First(c.Record.Id, c.TimestampUtc))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(NetworkBatch086090Evidence.Match(Descriptor, c,
                "R086 observed structured HTTP exploit-pattern indicators; impact and authorization unconfirmed; raw content redacted."));
        }
    }
}
