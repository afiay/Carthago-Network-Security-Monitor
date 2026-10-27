// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Payloads
{
    public sealed class R090_ReverseShellPayloadIndicatorRule : TelemetryDetectionRuleBase
    {
        private readonly NetworkBatch081085Dedup _seen = new();

        public override RuleDescriptor Descriptor => new(
            RuleId: "R090", Name: "Reverse Shell Payload Indicator", Category: "Payloads",
            Description: "Structured request evidence only; does not establish execution or malicious intent.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R090.Enabled", EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext c, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!NetworkBatch086090Evidence.TryTarget(c, out var target)
                || !NetworkBatch086090Evidence.ReverseShell(target)
                || !_seen.First(c.Record.Id, c.TimestampUtc))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(NetworkBatch086090Evidence.Match(Descriptor, c,
                "R090 observed structured HTTP exploit-pattern indicators; impact and authorization unconfirmed; raw content redacted."));
        }
    }
}
