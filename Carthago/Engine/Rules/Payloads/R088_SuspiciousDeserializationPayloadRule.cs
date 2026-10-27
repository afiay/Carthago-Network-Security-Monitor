// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Payloads
{
    public sealed class R088_SuspiciousDeserializationPayloadRule : TelemetryDetectionRuleBase
    {
        private readonly NetworkBatch081085Dedup _seen = new();

        public override RuleDescriptor Descriptor => new(
            RuleId: "R088", Name: "Suspicious Deserialization Payload", Category: "Payloads",
            Description: "Structured request evidence only; does not establish execution or malicious intent.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R088.Enabled", EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext c, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!NetworkBatch086090Evidence.TryTarget(c, out var target)
                || !NetworkBatch086090Evidence.Deserialization(c, target)
                || !_seen.First(c.Record.Id, c.TimestampUtc))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(NetworkBatch086090Evidence.Match(Descriptor, c,
                "R088 observed structured HTTP exploit-pattern indicators; impact and authorization unconfirmed; raw content redacted."));
        }
    }
}
