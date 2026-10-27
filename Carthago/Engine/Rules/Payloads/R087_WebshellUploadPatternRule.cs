// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Payloads
{
    public sealed class R087_WebshellUploadPatternRule : TelemetryDetectionRuleBase
    {
        private readonly NetworkBatch081085Dedup _seen = new();

        public override RuleDescriptor Descriptor => new(
            RuleId: "R087", Name: "Webshell Upload Pattern", Category: "Payloads",
            Description: "Structured request evidence only; does not establish execution or malicious intent.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R087.Enabled", EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext c, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!NetworkBatch086090Evidence.TryTarget(c, out var target)
                || !NetworkBatch086090Evidence.ScriptUpload(c)
                || !_seen.First(c.Record.Id, c.TimestampUtc))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(NetworkBatch086090Evidence.Match(Descriptor, c,
                "R087 observed structured HTTP exploit-pattern indicators; impact and authorization unconfirmed; raw content redacted."));
        }
    }
}
