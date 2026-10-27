// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Engine.Rules.Payloads
{
    public sealed class R084_Log4ShellJNDIInjectionPatternRule : TelemetryDetectionRuleBase
    {
        private readonly NetworkBatch081085Dedup _seen = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R084",
            Name: "Log4Shell / JNDI Injection Pattern",
            Category: "Payloads",
            Description: "Attributable typed protocol or structured HTTP evidence; no free-text Info-based detection.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R084.Enabled",
            EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!NetworkBatch081085Evidence.HttpRequest(context)
                || !NetworkBatch081085Evidence.HttpFields(context.Record)
                    .Any(NetworkBatch081085Evidence.Jndi)
                || !_seen.First(context.Record.Id, context.TimestampUtc))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(NetworkBatch081085Evidence.Match(Descriptor, context,
                "Structured HTTP request contains a JNDI lookup injection pattern; execution and exploit success not established."));
        }
    }
}
