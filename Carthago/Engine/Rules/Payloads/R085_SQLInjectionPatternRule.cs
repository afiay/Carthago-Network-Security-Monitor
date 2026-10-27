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
    public sealed class R085_SQLInjectionPatternRule : TelemetryDetectionRuleBase
    {
        private readonly NetworkBatch081085Dedup _seen = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R085",
            Name: "SQL Injection Pattern",
            Category: "Payloads",
            Description: "Attributable typed protocol or structured HTTP evidence; no free-text Info-based detection.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R085.Enabled",
            EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!NetworkBatch081085Evidence.HttpRequest(context)
                || !NetworkBatch081085Evidence.HttpFields(context.Record)
                    .Any(NetworkBatch081085Evidence.SqlInjection)
                || !_seen.First(context.Record.Id, context.TimestampUtc))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(NetworkBatch081085Evidence.Match(Descriptor, context,
                "Structured HTTP request contains a SQL injection expression; database execution and intent not established."));
        }
    }
}
