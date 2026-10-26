// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R004_BruteForceRule.cs
using Carthago.Models;
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R004_BruteForceRule : LegacyDetectionRuleBase
    {
        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var record = context.Record;
            // Never merge failed-authentication events for unknown targets:
            // independent missing-destination records would otherwise share
            // the same "unknown" brute-force counter.
            if (string.IsNullOrWhiteSpace(record.Source)
                || string.IsNullOrWhiteSpace(record.Destination)
                || record.DestinationPort is not int port || port is < 1 or > 65535)
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(
                    Descriptor.RuleId, RuleNoMatchReasonCategory.MissingRequiredField,
                    "UNATTRIBUTED_AUTH_FAILURE", "A complete observed source, target, and service port are required."));
            return base.EvaluateAsync(context, cancellationToken);
        }

        public override RuleDescriptor Descriptor => new(
            RuleId: "R004",
            Name: "Brute Force",
            Category: "Identity",
            Description: "Repeated authentication attempts",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R004.Enabled",
            EnabledByDefault: true);
    }
}
