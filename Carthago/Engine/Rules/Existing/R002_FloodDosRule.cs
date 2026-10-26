// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R002_FloodDosRule.cs
using Carthago.Models;
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R002_FloodDosRule : LegacyDetectionRuleBase
    {
        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var record = context.Record;
            // Legacy SYN/ACK flood counters measure TCP, not UDP or protocol
            // names found in free-form payload descriptions. Invalid service
            // endpoints cannot contribute bytes or packet observations.
            if (!string.Equals(record.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || record.DestinationPort is not int port || port is < 1 or > 65535)
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(
                    Descriptor.RuleId, RuleNoMatchReasonCategory.NotApplicableProtocol,
                    "NOT_TCP_FLOOD_TELEMETRY", "R002 needs attributed TCP service traffic."));
            return base.EvaluateAsync(context, cancellationToken);
        }

        public override RuleDescriptor Descriptor => new(
            RuleId: "R002",
            Name: "Flood / DoS",
            Category: "Network",
            Description: "Flood or denial-of-service behavior",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R002.Enabled",
            EnabledByDefault: true);
    }
}
