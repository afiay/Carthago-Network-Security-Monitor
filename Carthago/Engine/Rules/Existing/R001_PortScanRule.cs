// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R001_PortScanRule.cs
using Carthago.Models;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R001_PortScanRule : LegacyDetectionRuleBase
    {
        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Invalid transport port numbers must never become scan evidence.
            // The stateful detector remains in RuleEngine.Detectors.cs.
            if (context.Record.DestinationPort is not int port || port is < 1 or > 65535)
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(
                    Descriptor.RuleId, RuleNoMatchReasonCategory.MissingRequiredField,
                    "INVALID_SCAN_PORT", "A valid observed TCP destination port is required."));
            return base.EvaluateAsync(context, cancellationToken);
        }

        public override RuleDescriptor Descriptor => new(
            RuleId: "R001",
            Name: "Port Scan",
            Category: "Network",
            Description: "Port scan against multiple destination ports",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R001.Enabled",
            EnabledByDefault: true);
    }
}
