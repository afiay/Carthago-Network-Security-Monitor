// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R005_SuspiciousProtocolRule.cs
using Carthago.Models;
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R005_SuspiciousProtocolRule : LegacyDetectionRuleBase
    {
        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var record = context.Record;
            var service = record.ApplicationService?.Trim();
            var transport = record.Protocol?.Trim();
            // Protocol names mentioned in a summary or an unrelated transport
            // are not evidence of an observed insecure application service.
            var serviceIdentified = service is not null &&
                (service.Equals("TELNET", StringComparison.OrdinalIgnoreCase)
                 || service.Equals("FTP", StringComparison.OrdinalIgnoreCase)
                 || service.Equals("SMB", StringComparison.OrdinalIgnoreCase)
                 || service.Equals("SNMP", StringComparison.OrdinalIgnoreCase));
            var validTransport = service?.Equals("SNMP", StringComparison.OrdinalIgnoreCase) == true
                ? transport is not null &&
                    (transport.Equals("UDP", StringComparison.OrdinalIgnoreCase)
                     || transport.Equals("TCP", StringComparison.OrdinalIgnoreCase))
                : string.Equals(transport, "TCP", StringComparison.OrdinalIgnoreCase);
            if (!serviceIdentified || !validTransport)
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(
                    Descriptor.RuleId, RuleNoMatchReasonCategory.NotApplicableProtocol,
                    "UNVERIFIED_INSECURE_SERVICE", "An observed insecure application service with compatible transport is required."));
            return base.EvaluateAsync(context, cancellationToken);
        }

        public override RuleDescriptor Descriptor => new(
            RuleId: "R005",
            Name: "Suspicious Protocol",
            Category: "Protocol",
            Description: "Suspicious or unexpected protocol usage",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R005.Enabled",
            EnabledByDefault: true);
    }
}
