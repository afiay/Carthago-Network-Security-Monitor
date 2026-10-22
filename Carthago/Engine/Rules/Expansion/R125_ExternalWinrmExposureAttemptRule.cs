// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R125_ExternalWinrmExposureAttemptRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R125_ExternalWinrmExposureAttemptRule : IdentityAccessPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R125",
            Name: "External WinRM Exposure Attempt",
            Category: "IdentityAccess",
            Description: "Detects WinRM or WSMAN traffic that crosses an internal-external boundary with real management protocol evidence.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R125.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIdentityAccessProfile(
            ruleId: "R125",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port" },
            evidenceFields: new[] { "matched_conditions", "network.destinationPort" },
            positiveConditions: new[]
            {
                "The record must contain real WinRM or WSMAN context.",
                "The connection must cross an internal-external boundary.",
                "Internal-only management traffic should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on same-boundary WinRM administration.",
                "Do not alert on AnyText-only mentions of PowerShell remoting."
            },
            minimumConfidence: 74,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Approved hybrid-management or sanctioned cross-boundary administration can match."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive boundary-crossing winrm sample",
                "negative internal winrm sample"
            });

        public R125_ExternalWinrmExposureAttemptRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsWinrmContext(record))
                return NoMatch();

            if (!IsCrossBoundary(record, out var outboundToExternal, out var inboundFromExternal))
                return NoMatch();

            var matchedConditions = new List<string> { "winrm_protocol_context" };
            if (outboundToExternal) matchedConditions.Add("outbound_to_external");
            if (inboundFromExternal) matchedConditions.Add("inbound_from_external");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                outboundToExternal
                    ? "WinRM traffic originated internally and reached an external destination."
                    : "An external source reached an internal WinRM endpoint.",
                "Severity is High because WinRM crossing a trust boundary exposes privileged remote-management capability.",
                "Approved hybrid-management platforms or remote administration services can match. Validate whether the path is sanctioned.",
                "Validate whether the source and destination are part of an approved management workflow.",
                "Inspect authentication context and recent PowerShell activity from the same source."));

            return MatchIdentityAccess(
                context,
                SeverityLevel.High,
                "Boundary-crossing WinRM access observed",
                "WinRM",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.40, "winrm-protocol-context");
                    if (outboundToExternal) confidence.AddEvidence(0.22, "outbound-to-external");
                    if (inboundFromExternal) confidence.AddEvidence(0.22, "inbound-from-external");
                },
                cooldownKey: $"{record.Source}:{record.Destination}:{record.DestinationPort}");
        }
    }
}
