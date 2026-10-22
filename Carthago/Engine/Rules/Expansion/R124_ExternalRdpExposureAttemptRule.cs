// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R124_ExternalRdpExposureAttemptRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R124_ExternalRdpExposureAttemptRule : IdentityAccessPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R124",
            Name: "External RDP Exposure Attempt",
            Category: "IdentityAccess",
            Description: "Detects RDP traffic that crosses an internal-external boundary with real RDP protocol evidence, rather than any mention of remote desktop.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R124.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIdentityAccessProfile(
            ruleId: "R124",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port" },
            evidenceFields: new[] { "matched_conditions", "network.destinationPort" },
            positiveConditions: new[]
            {
                "The traffic must contain real RDP service context.",
                "The connection must cross an internal-external boundary.",
                "Same-segment or AnyText-only RDP mentions should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on internal-only RDP activity.",
                "Do not alert on bare GUI text with no RDP port or protocol evidence."
            },
            minimumConfidence: 74,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Approved cross-boundary remote administration and jump-host workflows can match. Validate whether the destination is an approved external RDP service."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive boundary-crossing rdp sample",
                "negative internal rdp sample"
            });

        public R124_ExternalRdpExposureAttemptRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsRdpContext(record))
                return NoMatch();

            if (!IsCrossBoundary(record, out var outboundToExternal, out var inboundFromExternal))
                return NoMatch();

            var matchedConditions = new List<string> { "rdp_protocol_context" };
            if (outboundToExternal) matchedConditions.Add("outbound_to_external");
            if (inboundFromExternal) matchedConditions.Add("inbound_from_external");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                outboundToExternal
                    ? "RDP traffic originated internally and crossed to an external destination."
                    : "An external source reached an internal RDP destination.",
                "Severity is High because boundary-crossing RDP often indicates exposed remote administration or lateral access attempts.",
                "Approved remote administration and managed support providers can match. Validate whether the host pair is sanctioned.",
                "Confirm the source and destination ownership and whether this RDP path is approved.",
                "Review nearby authentication, VPN, or admin access events from the same source."));

            return MatchIdentityAccess(
                context,
                SeverityLevel.High,
                "Boundary-crossing RDP access observed",
                "RemoteDesktop",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.40, "rdp-protocol-context");
                    if (outboundToExternal) confidence.AddEvidence(0.22, "outbound-to-external");
                    if (inboundFromExternal) confidence.AddEvidence(0.22, "inbound-from-external");
                },
                cooldownKey: $"{record.Source}:{record.Destination}:{record.DestinationPort}");
        }
    }
}
