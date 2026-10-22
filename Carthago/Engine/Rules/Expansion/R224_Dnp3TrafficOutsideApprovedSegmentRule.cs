// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R224_Dnp3TrafficOutsideApprovedSegmentRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R224_Dnp3TrafficOutsideApprovedSegmentRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R224",
            Name: "DNP3 Traffic Outside Approved Segment",
            Category: "IotOtAdvanced",
            Description: "Detects DNP3 traffic that crosses an unexpected boundary or segment, rather than any bare port-20000 or keyword hit.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R224.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R224",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "iot_or_ot_context" },
            evidenceFields: new[] { "matched_conditions", "network.destinationPort" },
            positiveConditions: new[]
            {
                "The record must contain real DNP3 protocol context.",
                "The traffic must cross an external boundary or a non-local internal segment.",
                "Same-segment DNP3 chatter should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on port-only matches.",
                "Do not alert on local same-segment DNP3 traffic."
            },
            minimumConfidence: 84,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+destination",
            falsePositives: new[] { "Approved SCADA masters and outstations on routed OT backbones may legitimately exchange DNP3 across segments." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive dnp3 cross-segment sample", "negative same-segment dnp3 sample" });

        public R224_Dnp3TrafficOutsideApprovedSegmentRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsDnp3Context(record))
                return NoMatch();

            var externalBoundary = IsExternalAddress(record.Source) || IsExternalAddress(record.Destination);
            var crossLocalSegment = IsInternalAddress(record.Source) && IsInternalAddress(record.Destination) && !SharesSame24(record.Source, record.Destination);
            if (!externalBoundary && !crossLocalSegment)
                return NoMatch();

            var matchedConditions = new List<string> { "dnp3_protocol_context" };
            if (externalBoundary) matchedConditions.Add("external_boundary");
            if (crossLocalSegment) matchedConditions.Add("cross_local_segment");

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                externalBoundary
                    ? "DNP3 traffic crossed an external boundary."
                    : "DNP3 traffic crossed non-local internal segments.",
                "Severity is High because DNP3 should stay inside tightly controlled OT segments and masters/outstations.",
                "Approved SCADA routing and carefully segmented OT backbones can resemble this pattern.",
                "Validate whether the source and destination are approved DNP3 peers or remote telemetry units.",
                "Review the DNP3 operation sequence for unexpected controls, integrity polls, or outstation access."));

            return MatchIot(
                context,
                SeverityLevel.High,
                "DNP3 traffic outside expected segment observed",
                "DNP3",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.38, "dnp3-protocol-context");
                    if (externalBoundary) confidence.AddEvidence(0.20, "external-boundary");
                    if (crossLocalSegment) confidence.AddEvidence(0.18, "cross-local-segment");
                },
                cooldownKey: $"{record.Source}:{record.Destination}");
        }
    }
}
