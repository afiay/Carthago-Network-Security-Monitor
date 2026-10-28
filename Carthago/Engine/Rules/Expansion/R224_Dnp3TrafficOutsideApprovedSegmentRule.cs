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

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch221225Evidence.Ot(record, out var protocol)
                || protocol != "dnp3" || !_replay.Observe(record, context.TimestampUtc))
                return NoMatch();
            var externalBoundary = IsExternalAddress(record.Source) || IsExternalAddress(record.Destination);
            var crossLocalSegment = IsInternalAddress(record.Source) && IsInternalAddress(record.Destination)
                && !SharesSame24(record.Source, record.Destination);
            if (!externalBoundary && !crossLocalSegment) return NoMatch();
            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", externalBoundary ? "typed_dnp3,external_boundary" :
                    "typed_dnp3,cross_24_heuristic", "rule")
            };
            evidence.AddRange(AnalystContext(
                "A parser-attributed DNP3 flow crossed an external boundary or a non-local /24 heuristic.",
                "A different /24 is not proof of an unapproved OT segment or a control operation.",
                "Approved routed SCADA backbones can cross /24 boundaries.",
                "Review authoritative asset segmentation and gateway logs.",
                "Confirm peer authorization before escalation."));
            return MatchIot(context, SeverityLevel.High,
                "Attributed DNP3 flow across network boundary observed", "DNP3",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.38, "dnp3-protocol-context");
                    if (externalBoundary) confidence.AddEvidence(0.20, "external-boundary");
                    if (crossLocalSegment) confidence.AddEvidence(0.18, "cross-local-segment");
                }, cooldownKey: NetworkBatch221225Evidence.Key(record, "dnp3"));
        }
    }
}

