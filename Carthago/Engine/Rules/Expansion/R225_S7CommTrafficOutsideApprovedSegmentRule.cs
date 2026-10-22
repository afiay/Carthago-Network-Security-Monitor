// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R225_S7CommTrafficOutsideApprovedSegmentRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R225_S7CommTrafficOutsideApprovedSegmentRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R225",
            Name: "S7comm Traffic Outside Approved Segment",
            Category: "IotOtAdvanced",
            Description: "Detects Siemens S7 communication crossing unexpected boundaries or segments, rather than loose port-102 matches.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R225.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R225",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "iot_or_ot_context" },
            evidenceFields: new[] { "matched_conditions", "network.destinationPort" },
            positiveConditions: new[]
            {
                "The record must contain real S7 or PLC communication context.",
                "The traffic must cross an external boundary or a non-local internal segment.",
                "Local same-segment PLC chatter should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on port-only traffic without S7 semantics.",
                "Do not alert on same-segment S7 traffic."
            },
            minimumConfidence: 84,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+destination",
            falsePositives: new[] { "Approved engineering stations or routed PLC networks may legitimately communicate across industrial segments." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive s7 cross-segment sample", "negative same-segment s7 sample" });

        public R225_S7CommTrafficOutsideApprovedSegmentRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsS7Context(record))
                return NoMatch();

            var externalBoundary = IsExternalAddress(record.Source) || IsExternalAddress(record.Destination);
            var crossLocalSegment = IsInternalAddress(record.Source) && IsInternalAddress(record.Destination) && !SharesSame24(record.Source, record.Destination);
            if (!externalBoundary && !crossLocalSegment)
                return NoMatch();

            var matchedConditions = new List<string> { "s7_protocol_context" };
            if (externalBoundary) matchedConditions.Add("external_boundary");
            if (crossLocalSegment) matchedConditions.Add("cross_local_segment");

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                externalBoundary
                    ? "S7 communication crossed an external boundary."
                    : "S7 communication crossed non-local internal segments.",
                "Severity is High because PLC programming and control protocols should remain inside tightly approved engineering paths.",
                "Approved engineering or routed PLC networks can resemble this pattern and should be tuned explicitly.",
                "Validate whether the source is an approved engineering workstation or PLC peer.",
                "Review whether the S7 conversation includes setup, read, or write operations that should not traverse the segment boundary."));

            return MatchIot(
                context,
                SeverityLevel.High,
                "S7 communication outside expected segment observed",
                "S7comm",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.38, "s7-protocol-context");
                    if (externalBoundary) confidence.AddEvidence(0.20, "external-boundary");
                    if (crossLocalSegment) confidence.AddEvidence(0.18, "cross-local-segment");
                },
                cooldownKey: $"{record.Source}:{record.Destination}");
        }
    }
}
