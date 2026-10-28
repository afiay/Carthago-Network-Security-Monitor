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

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch221225Evidence.Ot(record, out var protocol)
                || protocol != "s7comm" || !_replay.Observe(record, context.TimestampUtc))
                return NoMatch();
            var externalBoundary = IsExternalAddress(record.Source) || IsExternalAddress(record.Destination);
            var crossLocalSegment = IsInternalAddress(record.Source) && IsInternalAddress(record.Destination)
                && !SharesSame24(record.Source, record.Destination);
            if (!externalBoundary && !crossLocalSegment) return NoMatch();
            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", externalBoundary ? "typed_s7,external_boundary" :
                    "typed_s7,cross_24_heuristic", "rule")
            };
            evidence.AddRange(AnalystContext(
                "A parser-attributed S7comm flow crossed an external boundary or a non-local /24 heuristic.",
                "A different /24 does not establish an unapproved PLC route or successful write.",
                "Approved engineering stations can communicate across routed PLC segments.",
                "Review authoritative PLC topology and gateway logs.",
                "Confirm the source and destination are approved engineering peers."));
            return MatchIot(context, SeverityLevel.High,
                "Attributed S7comm flow across network boundary observed", "S7comm",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.38, "s7-protocol-context");
                    if (externalBoundary) confidence.AddEvidence(0.20, "external-boundary");
                    if (crossLocalSegment) confidence.AddEvidence(0.18, "cross-local-segment");
                }, cooldownKey: NetworkBatch221225Evidence.Key(record, "s7comm"));
        }
    }
}

