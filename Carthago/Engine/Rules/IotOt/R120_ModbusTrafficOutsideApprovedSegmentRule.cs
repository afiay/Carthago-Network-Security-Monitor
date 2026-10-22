// SPDX-License-Identifier: MIT
// File: Engine/Rules/IotOt/R120_ModbusTrafficOutsideApprovedSegmentRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.IotOt
{
    public sealed class R120_ModbusTrafficOutsideApprovedSegmentRule : IotOtPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R120",
            Name: "Modbus Traffic Outside Approved Segment",
            Category: "IotOt",
            Description: "Detects Modbus traffic that crosses a strong trust boundary or carries write-like function context outside a tight local segment, rather than any mention of modbus.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R120.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtProfile(
            ruleId: "R120",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.OtIcsProtocol, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "iot_or_ot_context" },
            evidenceFields: new[] { "matched_conditions", "network.destinationPort" },
            positiveConditions: new[]
            {
                "The record must contain real Modbus protocol context.",
                "The traffic must cross a strong boundary such as external scope or a non-local internal segment with write-like function context.",
                "Plain modbus mentions or same-segment chatter should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on weak Modbus hints without port or protocol context.",
                "Do not alert on same-segment local Modbus chatter when no write-like function is present."
            },
            minimumConfidence: 86,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Sanctioned OT controllers and approved OT segments should be shadowed via Approved.OtSegments and Approved.ModbusControllers."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive modbus cross-boundary write sample",
                "negative same-subnet modbus read sample"
            });

        public R120_ModbusTrafficOutsideApprovedSegmentRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsModbusContext(record))
                return NoMatch();

            var text = Text(record);
            var writeLike = text.IndexOf("write", StringComparison.OrdinalIgnoreCase) >= 0
                            || text.IndexOf("coil", StringComparison.OrdinalIgnoreCase) >= 0
                            || text.IndexOf("register", StringComparison.OrdinalIgnoreCase) >= 0
                            || text.IndexOf("function 5", StringComparison.OrdinalIgnoreCase) >= 0
                            || text.IndexOf("function 6", StringComparison.OrdinalIgnoreCase) >= 0
                            || text.IndexOf("function 15", StringComparison.OrdinalIgnoreCase) >= 0
                            || text.IndexOf("function 16", StringComparison.OrdinalIgnoreCase) >= 0;
            var externalBoundary = IsExternalAddress(record.Source) || IsExternalAddress(record.Destination);
            var crossLocalSegment = IsInternalAddress(record.Source) && IsInternalAddress(record.Destination) && !SharesSame24(record.Source, record.Destination);
            if (!externalBoundary && !(crossLocalSegment && writeLike))
                return NoMatch();

            var matchedConditions = new List<string> { "modbus_protocol_context" };
            if (externalBoundary) matchedConditions.Add("external_boundary");
            if (crossLocalSegment) matchedConditions.Add("cross_local_segment");
            if (writeLike) matchedConditions.Add("write_like_function");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                externalBoundary
                    ? "Modbus traffic crossed an external boundary."
                    : "Modbus traffic crossed local private segments with write-like function context.",
                "Severity is Critical because Modbus crossing trust boundaries or carrying write-like operations outside a tight local segment is high risk.",
                "Approved OT controllers and segments should be allowlisted through environment tuning rather than weakening the detector.",
                "Validate whether the source and destination belong to approved OT controllers or approved OT segments.",
                "Review the Modbus function context immediately for unauthorized writes or unexpected control actions."));

            return MatchIot(
                context,
                SeverityLevel.Critical,
                "Modbus traffic outside expected trust boundary",
                "Modbus",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.42, "modbus-protocol-context");
                    if (externalBoundary) confidence.AddEvidence(0.22, "external-boundary");
                    if (crossLocalSegment) confidence.AddEvidence(0.20, "cross-local-segment");
                    if (writeLike) confidence.AddCorrelation(0.18, "write-like-function");
                },
                cooldownKey: $"{record.Source}:{record.Destination}");
        }
    }
}
