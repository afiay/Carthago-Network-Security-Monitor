// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R228_OpcUaInternetEgressRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R228_OpcUaInternetEgressRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R228",
            Name: "OPC UA Internet Egress",
            Category: "IotOtAdvanced",
            Description: "Detects concrete OPC UA traffic from internal sources to external destinations, rather than any loose opc.tcp or port-4840 match.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R228.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R228",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "iot_or_ot_context" },
            evidenceFields: new[] { "matched_conditions", "network.destinationPort" },
            positiveConditions: new[]
            {
                "The traffic must contain real OPC UA context.",
                "The source should be internal and the destination external.",
                "Internal-only OPC UA traffic should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on opc keywords without protocol context.",
                "Do not alert on internal-only OPC UA sessions."
            },
            minimumConfidence: 84,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+destination",
            falsePositives: new[] { "Approved historians, cloud brokers, or secure vendor gateways may legitimately bridge OPC UA externally." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive opcua internet egress sample", "negative internal opcua sample" });

        public R228_OpcUaInternetEgressRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsOpcUaContext(record) || !IsInternalToExternal(record))
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "opcua_context,internal_to_external", "rule")
            };
            evidence.AddRange(AnalystContext(
                "OPC UA traffic from an internal source reached an external destination.",
                "Severity is High because OPC UA should not reach the internet without tightly controlled brokers or gateways.",
                "Approved historians or secure cloud/DMZ brokers can resemble this pattern and should be explicitly tuned.",
                "Validate whether the source is an approved broker, historian, or vendor-managed gateway.",
                "Review the OPC UA session context for browse, read, or write operations that crossed the boundary."));

            return MatchIot(
                context,
                SeverityLevel.High,
                "OPC UA egress to external destination observed",
                "OPC UA",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.36, "opcua-context");
                    confidence.AddEvidence(0.24, "internal-to-external");
                },
                cooldownKey: $"{record.Source}:{record.Destination}");
        }
    }
}
