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

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch226230Evidence.OpcUaEgress(r)
                || _observations.Observe(r.Source, r.Destination, r.Id, context.TimestampUtc,
                    TimeSpan.FromMinutes(10), false) == 0) return NoMatch();
            return MatchIot(context, SeverityLevel.High, "Typed OPC UA egress to external IP",
                "OPC UA",
                new[] { new DetectionEvidenceItem("matched_conditions", "typed_opcua,tcp_4840,internal_to_external", "rule") },
                confidence => { confidence.AddEvidence(0.36, "typed-opcua");
                    confidence.AddEvidence(0.24, "internal-to-external"); },
                cooldownKey: r.Source + ":" + r.Destination);
        }
    }
}
