// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R223_IcsProtocolToInternetRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R223_IcsProtocolToInternetRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R223",
            Name: "ICS Protocol To Internet",
            Category: "IotOtAdvanced",
            Description: "Detects concrete ICS or OT protocol traffic from internal sources to external destinations, rather than any loose industrial keyword hit.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R223.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R223",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "iot_or_ot_context" },
            evidenceFields: new[] { "protocol_name", "matched_conditions", "network.destinationPort" },
            positiveConditions: new[]
            {
                "The traffic must contain real ICS protocol context such as Modbus, DNP3, S7, CIP, OPC UA, or BACnet.",
                "The source should be internal and the destination external.",
                "Plain port-only internet traffic without protocol semantics should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on keyword-only OT mentions.",
                "Do not alert on internal-only ICS protocol traffic."
            },
            minimumConfidence: 88,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+destination",
            falsePositives: new[] { "Explicitly approved remote OT gateways or sanctioned vendor support tunnels may legitimately bridge ICS protocols externally." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive ics to internet sample", "negative internal modbus sample" });

        public R223_IcsProtocolToInternetRule() : base(Rule, Profile) { }

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch221225Evidence.Ot(record, out var protocolName)
                || !IsInternalToExternal(record) || !_replay.Observe(record, context.TimestampUtc))
                return NoMatch();
            var evidence = new List<DetectionEvidenceItem>
            {
                new("protocol_name", protocolName, "iot-ot"),
                new("matched_conditions", "parser_attributed_ot,transport_port_consistent,internal_to_external", "rule")
            };
            evidence.AddRange(AnalystContext(
                "An L7-attributed industrial protocol flow crossed from an internal address to an external address.",
                "The observed flow does not prove a successful PLC operation or unauthorized access.",
                "Approved OT gateways and vendor support tunnels may bridge this boundary.",
                "Correlate with trusted industrial gateway and change-control logs.",
                "Confirm the source and destination are approved OT peers."));
            return MatchIot(context, SeverityLevel.Critical,
                "Attributed ICS protocol flow to external destination observed", "IcsProtocol",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.42, "industrial-protocol-context");
                    confidence.AddEvidence(0.28, "internal-to-external");
                    confidence.AddCorrelation(0.10, protocolName);
                }, cooldownKey: NetworkBatch221225Evidence.Key(record, protocolName));
        }
    }
}

