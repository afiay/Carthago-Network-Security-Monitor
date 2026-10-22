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

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var protocolName = string.Empty;
            if (IsModbusContext(record)) protocolName = "modbus";
            else if (IsDnp3Context(record)) protocolName = "dnp3";
            else if (IsS7Context(record)) protocolName = "s7comm";
            else if (IsCipContext(record)) protocolName = "ethernetip-cip";
            else if (IsOpcUaContext(record)) protocolName = "opcua";
            else if (IsBacnetContext(record)) protocolName = "bacnet";
            else if (IsProfinetContext(record)) protocolName = "profinet";
            else if (ContainsAnyValue(Text(record), "iec104", "iec 104", "iec-104", "iec61850", "goose", "mms")) protocolName = "iec";
            if (string.IsNullOrWhiteSpace(protocolName) || !IsInternalToExternal(record))
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("protocol_name", protocolName, "iot-ot"),
                new("matched_conditions", "industrial_protocol_context,internal_to_external", "rule")
            };
            evidence.AddRange(AnalystContext(
                "Concrete ICS protocol traffic from an internal source reached an external destination.",
                "Severity is Critical because industrial control protocols should not traverse the public internet without tightly controlled gateways.",
                "Approved remote support links or managed OT gateways may resemble this traffic and should be tuned explicitly rather than broadening detection.",
                "Validate whether the source is an approved OT gateway, historian, or vendor-maintained bridge.",
                "Review the industrial protocol immediately for reads, writes, or discovery actions that crossed the trust boundary."));

            return MatchIot(
                context,
                SeverityLevel.Critical,
                "ICS protocol traffic to external destination observed",
                "IcsProtocol",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.42, "industrial-protocol-context");
                    confidence.AddEvidence(0.28, "internal-to-external");
                    confidence.AddCorrelation(0.10, protocolName);
                },
                cooldownKey: $"{record.Source}:{record.Destination}:{protocolName}");
        }
    }
}
