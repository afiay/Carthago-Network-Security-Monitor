// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R240_ModbusWriteFunctionRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R240_ModbusWriteFunctionRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R240",
            Name: "Modbus Write Function",
            Category: "IotOtAdvanced",
            Description: "Detects concrete Modbus write-function semantics and prioritizes writes crossing external or unexpected segment boundaries.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R240.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R240",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port", "iot_or_ot_context", "payload_or_uri" },
            evidenceFields: new[] { "matched_conditions", "network.destinationPort", "modbus.function" },
            positiveConditions: new[]
            {
                "The traffic must contain Modbus context and explicit write function semantics.",
                "Write single/multiple coil/register semantics must be present; Modbus port alone is insufficient.",
                "Unexpected segment crossing, external source/destination, or automation-like process increases confidence."
            },
            negativeConditions: new[]
            {
                "Do not alert on Modbus read-only traffic.",
                "Do not alert on generic port 502 traffic without write-function evidence."
            },
            minimumConfidence: 90,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "source+destination+modbus_function",
            falsePositives: new[] { "Approved engineering workstations, PLC programming sessions, or maintenance windows may legitimately issue Modbus writes." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedEngineeringHosts", "ApprovedMaintenanceWindows" },
            requiredTests: new[] { "positive modbus write multiple registers sample", "negative modbus read holding registers sample" });

        public R240_ModbusWriteFunctionRule() : base(Rule, Profile) { }

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch236240Evidence.ModbusWrite(r)
                || _observations.Observe(r.Source, r.Destination, r.Id, context.TimestampUtc,
                    TimeSpan.FromMinutes(10), false) == 0) return NoMatch();
            return MatchIot(context, SeverityLevel.Critical,
                "Parsed Modbus write-function request observed", "ModbusWrite",
                new[] {
                    new DetectionEvidenceItem("matched_conditions", "tcp_502,parsed_mbap,write_function_request", "rule"),
                    new DetectionEvidenceItem("modbus.function", "write", "ot-ics") },
                c => { c.AddEvidence(0.48, "parsed-modbus-write-request");
                    c.AddEvidence(0.42, "typed-tcp-502-operation"); },
                cooldownKey: r.Source + ":" + r.Destination + ":modbus-write");
        }
    }
}
