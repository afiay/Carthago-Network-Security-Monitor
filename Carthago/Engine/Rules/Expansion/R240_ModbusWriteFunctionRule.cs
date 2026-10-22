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
            requiredFields: new[] { "source", "destination_or_host", "modbus_context", "write_function" },
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

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsModbusContext(record) || !HasModbusWriteSemantics(record))
                return NoMatch();

            var unexpectedBoundary = IsUnexpectedSegmentCrossing(record);
            var automationProcess = IsAutomationLikeProcess(record.ProcessName);
            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", unexpectedBoundary ? "modbus_context,write_function,unexpected_boundary" : "modbus_context,write_function", "rule"),
                new("network.destinationPort", (record.DestinationPort ?? 0).ToString(System.Globalization.CultureInfo.InvariantCulture), "flow"),
                new("modbus.function", "write", "ot-ics")
            };
            evidence.AddRange(AnalystContext(
                "Modbus write-function semantics were observed, indicating an attempt to alter coils or registers.",
                "Severity is Critical because Modbus write functions can directly change OT process state, device behavior, or actuator outputs.",
                "Approved engineering workstations and scheduled maintenance can be legitimate sources; tune those explicitly.",
                "Confirm the source host role and whether a maintenance window was active.",
                "Review function code, target register/coil range, and any following process-state changes."));

            return MatchIot(
                context,
                SeverityLevel.Critical,
                "Modbus write function observed",
                "ModbusWrite",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.38, "modbus-context");
                    confidence.AddEvidence(0.36, "write-function-semantics");
                    if (unexpectedBoundary) confidence.AddCorrelation(0.10, "unexpected-boundary");
                    if (automationProcess) confidence.AddCorrelation(0.06, "automation-like-process");
                },
                cooldownKey: $"{record.Source}:{record.Destination}:modbus-write");
        }
    }
}
