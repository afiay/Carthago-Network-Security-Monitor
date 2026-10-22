// SPDX-License-Identifier: MIT
// File: Engine/Rules/IotOt/R117_TelnetLoginAttemptToIoTDeviceRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.IotOt
{
    public sealed class R117_TelnetLoginAttemptToIoTDeviceRule : IotOtPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R117",
            Name: "Telnet Login Attempt to IoT Device",
            Category: "IotOt",
            Description: "Detects telnet login attempts that include real authentication context against likely IoT or network-device targets, rather than generic port 23 traffic alone.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R117.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtProfile(
            ruleId: "R117",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.OtIcsProtocol, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "iot_or_ot_context" },
            evidenceFields: new[] { "network.destinationPort", "matched_conditions", "process.name" },
            positiveConditions: new[]
            {
                "The record must contain telnet or port-23 context.",
                "Authentication prompt or credential-attempt evidence must be present.",
                "The destination should look like an IoT, camera, router, or similar device target."
            },
            negativeConditions: new[]
            {
                "Do not alert on bare port-23 traffic without authentication context.",
                "Do not alert on telnet text that lacks device-target indicators."
            },
            minimumConfidence: 80,
            threshold: 1,
            window: TimeSpan.FromMinutes(5),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Legacy maintenance workflows may still use telnet on embedded or network devices."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive telnet login sample",
                "negative bare port-23 sample"
            });

        public R117_TelnetLoginAttemptToIoTDeviceRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsTelnetContext(record))
                return NoMatch();

            var text = Text(record);
            var authContext = text.IndexOf("login:", StringComparison.OrdinalIgnoreCase) >= 0
                              || text.IndexOf("password:", StringComparison.OrdinalIgnoreCase) >= 0
                              || text.IndexOf("username", StringComparison.OrdinalIgnoreCase) >= 0;
            if (!authContext || !IsLikelyIotDeviceTarget(record))
                return NoMatch();

            var matchedConditions = new List<string> { "telnet_context", "authentication_prompt", "device_target_context" };
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "The record contains telnet authentication context directed at a likely IoT or network-device target.",
                "Severity is High because interactive telnet logins to embedded or network devices are high-risk and often legacy or opportunistic.",
                "Some legacy maintenance workflows may still use telnet on embedded gear.",
                "Validate whether the destination is a sanctioned legacy device and whether telnet remains approved.",
                "Review the source process and account context for signs of brute force or opportunistic access."));

            return MatchIot(
                context,
                SeverityLevel.High,
                "Telnet login attempt to likely IoT or network device",
                "Telnet",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "telnet-context");
                    confidence.AddEvidence(0.24, "authentication-prompt");
                    confidence.AddCorrelation(0.10, "device-target-context");
                },
                cooldownKey: $"{record.Source}:{record.Destination}");
        }
    }
}
