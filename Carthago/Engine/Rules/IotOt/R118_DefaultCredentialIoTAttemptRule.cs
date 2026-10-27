// SPDX-License-Identifier: MIT
// File: Engine/Rules/IotOt/R118_DefaultCredentialIoTAttemptRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.IotOt
{
    public sealed class R118_DefaultCredentialIoTAttemptRule : IotOtPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R118",
            Name: "Default-Credential IoT Attempt",
            Category: "IotOt",
            Description: "Detects default-credential attempts only when the record contains both real authentication context and likely IoT or device-target indicators.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R118.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtProfile(
            ruleId: "R118",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.OtIcsProtocol, RuleTelemetryKind.Flow, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "iot_or_ot_context", "device_authentication_attempt" },
            evidenceFields: new[] { "matched_conditions", "process.name" },
            positiveConditions: new[]
            {
                "A Telnet login transcript or decoded HTTP Basic Authorization must contain a known default credential pair.",
                "An HTTP request must identify an IoT device host; free-form descriptions do not establish authentication.",
                "The destination should resemble an IoT, camera, router, or similar device target."
            },
            negativeConditions: new[]
            {
                "Do not alert on default-credential strings in documentation, URLs, or other unstructured descriptions.",
                "Do not alert on default-credential strings that lack device-target indicators."
            },
            minimumConfidence: 86,
            threshold: 1,
            window: TimeSpan.FromMinutes(5),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Authorized provisioning or factory-reset workflows can briefly use documented default credentials."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive default credential sample",
                "negative unrelated adminadmin string sample",
                "negative ordinary device administration without observed default credentials"
            });

        public R118_DefaultCredentialIoTAttemptRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch116120Evidence.CredentialTransport(context)
                || !SensitiveTelemetryContracts.HasDefaultCredentialAuthenticationAttempt(record)
                || !IsLikelyIotDeviceTarget(record))
                return NoMatch();

            var matchedConditions = new List<string> { "default_credential_token", "authentication_context", "device_target_context" };
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "The record contains a known default credential pattern directed at a likely IoT or embedded-device target.",
                "Severity is Critical because default-credential use against IoT or embedded devices strongly suggests insecure provisioning, brute force, or post-reset compromise.",
                "Authorized provisioning or recovery workflows can briefly use vendor-default credentials.",
                "Validate whether the device was being legitimately provisioned or factory-reset.",
                "If not expected, isolate the source and rotate credentials on the targeted device family."));

            return MatchIot(
                context,
                SeverityLevel.Critical,
                "Default credential attempt against likely IoT or embedded device",
                "Authentication",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.40, "default-credential-token");
                    confidence.AddEvidence(0.24, "authentication-context");
                    confidence.AddCorrelation(0.12, "device-target-context");
                },
                cooldownKey: $"{record.Source}:{record.Destination}");
        }
    }
}
