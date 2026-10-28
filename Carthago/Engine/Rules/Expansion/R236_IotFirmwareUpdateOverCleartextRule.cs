// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R236_IotFirmwareUpdateOverCleartextRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R236_IotFirmwareUpdateOverCleartextRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R236",
            Name: "IoT Firmware Update Over Cleartext",
            Category: "IotOtAdvanced",
            Description: "Detects observable IoT firmware artifact requests over cleartext HTTP only when update artifact and IoT/device context are both present.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R236.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R236",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "http_method", "http_uri", "cleartext_http", "firmware_artifact" },
            evidenceFields: new[] { "http.path", "matched_conditions", "host" },
            positiveConditions: new[]
            {
                "The transfer must be cleartext HTTP, not TLS.",
                "The URI, headers, or payload metadata must look like a firmware/update artifact.",
                "IoT/device/vendor context should be present to avoid generic binary download noise."
            },
            negativeConditions: new[]
            {
                "Do not alert on HTTPS firmware update checks.",
                "Do not alert on generic .bin downloads without IoT/update context."
            },
            minimumConfidence: 84,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+host+firmware_path",
            falsePositives: new[] { "Legacy IoT devices may still use HTTP firmware repositories; these should be tracked as risk acceptances or migrated." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedFirmwareHosts" },
            requiredTests: new[] { "positive cleartext firmware artifact sample", "negative https firmware update sample" });

        public R236_IotFirmwareUpdateOverCleartextRule() : base(Rule, Profile) { }

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch236240Evidence.FirmwareRequest(r)
                || _observations.Observe(r.Source, r.Destination, r.Id, context.TimestampUtc,
                    TimeSpan.FromMinutes(10), false) == 0) return NoMatch();
            return MatchIot(context, SeverityLevel.High,
                "IoT firmware artifact requested over cleartext HTTP", "CleartextFirmwareUpdate",
                new[] {
                    new DetectionEvidenceItem("matched_conditions", "parsed_http_get,firmware_route,device_process", "rule"),
                    new DetectionEvidenceItem("http.path", "[REDACTED]", "http") },
                c => { c.AddEvidence(0.38, "parsed-cleartext-http");
                    c.AddEvidence(0.32, "anchored-firmware-route");
                    c.AddCorrelation(0.18, "attributed-device-process"); },
                cooldownKey: r.Source + ":" + r.Destination + ":firmware-request");
        }
    }
}
