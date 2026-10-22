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
            Description: "Detects IoT firmware artifacts transferred over cleartext HTTP only when update artifact and IoT/device context are both present.",
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

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var text = Text(record);
            var iotContext = ContainsAnyValue(text, "iot", "device", "firmware", "router", "camera", "printer", "gateway", "sensor", "zigbee", "mqtt")
                             || IsSmartHomeHubVendorHost(BestHost(record))
                             || IsHubLikeProcess(record.ProcessName)
                             || IsCameraLikeProcess(record.ProcessName);
            if (!IsCleartextHttp(record) || !LooksLikeFirmwareArtifact(record) || !iotContext)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "cleartext_http,firmware_artifact,iot_context", "rule"),
                new("http.path", string.IsNullOrWhiteSpace(record.HttpUri) ? "/" : record.HttpUri!, "http"),
                new("host", BestHost(record), "http")
            };
            evidence.AddRange(AnalystContext(
                "A firmware/update-looking artifact for an IoT/device context was transferred over cleartext HTTP.",
                "Severity is High because cleartext firmware distribution can allow tampering, downgrade, or credential exposure around device-update workflows.",
                "Some legacy devices still use HTTP update repositories; approved hosts should be explicitly documented and tuned.",
                "Verify the firmware host, artifact hash, and device model/version.",
                "Check whether the device supports HTTPS update endpoints or signed firmware validation."));

            return MatchIot(
                context,
                SeverityLevel.High,
                "IoT firmware artifact transferred over cleartext HTTP",
                "CleartextFirmwareUpdate",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "cleartext-http");
                    confidence.AddEvidence(0.30, "firmware-artifact");
                    confidence.AddCorrelation(0.16, "iot-device-context");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{record.HttpUri}:firmware-http");
        }
    }
}
