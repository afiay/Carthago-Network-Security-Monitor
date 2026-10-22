// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R234_IpCameraRtspExternalStreamRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R234_IpCameraRtspExternalStreamRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R234",
            Name: "IP Camera RTSP External Stream",
            Category: "IotOtAdvanced",
            Description: "Detects RTSP camera streaming to or from an external destination with camera/RTSP evidence, rather than generic port 554 traffic.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R234.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R234",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http },
            requiredFields: new[] { "source", "destination_or_host", "rtsp_or_camera_context" },
            evidenceFields: new[] { "matched_conditions", "network.destinationPort", "camera.context" },
            positiveConditions: new[]
            {
                "The traffic must show RTSP semantics such as rtsp://, DESCRIBE, SETUP, PLAY, or RTSP application protocol.",
                "The flow must involve an external address or unexpected boundary.",
                "Camera/NVR/DVR context should be present unless the RTSP evidence is explicit."
            },
            negativeConditions: new[]
            {
                "Do not alert on internal-only camera viewing traffic.",
                "Do not alert on port 554 alone without RTSP semantics."
            },
            minimumConfidence: 84,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+destination+stream",
            falsePositives: new[] { "Approved cloud video gateways or remote monitoring services can legitimately stream RTSP externally." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedCameraGateways" },
            requiredTests: new[] { "positive external rtsp play camera sample", "negative internal rtsp camera viewer sample" });

        public R234_IpCameraRtspExternalStreamRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var text = Text(record);
            var rtsp = record.SourcePort == 554 || record.DestinationPort == 554 || record.SourcePort == 8554 || record.DestinationPort == 8554
                       || ContainsAnyValue(record.ApplicationProtocol, "rtsp")
                       || ContainsAnyValue(record.ApplicationService, "rtsp")
                       || ContainsAnyValue(text, "rtsp://", "rtsp/1.0", "describe rtsp", "setup rtsp", "play rtsp", "rtsp describe", "rtsp play");
            var cameraContext = IsCameraLikeProcess(record.ProcessName) || ContainsAnyValue(text, "camera", "ipcam", "nvr", "dvr", "hikvision", "dahua", "axis", "rtsp stream");
            if (!rtsp || !IsUnexpectedSegmentCrossing(record) || (!cameraContext && !ContainsAnyValue(text, "rtsp://")))
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", cameraContext ? "rtsp_semantics,external_or_boundary,camera_context" : "rtsp_semantics,external_or_boundary", "rule"),
                new("network.destinationPort", (record.DestinationPort ?? 0).ToString(System.Globalization.CultureInfo.InvariantCulture), "flow"),
                new("camera.context", cameraContext ? "present" : "rtsp-uri-only", "rule")
            };
            evidence.AddRange(AnalystContext(
                "RTSP camera-streaming semantics were observed across an external or unexpected network boundary.",
                "Severity is High because camera streams crossing external boundaries can expose physical surveillance data or indicate unauthorized remote viewing.",
                "Approved NVR cloud connectors and remote monitoring platforms can be legitimate if explicitly registered.",
                "Confirm whether the destination is an approved video-management or cloud relay service.",
                "Check camera/NVR access logs for the same source, stream path, and user account."));

            return MatchIot(
                context,
                SeverityLevel.High,
                "External RTSP camera stream observed",
                "RtspCameraStream",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.38, "rtsp-semantics");
                    confidence.AddEvidence(0.26, "external-or-boundary");
                    if (cameraContext) confidence.AddCorrelation(0.14, "camera-context");
                },
                cooldownKey: $"{record.Source}:{record.Destination}:rtsp-camera");
        }
    }
}
