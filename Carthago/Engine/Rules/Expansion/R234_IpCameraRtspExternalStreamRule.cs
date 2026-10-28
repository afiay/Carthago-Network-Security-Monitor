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

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch231235Evidence.RtspPlay(r)
                || _observations.Observe(r.Source, r.Destination, r.Id, context.TimestampUtc,
                    TimeSpan.FromMinutes(10), false) == 0) return NoMatch();
            return MatchIot(context, SeverityLevel.High, "RTSP PLAY request crossed network boundary",
                "RtspCameraStream", new[] {
                    new DetectionEvidenceItem("matched_conditions", "parsed_rtsp_play,tcp_rtsp_port,boundary", "rule"),
                    new DetectionEvidenceItem("camera.context", "unverified_rtsp_request", "rule") },
                confidence => { confidence.AddEvidence(0.38, "parsed-rtsp-play");
                    confidence.AddEvidence(0.26, "boundary"); },
                cooldownKey: r.Source + ":" + r.Destination + ":rtsp-play");
        }
    }
}
