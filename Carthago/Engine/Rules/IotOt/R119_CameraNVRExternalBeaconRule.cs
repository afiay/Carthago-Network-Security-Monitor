// SPDX-License-Identifier: MIT
// File: Engine/Rules/IotOt/R119_CameraNVRExternalBeaconRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.IotOt
{
    public sealed class R119_CameraNVRExternalBeaconRule : IotOtPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R119",
            Name: "Camera / NVR External Beacon",
            Category: "IotOt",
            Description: "Detects repeated external beaconing or direct RTSP-style external streaming from camera or NVR-like devices, while suppressing isolated one-off traffic.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R119.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtProfile(
            ruleId: "R119",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.OtIcsProtocol, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "iot_or_ot_context" },
            evidenceFields: new[] { "count", "window_seconds", "matched_conditions" },
            positiveConditions: new[]
            {
                "The source must resemble a camera or NVR endpoint.",
                "Traffic must go to an external destination.",
                "Repeated beacons or direct RTSP-style external streaming should drive detection."
            },
            negativeConditions: new[]
            {
                "Do not alert on isolated one-off external hits.",
                "Do not alert when camera or NVR context is absent."
            },
            minimumConfidence: 80,
            threshold: 5,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Approved camera vendor clouds and sanctioned remote-viewing platforms may legitimately beacon or stream."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds" },
            requiredTests: new[]
            {
                "positive repeated camera beacon sample",
                "negative one-off camera egress sample"
            });

        private readonly NetworkBatch116120Window _events = new();

        public R119_CameraNVRExternalBeaconRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch116120Evidence.CameraSource(context)
                || !IsInternalAddress(record.Source) || !IsExternalAddress(record.Destination))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 900, 60, 7200));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 5, 2, 500);
            var count = _events.Count($"{record.Source}:{record.Destination}", record.Id, context.TimestampUtc, window);
            var directRtsp = NetworkBatch116120Evidence.DirectRtsp(record);
            if (!directRtsp && count < threshold)
                return NoMatch();

            var matchedConditions = new List<string> { "camera_or_nvr_context", "external_destination" };
            if (directRtsp) matchedConditions.Add("direct_rtsp_external");
            if (count >= threshold) matchedConditions.Add("repeated_beacon_threshold");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                directRtsp
                    ? "Camera or NVR-like traffic reached an external RTSP-style endpoint."
                    : $"{record.Source} contacted the same external destination {count} times with camera/NVR-like telemetry within {window.TotalMinutes:F0} minutes.",
                "Severity is High because cameras and NVRs should rarely beacon or stream directly to unsanctioned external destinations.",
                "Approved vendor cloud relay or remote-viewing platforms may legitimately create similar traffic.",
                "Validate whether the destination belongs to an approved vendor cloud or remote-viewing service.",
                "Review camera or NVR inventory and isolate unexpected external streaming or beacon activity."));

            return MatchIot(
                context,
                SeverityLevel.High,
                directRtsp ? "Camera or NVR external RTSP-style traffic" : $"Camera or NVR external beacon from {record.Source}",
                "Camera/NVR",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.36, "camera-or-nvr-context");
                    confidence.AddEvidence(0.22, "external-destination");
                    if (directRtsp) confidence.AddEvidence(0.16, "direct-rtsp-external");
                    if (count >= threshold) confidence.AddEvidence(0.12, "repeated-beacon-threshold");
                },
                count: count,
                window: window,
                cooldownKey: $"{record.Source}:{record.Destination}");
        }
    }
}
