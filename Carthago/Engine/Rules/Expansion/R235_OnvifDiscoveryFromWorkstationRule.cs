// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R235_OnvifDiscoveryFromWorkstationRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R235_OnvifDiscoveryFromWorkstationRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R235",
            Name: "ONVIF Discovery From Workstation",
            Category: "IotOtAdvanced",
            Description: "Detects workstation-originated ONVIF/WS-Discovery probing when discovery semantics and burst behavior are present.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R235.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R235",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "onvif_discovery_context" },
            evidenceFields: new[] { "count", "window_seconds", "matched_conditions" },
            positiveConditions: new[]
            {
                "The traffic must contain ONVIF or WS-Discovery probe semantics.",
                "The source should look like a workstation or non-camera host.",
                "A burst or repeated discovery activity should be present."
            },
            negativeConditions: new[]
            {
                "Do not alert on normal camera/NVR ONVIF chatter.",
                "Do not alert on isolated discovery during approved camera onboarding."
            },
            minimumConfidence: 76,
            threshold: 5,
            window: TimeSpan.FromMinutes(2),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "source+destination",
            falsePositives: new[] { "Camera management software, inventory tooling, and initial camera onboarding may legitimately perform ONVIF discovery." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedCameraManagers" },
            requiredTests: new[] { "positive workstation onvif burst sample", "negative nvr onvif sample" });

        public R235_OnvifDiscoveryFromWorkstationRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var workstation = IsWorkstationLikeProcess(record.ProcessName) || (!IsCameraLikeProcess(record.ProcessName) && IsInternalAddress(record.Source));
            if (!IsOnvifContext(record) || !HasOnvifDiscoverySemantics(record) || !workstation)
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 120, 30, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 5, 2, 500);
            var count = CountDistinctValues($"{Descriptor.RuleId}:{record.Source}", record.Destination ?? BestHost(record), context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", "onvif_discovery,workstation_source,distinct_target_burst", "rule")
            };
            evidence.AddRange(AnalystContext(
                "A workstation-like source generated repeated ONVIF/WS-Discovery camera discovery traffic.",
                "Severity is Medium because ONVIF enumeration can reveal cameras, NVRs, device models, and surveillance topology.",
                "Approved camera-management workstations and onboarding tools should be allow-listed.",
                "Confirm whether the source is an approved VMS/camera-management host.",
                "Review the discovered camera targets and check for follow-on RTSP, web admin, or credential attempts."));

            return MatchIot(
                context,
                SeverityLevel.Medium,
                "ONVIF discovery burst from workstation observed",
                "OnvifDiscovery",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "onvif-discovery-semantics");
                    confidence.AddEvidence(0.20, "workstation-like-source");
                    confidence.AddEvidence(0.18, "distinct-target-burst");
                },
                count,
                window,
                $"{record.Source}:onvif-discovery");
        }
    }
}
