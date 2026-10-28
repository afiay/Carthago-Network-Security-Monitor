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
            distinctBy: "unique_packet",
            falsePositives: new[] { "Camera management software, inventory tooling, and initial camera onboarding may legitimately perform ONVIF discovery." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedCameraManagers" },
            requiredTests: new[] { "positive workstation onvif burst sample", "negative nvr onvif sample" });

        public R235_OnvifDiscoveryFromWorkstationRule() : base(Rule, Profile) { }

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch231235Evidence.OnvifProbe(r)) return NoMatch();
            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 120, 30, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 5, 2, 500);
            var count = _observations.Observe(r.Source, r.Destination, r.Id, context.TimestampUtc, window, false);
            if (count < threshold) return NoMatch();
            return MatchIot(context, SeverityLevel.Medium, "Workstation-attributed WS-Discovery Probe burst",
                "OnvifDiscovery", new[] {
                    new DetectionEvidenceItem("count", count.ToString(), "rule"),
                    new DetectionEvidenceItem("matched_conditions", "parsed_wsdiscovery_probe,workstation_process,unique_packet_burst", "rule") },
                confidence => { confidence.AddEvidence(0.28, "parsed-wsdiscovery-probe");
                    confidence.AddEvidence(0.20, "workstation-process");
                    confidence.AddEvidence(0.18, "unique-packet-burst"); },
                count, window, r.Source + ":wsdiscovery");
        }
    }
}
