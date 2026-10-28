// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R238_SmartHomeHubCloudBurstRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R238_SmartHomeHubCloudBurstRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R238",
            Name: "Smart Home Hub Cloud Burst",
            Category: "IotOtAdvanced",
            Description: "Detects bursty cloud synchronization from smart-home hub context to vendor/cloud endpoints while suppressing isolated telemetry calls.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R238.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R238",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http },
            requiredFields: new[] { "source", "destination_or_host", "hub_context", "cloud_vendor_or_sync_context" },
            evidenceFields: new[] { "count", "window_seconds", "host", "matched_conditions" },
            positiveConditions: new[]
            {
                "The source/process/text must indicate a smart-home hub or bridge.",
                "The destination must be external and cloud/vendor-like or carry sync/telemetry context.",
                "The behavior must exceed a burst threshold within the configured window."
            },
            negativeConditions: new[]
            {
                "Do not alert on isolated normal hub heartbeat traffic.",
                "Do not alert on internal hub-to-device traffic."
            },
            minimumConfidence: 72,
            threshold: 60,
            window: TimeSpan.FromMinutes(5),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+cloud_host",
            falsePositives: new[] { "Device onboarding, hub reboot, scene synchronization, or cloud recovery can temporarily produce bursty vendor traffic." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedHubClouds" },
            requiredTests: new[] { "positive smart hub cloud burst sample", "negative isolated hub heartbeat sample" });

        public R238_SmartHomeHubCloudBurstRule() : base(Rule, Profile) { }

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch236240Evidence.HubCloud(r, out var host)) return NoMatch();
            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 300, 60, 7200));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 60, 10, 5000);
            var count = _observations.Observe(r.Source + ":" + host, r.Destination,
                r.Id, context.TimestampUtc, window, false);
            if (count < threshold) return NoMatch();
            return MatchIot(context, SeverityLevel.Medium,
                "Attributed smart-home hub vendor-cloud request burst", "SmartHomeCloudBurst",
                new[] {
                    new DetectionEvidenceItem("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                    new DetectionEvidenceItem("matched_conditions", "attributed_hub_process,typed_vendor_host,distinct_packet_burst", "rule") },
                c => { c.AddEvidence(0.30, "attributed-hub-process");
                    c.AddEvidence(0.30, "typed-vendor-authority");
                    c.AddCorrelation(0.16, "bounded-burst"); },
                count, window, r.Source + ":" + r.Destination + ":hub-cloud");
        }
    }
}
