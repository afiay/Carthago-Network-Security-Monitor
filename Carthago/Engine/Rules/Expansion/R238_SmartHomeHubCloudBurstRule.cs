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

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = BestHost(record);
            var hubContext = HasSmartHomeHubTelemetryContext(record) || IsSmartHomeHubVendorHost(host);
            var cloudContext = IsSmartHomeHubVendorHost(host) || ContainsAnyValue(Text(record), "cloud", "sync", "telemetry", "heartbeat", "device status", "scene", "automation");
            if (!hubContext || !cloudContext || !IsInternalToExternal(record))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 300, 60, 7200));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 60, 10, 5000);
            var count = CountWindowEvents($"{Descriptor.RuleId}:{record.Source}:{host}", context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("host", host, "flow"),
                new("matched_conditions", "smart_home_hub_context,cloud_sync_context,burst_threshold", "rule")
            };
            evidence.AddRange(AnalystContext(
                "Smart-home hub or bridge telemetry produced a high-rate cloud synchronization burst.",
                "Severity is Medium because unusual bursty cloud synchronization can indicate device takeover, automation loop failure, or unexpected data export.",
                "Onboarding, reboot recovery, and vendor-cloud outage recovery can look similar; compare with recent device lifecycle events.",
                "Check whether the hub recently rebooted, added devices, or recovered from an outage.",
                "Review destination hostnames and volume for unexpected vendor or non-vendor cloud endpoints."));

            return MatchIot(
                context,
                SeverityLevel.Medium,
                "Smart-home hub cloud synchronization burst observed",
                "SmartHomeCloudBurst",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.22, "hub-context");
                    confidence.AddEvidence(0.20, "cloud-sync-context");
                    confidence.AddEvidence(0.18, "burst-threshold");
                },
                count,
                window,
                $"{record.Source}:{host}:smart-home-cloud-burst");
        }
    }
}
