// SPDX-License-Identifier: MIT
// File: Engine/Rules/IotOt/R116_UPnPExposureDiscoveryAbuseRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.IotOt
{
    public sealed class R116_UPnPExposureDiscoveryAbuseRule : IotOtPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R116",
            Name: "UPnP Exposure / Discovery Abuse",
            Category: "IotOt",
            Description: "Detects UPnP/SSDP discovery abuse when discovery traffic leaves the local network or becomes a strong internal discovery burst, rather than on one-off local discovery chatter.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R116.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtProfile(
            ruleId: "R116",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.OtIcsProtocol, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "iot_or_ot_context" },
            evidenceFields: new[] { "count", "window_seconds", "matched_conditions" },
            positiveConditions: new[]
            {
                "The record must contain SSDP or UPnP discovery context.",
                "External destinations or strong discovery bursts should drive detection.",
                "One-off local discovery traffic should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on a single internal discovery request.",
                "Do not alert on generic multicast noise that lacks SSDP or UPnP context."
            },
            minimumConfidence: 72,
            threshold: 25,
            window: TimeSpan.FromMinutes(1),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source",
            falsePositives: new[]
            {
                "Media devices and smart-home hubs can legitimately perform local discovery, especially after reboot."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds" },
            requiredTests: new[]
            {
                "positive external upnp discovery sample",
                "positive internal upnp burst sample",
                "negative single local upnp sample"
            });

        private readonly NetworkBatch116120Window _events = new();

        public R116_UPnPExposureDiscoveryAbuseRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch116120Evidence.SsdpDiscovery(context))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 60, 10, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 25, 5, 5000);
            var count = _events.Count(record.Source!, record.Id, context.TimestampUtc, window);
            var externalDestination = IsExternalAddress(record.Destination);
            if (!externalDestination && count < threshold)
                return NoMatch();

            var matchedConditions = new List<string> { "upnp_discovery_context" };
            if (externalDestination) matchedConditions.Add("external_destination");
            if (count >= threshold) matchedConditions.Add("internal_discovery_burst");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                externalDestination
                    ? $"UPnP discovery traffic from {record.Source} reached an external destination."
                    : $"{record.Source} generated {count} UPnP discovery events within {window.TotalSeconds:F0}s.",
                externalDestination
                    ? "Severity is High because UPnP discovery should not traverse to external destinations."
                    : "Severity is Medium because the local discovery rate is unusually high.",
                "Local device discovery can spike during reboot storms or media-device onboarding.",
                "Validate whether a device restart, onboarding, or network change explains the discovery burst.",
                "Escalate quickly if UPnP or SSDP traffic is observed toward external destinations."));

            return MatchIot(
                context,
                externalDestination ? SeverityLevel.High : SeverityLevel.Medium,
                externalDestination ? "UPnP discovery traffic reached external destination" : $"UPnP discovery burst from {record.Source}",
                "UPnP/SSDP",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "upnp-discovery-context");
                    if (externalDestination) confidence.AddEvidence(0.22, "external-destination");
                    if (count >= threshold) confidence.AddEvidence(0.16, "discovery-burst-threshold");
                },
                count: count,
                window: window,
                cooldownKey: $"{record.Source}");
        }
    }
}
