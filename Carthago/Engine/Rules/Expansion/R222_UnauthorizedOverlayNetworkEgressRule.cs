// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R222_UnauthorizedOverlayNetworkEgressRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R222_UnauthorizedOverlayNetworkEgressRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R222",
            Name: "Unauthorized Overlay Network Egress",
            Category: "CloudDev",
            Description: "Detects repeated first-seen overlay, tunnel, or mesh-network egress when process, host, or known service-port context points to Tailscale, ZeroTier, ngrok, Cloudflare Tunnel, or WireGuard.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R222.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R222",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.CloudAudit },
            requiredFields: new[] { "source", "destination_or_host", "process_or_service" },
            evidenceFields: new[] { "vendor", "signal", "count", "baseline.reason", "matched_conditions" },
            positiveConditions: new[]
            {
                "The signal must map to a concrete overlay or tunnel vendor using process, host, or known service-port context.",
                "The source should repeat the egress pattern within the configured window.",
                "First-seen vendor context should remain visible so established sanctioned overlays can be tuned separately."
            },
            negativeConditions: new[]
            {
                "Do not alert on generic vendor web browsing without overlay or tunnel process context.",
                "Do not alert on isolated single events."
            },
            minimumConfidence: 82,
            threshold: 3,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "destination",
            falsePositives: new[] { "Approved mesh networking, VPN, or tunnel agents can legitimately contact these vendors." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[] { "positive overlay egress sample", "negative cloudflare browsing sample" });

        public R222_UnauthorizedOverlayNetworkEgressRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!TryClassifyOverlayNetworkEgress(record, out var vendor, out var signal))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 600, 60, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 3, 2, 100);
            var baseline = ObserveBaseline("clouddev.overlay-network-vendor", record.Source ?? "unknown", vendor, context, $"host={BestHost(record)}; signal={signal}");
            var firstSeen = baseline.IsFirstSeen
                || (baseline.FirstSeenUtc.HasValue && context.TimestampUtc - baseline.FirstSeenUtc.Value <= window)
                || (string.Equals(baseline.Reason, "baseline unavailable", StringComparison.OrdinalIgnoreCase)
                    && FirstSeenWithinWindow($"{Descriptor.RuleId}:first-seen:{record.Source}:{vendor}", context.TimestampUtc, window));
            var count = CountWindowEvents($"{Descriptor.RuleId}:{record.Source}:{vendor}", context.TimestampUtc, window);
            if (!firstSeen || count < threshold)
                return NoMatch();

            var matchedConditions = new List<string> { "overlay_vendor_context", "first_seen_vendor", "egress_threshold" };
            if (signal.Contains("process", StringComparison.OrdinalIgnoreCase)) matchedConditions.Add("overlay_process");
            if (signal.Contains("host", StringComparison.OrdinalIgnoreCase)) matchedConditions.Add("vendor_host");
            if (signal.Contains("port", StringComparison.OrdinalIgnoreCase)) matchedConditions.Add("known_overlay_port");

            var evidence = new List<DetectionEvidenceItem>
            {
                new("vendor", vendor, "cloud"),
                new("signal", signal, "rule"),
                new("baseline.reason", baseline.Reason, "baseline"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                "The source repeatedly contacted first-seen overlay or tunnel infrastructure with matching vendor, process, or known service-port context.",
                "Severity is High because overlay and tunnel egress can bypass network segmentation and create covert or unsanctioned access paths.",
                "Approved mesh VPNs or support tunnels can resemble this traffic. Validate whether the agent and vendor are sanctioned before escalating.",
                "Review the process lineage and destination vendor to determine whether a tunnel or mesh client initiated the traffic.",
                "Confirm whether the overlay vendor is approved for the source host or role."));

            return MatchCloudDev(
                context,
                SeverityLevel.High,
                "Overlay or tunnel egress pattern observed",
                "OverlayNetworkEgress",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.26, "overlay-vendor-context");
                    confidence.AddEvidence(0.18, "egress-threshold");
                    confidence.AddEvidence(0.12, "first-seen-vendor");
                    if (signal.Contains("process", StringComparison.OrdinalIgnoreCase)) confidence.AddEvidence(0.10, "overlay-process");
                    if (signal.Contains("port", StringComparison.OrdinalIgnoreCase)) confidence.AddEvidence(0.08, "known-overlay-port");
                    if (signal.Contains("host", StringComparison.OrdinalIgnoreCase)) confidence.AddEvidence(0.08, "vendor-host");
                },
                count,
                window,
                $"{record.Source}:{vendor}");
        }
    }
}
