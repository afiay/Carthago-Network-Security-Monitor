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

        private readonly NetworkBatch201205Window _observations = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch221225Evidence.Overlay(record, out var vendor, out var signal))
                return NoMatch();
            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 600, 60, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 3, 2, 100);
            var key = NetworkBatch221225Evidence.Key(record, vendor);
            var baseline = ObserveBaseline("clouddev.overlay-network-vendor", record.Source ?? "unknown",
                vendor, context, "vendor=" + vendor + "; endpoint_fingerprint=" + key);
            var firstSeen = baseline.IsFirstSeen
                || baseline.FirstSeenUtc.HasValue && context.TimestampUtc - baseline.FirstSeenUtc.Value <= window
                || string.Equals(baseline.Reason, "baseline unavailable", StringComparison.OrdinalIgnoreCase)
                    && FirstSeenWithinWindow($"{Descriptor.RuleId}:first-seen:{key}", context.TimestampUtc, window);
            if (!_observations.Observe(record, key, record.Id.ToString("N"), context.TimestampUtc,
                window, 0, out var count, out _) || !firstSeen || count < threshold)
                return NoMatch();
            var evidence = new List<DetectionEvidenceItem>
            {
                new("vendor", vendor, "cloud"),
                new("signal", signal, "rule"),
                new("baseline.reason", baseline.Reason, "baseline"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", "typed_flow,overlay_process,corroborated_endpoint,first_seen,distinct_egress", "rule")
            };
            evidence.AddRange(AnalystContext(
                "A source made repeated distinct egress flows with a matching overlay process and endpoint or service port.",
                "The traffic may be a tunnel connection; unauthorized access is not independently established.",
                "Sanctioned mesh VPNs and remote support tunnels are common benign equivalents.",
                "Correlate with endpoint process and network policy records.",
                "Confirm asset-specific tunnel authorization before escalation."));
            return MatchCloudDev(context, SeverityLevel.High,
                "Overlay or tunnel client egress pattern observed", "OverlayNetworkEgress",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.26, "overlay-vendor-context");
                    confidence.AddEvidence(0.18, "egress-threshold");
                    confidence.AddEvidence(0.12, "first-seen-vendor");
                    confidence.AddEvidence(0.10, "overlay-process");
                    if (signal.Contains("port", StringComparison.OrdinalIgnoreCase))
                        confidence.AddEvidence(0.08, "known-overlay-port");
                    else confidence.AddEvidence(0.08, "vendor-host");
                }, count, window, key);
        }
    }
}

