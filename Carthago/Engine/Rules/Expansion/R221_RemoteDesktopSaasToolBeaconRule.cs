// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R221_RemoteDesktopSaasToolBeaconRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R221_RemoteDesktopSaasToolBeaconRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R221",
            Name: "Remote Desktop SaaS Tool Beacon",
            Category: "CloudDev",
            Description: "Detects repeated beacons to first-seen remote-support SaaS infrastructure when host, process, or service context points to AnyDesk, TeamViewer, ScreenConnect, ConnectWise, Splashtop, or RustDesk.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R221.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R221",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.CloudAudit },
            requiredFields: new[] { "source", "destination_or_host", "process_or_service" },
            evidenceFields: new[] { "vendor", "signal", "count", "baseline.reason", "matched_conditions" },
            positiveConditions: new[]
            {
                "The destination or process context must map to a concrete remote-support SaaS vendor.",
                "The signal should combine host, process, or service context rather than a loose domain hit.",
                "The same source should repeat the beacon pattern within the configured window."
            },
            negativeConditions: new[]
            {
                "Do not alert on ordinary vendor web browsing without remote-tool process or service context.",
                "Do not alert on isolated single events."
            },
            minimumConfidence: 78,
            threshold: 4,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "destination",
            falsePositives: new[] { "Approved remote-support sessions or sanctioned helpdesk tooling can legitimately beacon to vendor infrastructure." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[] { "positive remote desktop saas beacon sample", "negative browser visit to vendor sample" });

        public R221_RemoteDesktopSaasToolBeaconRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!TryClassifyRemoteDesktopSaas(record, out var vendor, out var signal))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 600, 60, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 4, 2, 100);
            var baseline = ObserveBaseline("clouddev.remote-desktop-vendor", record.Source ?? "unknown", vendor, context, $"host={BestHost(record)}; signal={signal}");
            var firstSeen = baseline.IsFirstSeen
                || (baseline.FirstSeenUtc.HasValue && context.TimestampUtc - baseline.FirstSeenUtc.Value <= window)
                || (string.Equals(baseline.Reason, "baseline unavailable", StringComparison.OrdinalIgnoreCase)
                    && FirstSeenWithinWindow($"{Descriptor.RuleId}:first-seen:{record.Source}:{vendor}", context.TimestampUtc, window));
            var count = CountWindowEvents($"{Descriptor.RuleId}:{record.Source}:{vendor}", context.TimestampUtc, window);
            if (!firstSeen || count < threshold)
                return NoMatch();

            var matchedConditions = new List<string> { "remote_desktop_vendor_context", "first_seen_vendor", "beacon_threshold" };
            if (signal.Contains("process", StringComparison.OrdinalIgnoreCase)) matchedConditions.Add("remote_tool_process");
            if (signal.Contains("host", StringComparison.OrdinalIgnoreCase)) matchedConditions.Add("vendor_host");

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
                "The source repeatedly contacted first-seen remote-support SaaS infrastructure with matching vendor host, process, or service context.",
                "Severity is Medium because repeated remote-support beacons can indicate unsanctioned remote access tooling even when the vendor is legitimate.",
                "Approved helpdesk sessions or sanctioned remote-support rollouts can look similar. Validate the vendor, session owner, and endpoint role before escalating.",
                "Review the process lineage to determine whether a remote-support client or embedded agent initiated the traffic.",
                "Confirm whether the vendor is approved for this host or user population."));

            return MatchCloudDev(
                context,
                SeverityLevel.Medium,
                "Remote desktop SaaS beacon pattern observed",
                "RemoteDesktopSaasBeacon",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.22, "remote-desktop-vendor-context");
                    confidence.AddEvidence(0.18, "beacon-threshold");
                    confidence.AddEvidence(0.12, "first-seen-vendor");
                    if (signal.Contains("process", StringComparison.OrdinalIgnoreCase)) confidence.AddEvidence(0.10, "remote-tool-process");
                    if (signal.Contains("host", StringComparison.OrdinalIgnoreCase)) confidence.AddEvidence(0.08, "vendor-host");
                },
                count,
                window,
                $"{record.Source}:{vendor}");
        }
    }
}
