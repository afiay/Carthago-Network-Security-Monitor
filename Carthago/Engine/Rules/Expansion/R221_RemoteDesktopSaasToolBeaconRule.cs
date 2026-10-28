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

        private readonly NetworkBatch201205Window _observations = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch221225Evidence.RemoteDesktop(record, out var vendor))
                return NoMatch();
            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 600, 60, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 4, 2, 100);
            var key = NetworkBatch221225Evidence.Key(record, vendor);
            var baseline = ObserveBaseline("clouddev.remote-desktop-vendor", record.Source ?? "unknown",
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
                new("signal", "process+host", "rule"),
                new("baseline.reason", baseline.Reason, "baseline"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", "typed_flow,remote_tool_process,vendor_host,first_seen,distinct_beacons", "rule")
            };
            evidence.AddRange(AnalystContext(
                "A source made repeated distinct flows with a remote-support process and matching vendor endpoint.",
                "The signal is consistent with remote-support activity, not proof of an unauthorized session.",
                "Approved helpdesk tooling can generate identical beacons.",
                "Correlate with trusted process and session telemetry.",
                "Verify asset-specific vendor approval before escalation."));
            return MatchCloudDev(context, SeverityLevel.Medium,
                "Remote-support client beacon pattern observed", "RemoteDesktopSaasBeacon",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.22, "remote-desktop-vendor-context");
                    confidence.AddEvidence(0.18, "beacon-threshold");
                    confidence.AddEvidence(0.12, "first-seen-vendor");
                    confidence.AddEvidence(0.10, "remote-tool-process");
                    confidence.AddEvidence(0.08, "vendor-host");
                }, count, window, key);
        }
    }
}

