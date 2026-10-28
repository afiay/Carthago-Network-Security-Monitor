// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R271_ThreatFeedIocWithLowReputationOverlapRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R271_ThreatFeedIocWithLowReputationOverlapRule : EvasionInfraPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R271",
            Name: "Threat Feed IOC With Low Reputation Overlap",
            Category: "EvasionInfra",
            Description: "Detects threat feed ioc with low reputation overlap only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R271.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvasionInfraProfile(
            ruleId: "R271",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.ThreatIntel },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port" },
            evidenceFields: new[] { "network.source", "network.destination", "threatintel.feedConfidence", "reputation.score", "matched_conditions" },
            positiveConditions: new[]
            {
                "Exact source-IP match in a fresh local threat-feed snapshot is required.",
                "Independent malicious source-IP reputation and typed inbound transport must corroborate the feed match.",
                "Packet descriptions, host hints, and unverified reputation cannot substitute for a feed match."
            },
            negativeConditions: new[]
            {
                "Do not alert when the required telemetry fields are absent.",
                "Do not alert on generic logs that mention the concept but lack network/process/pipeline evidence."
            },
            minimumConfidence: 88,
            threshold: 1,
            window: TimeSpan.FromMinutes(20),
            cooldown: TimeSpan.FromMinutes(45),
            distinctBy: "source+destination+behavior",
            falsePositives: new[] { "Stale feeds, parked domains, and shared infrastructure can cause false positives; verify feed age and destination role." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "Threshold", "WindowSeconds" },
            requiredTests: new[] { "positive R271 evidence-gated sample", "negative R271 descriptor-only sample", "negative R271 missing telemetry sample" });

        public R271_ThreatFeedIocWithLowReputationOverlapRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            // Match the same observed SOURCE IP in the locally loaded feed and the
            // source-IP reputation enrichment. Never infer an IOC from packet Info.
            if (!Carthago.Services.ThreatFeedService.TryMatch(record.Source ?? string.Empty, out var feed)
                || !NetworkBatch271275Evidence.HasSourceOverlap(
                    record, feed, Carthago.Services.ThreatFeedService.CurrentStats.LastBuild,
                    context.TimestampUtc))
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                    "TRUSTED_SOURCE_IOC_REPUTATION_OVERLAP_REQUIRED",
                    "A fresh exact source-IP feed match and independent source reputation are required.");

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "exact_source_ip_feed_match,source_reputation_malicious,fresh_snapshot", "rule"),
                new("threatintel.feedConfidence", feed.Confidence.ToString(System.Globalization.CultureInfo.InvariantCulture), "threat-intel"),
                new("threatintel.sourceCount", feed.Sources.Length.ToString(System.Globalization.CultureInfo.InvariantCulture), "threat-intel"),
                new("reputation.score", record.ReputationScore!.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), "reputation"),
                new("rule.windowCount", "1", "rule")
            };
            evidence.AddRange(AnalystContext(
                "An inbound source IP exactly matches a fresh local feed snapshot and separately has a high malicious source-IP reputation score.",
                "The two independently sourced classifications warrant triage, but do not prove malicious activity or compromise.",
                "Shared IP infrastructure, stale reputation, and manual lookup timing may create misleading overlap.",
                "Validate feed freshness and independent reputation provenance before escalation.",
                "Review the inbound connection and the source-IP owner."));

            return MatchEvasionInfra(
                context, SeverityLevel.Critical,
                "Exact inbound source-IP threat-feed and reputation overlap",
                "SourceIpFeedReputationOverlap", evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "exact-feed-match");
                    confidence.AddEvidence(0.22, "independent-source-reputation");
                    confidence.AddEvidence(0.18, "freshness-and-transport");
                },
                count: 1, window: Profile.Window,
                cooldownKey: $"{record.Source}:{record.Destination}:SourceIpFeedReputationOverlap");
        }
    }
}
