// SPDX-License-Identifier: MIT
// File: Engine/Rules/Dns/R099_DNSQueryToNewlyRegisteredDomainRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Dns
{
    public sealed class R099_DNSQueryToNewlyRegisteredDomainRule : DnsPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R099",
            Name: "DNS Query to Newly Registered Domain",
            Category: "Dns",
            Description: "Flags DNS questions with recent reputation observation timing and DNS evidence; registration age is not available from this record.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R099.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R099",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns, RuleTelemetryKind.ThreatIntel },
            requiredFields: new[] { "source", "dns_qname" },
            evidenceFields: new[]
            {
                "dns.qname", "reputation.lastSeenDays", "reputation.score", "baseline.reason", "matched_conditions"
            },
            positiveConditions: new[]
            {
                "A DNS qname must be present in structured DNS telemetry.",
                "A recent, timestamped reputation observation must be present; this is not registration age.",
                "The query should be first-seen or infrequent for the source."
            },
            negativeConditions: new[]
            {
                "No match when reputation timing is absent.",
                "No match when baseline storage is unavailable.",
                "Do not infer newly registered domains from generic text strings."
            },
            minimumConfidence: 74,
            threshold: null,
            window: null,
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+domain",
            falsePositives: new[]
            {
                "Legitimate new SaaS vendors, newly created marketing sites, or software-update endpoints can appear recently registered.",
                "Lab or replay environments may intentionally use fresh domains."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "RecentDaysThreshold" },
            requiredTests: new[]
            {
                "positive recent-domain sample",
                "negative missing reputation timing sample",
                "negative AnyText-only sample",
                "evidence and confidence assertion"
            });

        public R099_DNSQueryToNewlyRegisteredDomainRule()
            : base(Rule, Profile)
        {
        }

        protected override IReadOnlyList<RuleFalsePositiveNote> AdditionalKnownFalsePositives => new[]
        {
            new RuleFalsePositiveNote("Legitimate new vendor or application domain", "Tune with baseline history, approved vendors, or change windows instead of removing reputation-timed detections.")
        };

        protected override string? InvestigationHintOverride
            => "Validate the owning business context for the domain, compare first-seen timing with change windows, and inspect follow-on traffic for suspicious downloads or authentication flows.";

        protected override string? TuningHintOverride
            => "Use recent-domain thresholds and approved-vendor allowlists. Keep the rule tied to structured DNS and reputation timing rather than text markers.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!NetworkBatch096100Evidence.Dns(context)
                || !TryGetDnsQuestion(context, out var query))
                return NoMatch();

            var root = RootDomain(query);
            if (LooksLikeBenignValidationQuery(query) || IsKnownTelemetryRoot(root))
                return NoMatch();

            if (!context.Record.ReputationLastSeen.HasValue)
                return NoMatch();

            var recentDaysThreshold = IntSetting(Descriptor.RuleId, "RecentDaysThreshold", 7, 1, 60);
            var daysSinceSeen = (context.TimestampUtc - context.Record.ReputationLastSeen.Value.ToUniversalTime()).TotalDays;
            if (daysSinceSeen < 0 || daysSinceSeen > recentDaysThreshold
                || context.Record.ReputationScore is int score && (score < 0 || score > 100))
                return NoMatch();

            var baseline = ObserveBaseline("dns.recent-domain", context.Record.Source ?? "unknown", query, context, $"recentDays={daysSinceSeen:F1}");
            if (string.Equals(baseline.Reason, "baseline unavailable", StringComparison.OrdinalIgnoreCase)
                || baseline.IsKnown && baseline.ObservationCount > 2 && daysSinceSeen > 3.0)
                return NoMatch();

            var highSeverity = daysSinceSeen <= 3.0 || (context.Record.ReputationScore.HasValue && context.Record.ReputationScore.Value >= 70);
            var matchedConditions = new List<string> { "recent_reputation_observation", "dns_qname_present" };
            if (baseline.IsFirstSeen || !baseline.IsKnown) matchedConditions.Add("first_seen_for_source");
            if (highSeverity) matchedConditions.Add("very_recent_reputation_or_high_risk");

            var whyMatched = $"The domain '{query}' has recent reputation activity ({daysSinceSeen:F1} days); baseline status for {context.Record.Source}: {baseline.Reason} ({baseline.ObservationCount} observations).";
            var severityReason = highSeverity
                ? "Severity is High because the reputation observation is very recent or the recorded risk score is elevated; this is not evidence of registration age."
                : "Severity is Medium because reputation activity was observed recently; domain age and malicious intent remain unverified.";
            var falsePositives = "Brand-new vendor, campaign, or software-update domains can look suspiciously recent. Confirm ownership and planned changes before escalating.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("reputation.lastSeenDays", daysSinceSeen.ToString("F1", System.Globalization.CultureInfo.InvariantCulture), "reputation"),
                new("baseline.reason", baseline.Reason, "baseline"),
                new("baseline.observationCount", baseline.ObservationCount.ToString(System.Globalization.CultureInfo.InvariantCulture), "baseline"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            if (context.Record.ReputationScore.HasValue)
                evidence.Add(new DetectionEvidenceItem("reputation.score", context.Record.ReputationScore.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), "reputation"));
            if (!string.IsNullOrWhiteSpace(context.Record.WhoisRegistrar))
                evidence.Add(new DetectionEvidenceItem("whois.registrar", context.Record.WhoisRegistrar!, "whois"));
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Review why the host is querying a recently observed domain and whether it aligns with a known rollout or user action.",
                "Inspect subsequent HTTP/TLS traffic, downloads, or authentication flows associated with the domain.",
                "Allowlist only after confirming the domain owner and intended business purpose."));

            return MatchDns(
                context,
                highSeverity ? SeverityLevel.High : SeverityLevel.Medium,
                $"Query with recent reputation observation detected: {query}",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "recent-domain-enrichment");
                    if (!string.Equals(baseline.Reason, "baseline unavailable", StringComparison.OrdinalIgnoreCase))
                        confidence.AddBaseline(baseline.IsFirstSeen || !baseline.IsKnown ? 0.18 : 0.10, baseline.Reason);
                    else
                        confidence.AddCorrelation(0.10, "baseline-unavailable-fallback");
                    if (daysSinceSeen <= 3.0) confidence.AddThreatIntel(0.16, "very-recent-domain");
                    if (context.Record.ReputationScore.HasValue && context.Record.ReputationScore.Value >= 70) confidence.AddThreatIntel(0.12, "elevated-reputation-score");
                },
                cooldownKey: $"{context.Record.Source}:{query}");
        }
    }
}
