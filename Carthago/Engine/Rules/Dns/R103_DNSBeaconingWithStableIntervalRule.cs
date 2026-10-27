// SPDX-License-Identifier: MIT
// File: Engine/Rules/Dns/R103_DNSBeaconingWithStableIntervalRule.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Dns
{
    public sealed class R103_DNSBeaconingWithStableIntervalRule : DnsPrecisionDetectionRuleBase
    {
        private readonly NetworkBatch081085Dedup _seen = new();
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R103",
            Name: "DNS Beaconing With Stable Interval",
            Category: "Dns",
            Description: "Detects repeated DNS questions to the same root with low-jitter intervals, using windowed cadence analysis over structured DNS telemetry.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R103.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R103",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns },
            requiredFields: new[] { "source", "dns_qname" },
            evidenceFields: new[]
            {
                "dns.qname", "dns.rootDomain", "count", "window_seconds",
                "dns.averageIntervalSeconds", "dns.intervalStdDev", "dns.distinctQueries", "matched_conditions"
            },
            positiveConditions: new[]
            {
                "A DNS qname must be present in structured DNS telemetry.",
                "Queries to the same root must repeat enough times within a window to measure cadence.",
                "Observed intervals must be stable with low jitter and limited exact-query variation."
            },
            negativeConditions: new[]
            {
                "No match when DNS qname telemetry is absent.",
                "Do not infer beaconing from a single query or host text alone.",
                "Suppress known platform telemetry roots or rotating query names unless cadence and exact-query reuse are unusually strong."
            },
            minimumConfidence: 80,
            threshold: 6,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+root_domain",
            falsePositives: new[]
            {
                "Software updates, endpoint agents, and health-check services can produce periodic DNS lookups.",
                "Some backup or remote-management products poll with stable cadence."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "MinAverageIntervalSeconds", "JitterFraction", "MaxDistinctQueries" },
            requiredTests: new[]
            {
                "positive stable-cadence DNS sample",
                "negative missing DNS telemetry",
                "negative AnyText-only sample",
                "threshold and cadence assertion"
            });

        public R103_DNSBeaconingWithStableIntervalRule()
            : base(Rule, Profile)
        {
        }

        protected override IReadOnlyList<RuleFalsePositiveNote> AdditionalKnownFalsePositives => new[]
        {
            new RuleFalsePositiveNote("Endpoint agents or health checks with periodic DNS polling", "Tune approved roots and minimum sample counts instead of weakening cadence validation.")
        };

        protected override string? InvestigationHintOverride
            => "Review the periodicity of queries to the same root, identify the responsible process or service, and correlate the cadence with follow-on connections.";

        protected override string? TuningHintOverride
            => "Tune sample count, minimum interval, and jitter fraction. Keep the rule behavioral so it cannot alert from a single DNS host string.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!NetworkBatch096100Evidence.Dns(context)
                || !TryGetDnsQuestion(context, out var query))
                return NoMatch();
            // Count unique packet observations, not duplicate record delivery.
            if (!_seen.First(context.Record.Id, context.TimestampUtc))
                return NoMatch();

            var root = RootDomain(query);
            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 900, 60, 7200));
            var minimumSamples = IntSetting(Descriptor.RuleId, "Threshold", 6, 3, 200);
            var minimumAverageInterval = IntSetting(Descriptor.RuleId, "MinAverageIntervalSeconds", 10, 1, 3600);
            var jitterFraction = DoubleSetting(Descriptor.RuleId, "JitterFraction", 0.10, 0.01, 1.0);
            var maxDistinctQueries = IntSetting(Descriptor.RuleId, "MaxDistinctQueries", 2, 1, 20);
            var queryTimestamps = SnapshotWindowEvents($"{Descriptor.RuleId}:{context.Record.Source}:{root}:exact:{query}", context.TimestampUtc, window);
            if (queryTimestamps.Count < minimumSamples)
                return NoMatch();

            var distinctQueryCount = CountDistinctValues($"{Descriptor.RuleId}:{context.Record.Source}:{root}:query", query, context.TimestampUtc, window);
            if (distinctQueryCount > maxDistinctQueries)
                return NoMatch();

            var intervals = new List<double>();
            for (var index = 1; index < queryTimestamps.Count; index++)
                intervals.Add((queryTimestamps[index] - queryTimestamps[index - 1]).TotalSeconds);

            if (intervals.Count == 0)
                return NoMatch();

            var averageInterval = intervals.Average();
            if (averageInterval < minimumAverageInterval)
                return NoMatch();

            var stdDev = Math.Sqrt(intervals.Select(value => (value - averageInterval) * (value - averageInterval)).Average());
            if (stdDev > Math.Max(1.0, averageInterval * jitterFraction))
                return NoMatch();

            if (IsKnownTelemetryRoot(root) && (queryTimestamps.Count < minimumSamples + 2 || distinctQueryCount > 1) && stdDev > Math.Max(0.75, averageInterval * (jitterFraction / 2.0)))
                return NoMatch();

            var highSeverity = (queryTimestamps.Count >= minimumSamples + 2 && distinctQueryCount == 1)
                || stdDev <= Math.Max(0.5, averageInterval * 0.05);
            var matchedConditions = new List<string> { "stable_dns_interval", "windowed_sample_threshold", "dns_qname_present" };
            if (highSeverity)
                matchedConditions.Add("low_jitter_high_sample_count");
            matchedConditions.Add("exact_query_reuse");

            var whyMatched = $"{context.Record.Source} queried {query} {queryTimestamps.Count} times with an average interval of {averageInterval:F1}s and standard deviation of {stdDev:F1}s.";
            var severityReason = highSeverity
                ? "Severity is High because the cadence is both stable and well-sampled, which is characteristic of beaconing rather than opportunistic DNS usage."
                : "Severity is Medium because the cadence is stable, but the sample volume or jitter margin leaves more room for benign polling explanations.";
            var falsePositives = "Endpoint agents, health checks, and backup tooling can poll domains periodically. Validate the process owner and root domain before escalating.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("count", queryTimestamps.Count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("dns.averageIntervalSeconds", averageInterval.ToString("F1", System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("dns.intervalStdDev", stdDev.ToString("F1", System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("dns.distinctQueries", distinctQueryCount.ToString(System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Identify the host process or workload issuing the periodic DNS queries and determine whether the cadence matches an approved agent.",
                "Review subsequent network activity to the resolved destinations for corresponding beacon traffic.",
                "Tune approved telemetry roots or increase the sample requirement only after confirming the polling is benign."));

            return MatchDns(
                context,
                highSeverity ? SeverityLevel.High : SeverityLevel.Medium,
                $"Stable-interval DNS beaconing pattern observed for {root}",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "stable-interval-cadence");
                    confidence.AddEvidence(0.20, "windowed-sample-threshold");
                    if (highSeverity) confidence.AddEvidence(0.12, "low-jitter-high-sample-count");
                    confidence.AddEvidence(0.08, "exact-query-reuse");
                    if (!IsKnownTelemetryRoot(root)) confidence.AddCorrelation(0.10, "non-approved-root");
                },
                count: queryTimestamps.Count,
                window: window,
                cooldownKey: $"{context.Record.Source}:{root}");
        }
    }
}
