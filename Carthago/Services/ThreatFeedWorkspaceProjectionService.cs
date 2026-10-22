// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Carthago.Analytics.Models;
using Carthago.Models;

namespace Carthago.Services
{
    public static class ThreatFeedWorkspaceProjectionService
    {
        public static ThreatFeedWorkspaceSnapshot Build(IEnumerable<Incident> incidents, IEnumerable<AnomalySignal> anomalies, DateTime utcNow)
        {
            var incidentList = incidents?.ToArray() ?? Array.Empty<Incident>();
            var anomalyList = anomalies?.ToArray() ?? Array.Empty<AnomalySignal>();
            var matches = new List<ThreatMatchProjection>();

            foreach (var incident in incidentList)
            {
                if (!LooksThreatLinked(incident))
                    continue;

                var indicator = SelectIndicator(incident);
                if (string.IsNullOrWhiteSpace(indicator))
                    continue;

                ThreatFeedService.TryMatch(indicator, out var threatMatch);
                var confidence = threatMatch?.Confidence ?? InferConfidence(incident);
                var sources = threatMatch?.Sources?.Length > 0 ? threatMatch.Sources : InferSources(incident);
                var tags = MergeTags(incident.Tags, threatMatch?.Tags, incident.RelatedAnomalies.SelectMany(item => item.Tags));
                var rules = incident.RelatedEvents.Select(evt => evt.RuleId)
                    .Concat(incident.RelatedAnomalies.SelectMany(item => item.RelatedRuleIds))
                    .Where(rule => !string.IsNullOrWhiteSpace(rule))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(6)
                    .ToArray();

                matches.Add(new ThreatMatchProjection(
                    Id: incident.Id,
                    Title: incident.Title,
                    Indicator: indicator,
                    IndicatorKind: ClassifyIndicator(indicator, threatMatch?.Kind),
                    Severity: string.IsNullOrWhiteSpace(incident.Severity) ? "High" : incident.Severity,
                    RiskScore: Math.Clamp(incident.RiskScore, 0, 100),
                    Confidence: Math.Clamp(confidence, 0, 100),
                    Classification: InferClassification(incident, threatMatch?.Tags),
                    FeedSource: string.Join(" • ", sources),
                    RelatedHost: Safe(incident.PrimarySourceIp, "Unknown host"),
                    RelatedIncidentTitle: incident.Title,
                    RelatedIncidentId: incident.Id,
                    FirstSeenUtc: FirstSeen(incident),
                    Summary: Safe(incident.Summary, incident.RiskReasons.FirstOrDefault() ?? "Threat-linked behavior was correlated into this incident."),
                    Evidence: incident.Evidence.Concat(incident.RiskReasons).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray(),
                    Tags: tags,
                    RelatedRules: rules,
                    FeedState: threatMatch == null ? "Observed" : "Matched"));
            }

            foreach (var anomaly in anomalyList)
            {
                if (!LooksThreatLinked(anomaly))
                    continue;

                var indicator = anomaly.DestinationHost ?? anomaly.DestinationIp;
                if (string.IsNullOrWhiteSpace(indicator) || matches.Any(match => string.Equals(match.Indicator, indicator, StringComparison.OrdinalIgnoreCase)))
                    continue;

                ThreatFeedService.TryMatch(indicator, out var threatMatch);
                matches.Add(new ThreatMatchProjection(
                    Id: anomaly.Id,
                    Title: string.IsNullOrWhiteSpace(anomaly.Title) ? "Threat-linked anomaly" : anomaly.Title,
                    Indicator: indicator,
                    IndicatorKind: ClassifyIndicator(indicator, threatMatch?.Kind),
                    Severity: string.IsNullOrWhiteSpace(anomaly.Severity) ? "High" : anomaly.Severity,
                    RiskScore: NormalizeScore(anomaly.Score),
                    Confidence: Math.Clamp(threatMatch?.Confidence ?? 72, 0, 100),
                    Classification: InferClassification(anomaly, threatMatch?.Tags),
                    FeedSource: string.Join(" • ", threatMatch?.Sources?.Length > 0 ? threatMatch.Sources : new[] { "Threat / reputation analytics" }),
                    RelatedHost: Safe(anomaly.SourceIp, "Unknown host"),
                    RelatedIncidentTitle: "No related incident",
                    RelatedIncidentId: string.Empty,
                    FirstSeenUtc: anomaly.CreatedUtc,
                    Summary: Safe(anomaly.Description, "Threat-linked anomaly observed."),
                    Evidence: anomaly.Reasons.Take(4).ToArray(),
                    Tags: MergeTags(anomaly.Tags, threatMatch?.Tags),
                    RelatedRules: anomaly.RelatedRuleIds.Distinct(StringComparer.OrdinalIgnoreCase).Take(6).ToArray(),
                    FeedState: threatMatch == null ? "Observed" : "Matched"));
            }

            var orderedMatches = matches
                .OrderByDescending(match => SeverityRank(match.Severity))
                .ThenByDescending(match => match.RiskScore)
                .ThenByDescending(match => match.FirstSeenUtc)
                .ToArray();

            var topSources = orderedMatches
                .SelectMany(match => match.FeedSource.Split(" • ", StringSplitOptions.RemoveEmptyEntries).Select(source => new { match, source }))
                .GroupBy(item => item.source, StringComparer.OrdinalIgnoreCase)
                .Select(group => new ThreatFeedSummaryRow(
                    Name: group.Key,
                    Count: group.Count(),
                    Severity: HighestSeverity(group.Select(item => item.match.Severity)),
                    TrendText: $"{group.Count(match => match.match.FirstSeenUtc >= utcNow.AddMinutes(-15))} in 15m"))
                .OrderByDescending(row => row.Count)
                .ThenBy(row => row.Name)
                .Take(5)
                .ToArray();

            var recentTypes = orderedMatches
                .GroupBy(match => match.IndicatorKind, StringComparer.OrdinalIgnoreCase)
                .Select(group => new ThreatFeedSummaryRow(
                    Name: group.Key,
                    Count: group.Count(),
                    Severity: HighestSeverity(group.Select(item => item.Severity)),
                    TrendText: $"{group.Count(match => match.FirstSeenUtc >= utcNow.AddHours(-24))} in 24h"))
                .OrderByDescending(row => row.Count)
                .ThenBy(row => row.Name)
                .Take(6)
                .ToArray();

            var stats = ThreatFeedService.CurrentStats;
            return new ThreatFeedWorkspaceSnapshot(
                Matches: orderedMatches,
                TopSources: topSources,
                RecentIndicatorTypes: recentTypes,
                ActiveMatchCount: orderedMatches.Length,
                HighConfidenceCount: orderedMatches.Count(match => match.Confidence >= 80),
                SuppressedCount: incidentList.Count(incident => incident.IsSuppressed && LooksThreatLinked(incident)),
                NewIndicators24h: orderedMatches.Count(match => match.FirstSeenUtc >= utcNow.AddHours(-24)),
                FeedHealthText: stats.Indicators > 0 ? "Healthy" : "Warming",
                FeedHealthDetail: $"Indicators {stats.Indicators} • Feeds {stats.Feeds}");
        }

        private static bool LooksThreatLinked(Incident incident)
            => incident.RelatedAnomalies.Any(LooksThreatLinked)
               || incident.RelatedEvents.Any(evt => evt.RuleId is "R003" or "R016")
               || Contains(incident.Category, "Threat")
               || incident.RiskReasons.Any(reason => Contains(reason, "threat intelligence") || Contains(reason, "reputation"));

        private static bool LooksThreatLinked(AnomalySignal anomaly)
            => Contains(anomaly.Category, "Threat")
               || Contains(anomaly.Category, "Reputation")
               || anomaly.RelatedRuleIds.Any(rule => rule is "R003" or "R016")
               || anomaly.Tags.Any(tag => Contains(tag, "threat") || Contains(tag, "reputation"));

        private static string? SelectIndicator(Incident incident)
            => incident.PrimaryDestinationHost
               ?? incident.PrimaryDestinationIp
               ?? incident.RelatedEvents.Select(evt => evt.DestinationHost ?? evt.DestinationIp).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))
               ?? incident.RelatedAnomalies.Select(anomaly => anomaly.DestinationHost ?? anomaly.DestinationIp).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));

        private static string[] InferSources(Incident incident)
            => incident.RelatedEvents.Any(evt => evt.RuleId == "R003")
                ? new[] { "Threat Feed" }
                : new[] { "Reputation" };

        private static int InferConfidence(Incident incident)
            => incident.RelatedEvents.Any(evt => evt.RuleId == "R003") ? 96 : 88;

        private static string InferClassification(Incident incident, IEnumerable<string>? tags)
        {
            if (Contains(incident.Category, "Command") || tags?.Any(tag => Contains(tag, "c2")) == true)
                return "Command & Control";
            if (tags?.Any(tag => Contains(tag, "botnet")) == true)
                return "Botnet";
            if (incident.RelatedEvents.Any(evt => evt.RuleId == "R016"))
                return "Reputation";
            return "Threat match";
        }

        private static string InferClassification(AnomalySignal anomaly, IEnumerable<string>? tags)
        {
            if (Contains(anomaly.Category, "ThreatIntel"))
                return "Threat intelligence";
            if (tags?.Any(tag => Contains(tag, "phishing")) == true)
                return "Phishing";
            return "Threat-linked anomaly";
        }

        private static string ClassifyIndicator(string value, IndicatorKind? kind)
        {
            if (kind.HasValue)
                return kind.Value.ToString();

            if (Uri.TryCreate(value, UriKind.Absolute, out _))
                return "URL";
            if (value.Contains(':'))
                return value.Count(ch => ch == ':') >= 2 ? "IPv6" : "URL";
            if (value.Count(ch => ch == '.') == 3 && value.All(ch => char.IsDigit(ch) || ch == '.'))
                return "IPv4";
            if (value.Contains('.'))
                return "Domain";
            return "Indicator";
        }

        private static string[] MergeTags(params IEnumerable<string>?[] sources)
            => sources
                .Where(source => source != null)
                .SelectMany(source => source!)
                .Where(tag => !string.IsNullOrWhiteSpace(tag))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(8)
                .ToArray();

        private static int NormalizeScore(double rawScore)
        {
            if (double.IsNaN(rawScore) || double.IsInfinity(rawScore))
                return 0;
            if (rawScore <= 1.0)
                return (int)Math.Round(Math.Clamp(rawScore, 0.0, 1.0) * 100.0, MidpointRounding.AwayFromZero);
            return (int)Math.Round(Math.Clamp(rawScore, 0.0, 100.0), MidpointRounding.AwayFromZero);
        }

        private static DateTime FirstSeen(Incident incident)
        {
            if (incident.FirstSeenUtc != default)
                return incident.FirstSeenUtc;
            if (incident.CreatedUtc != default)
                return incident.CreatedUtc;
            return incident.UpdatedUtc == default ? DateTime.UtcNow : incident.UpdatedUtc;
        }

        private static int SeverityRank(string? severity)
            => severity?.ToLowerInvariant() switch
            {
                "critical" => 4,
                "high" => 3,
                "medium" => 2,
                "low" => 1,
                _ => 0
            };

        private static string HighestSeverity(IEnumerable<string> severities)
            => severities.OrderByDescending(SeverityRank).FirstOrDefault() ?? "Low";

        private static string Safe(string? value, string fallback)
            => string.IsNullOrWhiteSpace(value) ? fallback : value;

        private static bool Contains(string? value, string needle)
            => !string.IsNullOrWhiteSpace(value) && value.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    public sealed record ThreatFeedWorkspaceSnapshot(
        IReadOnlyList<ThreatMatchProjection> Matches,
        IReadOnlyList<ThreatFeedSummaryRow> TopSources,
        IReadOnlyList<ThreatFeedSummaryRow> RecentIndicatorTypes,
        int ActiveMatchCount,
        int HighConfidenceCount,
        int SuppressedCount,
        int NewIndicators24h,
        string FeedHealthText,
        string FeedHealthDetail);

    public sealed record ThreatMatchProjection(
        string Id,
        string Title,
        string Indicator,
        string IndicatorKind,
        string Severity,
        int RiskScore,
        int Confidence,
        string Classification,
        string FeedSource,
        string RelatedHost,
        string RelatedIncidentTitle,
        string RelatedIncidentId,
        DateTime FirstSeenUtc,
        string Summary,
        IReadOnlyList<string> Evidence,
        IReadOnlyList<string> Tags,
        IReadOnlyList<string> RelatedRules,
        string FeedState);

    public sealed record ThreatFeedSummaryRow(
        string Name,
        int Count,
        string Severity,
        string TrendText);
}
