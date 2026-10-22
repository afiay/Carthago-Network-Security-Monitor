// SPDX-License-Identifier: MIT
// File: Services/StatisticsMetricRegistry.cs
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using Carthago.Analytics.Models;
using Carthago.Models;

namespace Carthago.Services
{
    public sealed class StatisticsMetricContext
    {
        public IReadOnlyList<Incident> Incidents { get; init; } = Array.Empty<Incident>();
        public IReadOnlyList<AnomalySignal> Anomalies { get; init; } = Array.Empty<AnomalySignal>();
        public IReadOnlyList<DetectionEvent> Detections { get; init; } = Array.Empty<DetectionEvent>();
        public BaselineStatus BaselineStatus { get; init; } = new();
        public bool DemoModeEnabled { get; init; }
        public DateTime NowUtc { get; init; } = DateTime.UtcNow;
    }

    public sealed class StatisticsMetricValue
    {
        public StatisticsMetricValue(string value, string detail = "", string state = "normal")
        {
            Value = value;
            Detail = detail;
            State = state;
        }

        public string Value { get; }
        public string Detail { get; }
        public string State { get; }
    }

    public sealed class StatisticsTimeWindowOption
    {
        public StatisticsTimeWindowOption(string key, string displayName, int minutes)
        {
            Key = key;
            DisplayName = displayName;
            Minutes = Math.Max(1, minutes);
        }

        public string Key { get; }
        public string DisplayName { get; }
        public int Minutes { get; }
    }

    public sealed class StatisticsMetricDescriptor
    {
        public StatisticsMetricDescriptor(
            string key,
            string displayName,
            string description,
            string category,
            string defaultTimeWindow,
            Func<StatisticsMetricContext, StatisticsMetricValue> resolver)
        {
            Key = key;
            DisplayName = displayName;
            Description = description;
            Category = category;
            DefaultTimeWindow = defaultTimeWindow;
            Resolve = resolver;
        }

        public string Key { get; }
        public string DisplayName { get; }
        public string Description { get; }
        public string Category { get; }
        public string DefaultTimeWindow { get; }
        public Func<StatisticsMetricContext, StatisticsMetricValue> Resolve { get; }
    }

    public static class StatisticsTimeWindows
    {
        private static readonly IReadOnlyList<StatisticsTimeWindowOption> _all = new ReadOnlyCollection<StatisticsTimeWindowOption>(new[]
        {
            new StatisticsTimeWindowOption("15m", "15 minutes", 15),
            new StatisticsTimeWindowOption("1h", "1 hour", 60),
            new StatisticsTimeWindowOption("24h", "24 hours", 1440),
            new StatisticsTimeWindowOption("7d", "7 days", 10080),
        });

        public static IReadOnlyList<StatisticsTimeWindowOption> All => _all;

        public static StatisticsTimeWindowOption FindOrDefault(string? key, string? fallback = "15m")
            => _all.FirstOrDefault(item => string.Equals(item.Key, key, StringComparison.OrdinalIgnoreCase))
               ?? _all.FirstOrDefault(item => string.Equals(item.Key, fallback, StringComparison.OrdinalIgnoreCase))
               ?? _all[0];
    }

    public static class StatisticsMetricRegistry
    {
        private static readonly IReadOnlyList<StatisticsMetricDescriptor> _metrics = new ReadOnlyCollection<StatisticsMetricDescriptor>(new[]
        {
            Metric("ActiveIncidents", "Active incidents", "Unresolved correlated incidents.", "Incidents", ctx => Count(ActiveIncidents(ctx).Count(), "Correlated investigations in queue")),
            Metric("CriticalIncidents", "Critical incidents", "Unresolved critical incidents.", "Incidents", ctx => Count(ActiveIncidents(ctx).Count(i => IsSeverity(i, "Critical")), "Require immediate review")),
            Metric("HighIncidents", "High incidents", "Unresolved high-severity incidents.", "Incidents", ctx => Count(ActiveIncidents(ctx).Count(i => IsSeverity(i, "High")), "High priority queue")),
            Metric("NewAnomalies", "New anomalies", "Anomalies observed in the selected time window.", "Anomalies", ctx => CountAnomalies(ctx, "15m"), "15m"),
            Metric("NewAnomalies15m", "New anomalies", "Anomalies observed in the last 15 minutes.", "Anomalies", ctx => CountAnomalies(ctx, "15m"), "15m"),
            Metric("NewAnomalies1h", "New anomalies", "Anomalies observed in the last hour.", "Anomalies", ctx => CountAnomalies(ctx, "1h"), "1h"),
            Metric("HighestRiskHost", "Highest risk host", "Host attached to the currently highest-risk unresolved incident.", "Incidents", HighestRiskHost),
            Metric("ThreatFeedHits", "Threat feed hits", "Threat-intel and reputation matches in current anomaly set.", "Threat intel", ThreatFeedHits),
            Metric("BaselineConfidence", "Baseline confidence", "Current deterministic baseline confidence.", "Baseline", ctx => new StatisticsMetricValue(Safe(ctx.BaselineStatus.Confidence, "Learning"), BuildBaselineDetail(ctx.BaselineStatus))),
            Metric("MlAnomalyCount", "ML-assisted anomalies", "Signals tagged as ML-assisted scoring.", "ML", ctx => Count(ctx.Anomalies.Count(a => ContainsAny(a.Category, "ml") || a.Tags.Any(t => ContainsAny(t, "ml"))), "ML-assisted behavior score")),
            Metric("SuppressedIncidents", "Suppressed incidents", "Incidents suppressed by analyst feedback.", "Incidents", ctx => Count(ctx.Incidents.Count(i => i.IsSuppressed), "Suppression active")),
            Metric("FalsePositiveCount", "False positives", "Incidents marked as false positive.", "Feedback", ctx => Count(ctx.Incidents.Count(i => string.Equals(i.AnalystFeedbackType, "FalsePositive", StringComparison.OrdinalIgnoreCase)), "Analyst feedback")),
            Metric("ConfirmedSuspiciousCount", "Confirmed suspicious", "Incidents confirmed as suspicious.", "Feedback", ctx => Count(ctx.Incidents.Count(i => string.Equals(i.AnalystFeedbackType, "ConfirmedSuspicious", StringComparison.OrdinalIgnoreCase)), "Analyst feedback")),
            Metric("RawDetectionsCount", "Raw detections", "Rule detections currently held in memory.", "Forensics", ctx => Count(ctx.Detections.Count, "Available in Advanced / Raw Detections")),
            Metric("SinkFailures", "External delivery failures", "Sink delivery failures visible in delivery logs.", "Integrations", ctx => Count(ctx.Detections.Count(d => ContainsAny(d.Description, "sink", "delivery failed", "webhook failed")), "Open External delivery for details")),
            Metric("CiscoCriticalEvents", "Cisco critical events", "Cisco/syslog-related critical detections.", "Cisco", ctx => Count(ctx.Detections.Count(d => IsSeverity(d, SeverityLevel.Critical) && ContainsAny(d.Description + " " + d.RuleId, "cisco", "syslog")), "Open Cisco tools for details")),
            Metric("DemoIncidentCount", "Demo incidents", "Developer demo incidents currently present.", "Demo", ctx => Count(ctx.Incidents.Count(i => i.Tags.Any(t => ContainsAny(t, "demo"))), ctx.DemoModeEnabled ? "Demo mode enabled" : "Demo mode hidden")),
        });

        public static IReadOnlyList<StatisticsMetricDescriptor> All => _metrics;

        public static StatisticsMetricDescriptor? Find(string? key)
            => _metrics.FirstOrDefault(metric => string.Equals(metric.Key, key, StringComparison.OrdinalIgnoreCase));

        public static StatisticsMetricValue Resolve(string? key, StatisticsMetricContext context)
        {
            var descriptor = Find(key) ?? Find("ActiveIncidents")!;
            try
            {
                return descriptor.Resolve(context ?? new StatisticsMetricContext());
            }
            catch
            {
                return new StatisticsMetricValue("—", "No data", "error");
            }
        }

        public static StatisticsMetricValue Resolve(string? key, StatisticsMetricContext context, string? timeWindow)
        {
            var descriptor = Find(key) ?? Find("ActiveIncidents")!;
            if (IsTimeWindowAwareAnomalyMetric(descriptor.Key))
                return CountAnomalies(context ?? new StatisticsMetricContext(), timeWindow);

            return Resolve(descriptor.Key, context);
        }

        private static StatisticsMetricDescriptor Metric(string key, string displayName, string description, string category, Func<StatisticsMetricContext, StatisticsMetricValue> resolver, string defaultTimeWindow = "15m")
            => new(key, displayName, description, category, defaultTimeWindow, resolver);

        private static bool IsTimeWindowAwareAnomalyMetric(string key)
            => string.Equals(key, "NewAnomalies", StringComparison.OrdinalIgnoreCase)
               || string.Equals(key, "NewAnomalies15m", StringComparison.OrdinalIgnoreCase)
               || string.Equals(key, "NewAnomalies1h", StringComparison.OrdinalIgnoreCase);

        private static StatisticsMetricValue CountAnomalies(StatisticsMetricContext context, string? timeWindow)
        {
            var window = StatisticsTimeWindows.FindOrDefault(timeWindow);
            var safeContext = context ?? new StatisticsMetricContext();
            var cutoff = safeContext.NowUtc.AddMinutes(-window.Minutes);
            var count = (safeContext.Anomalies ?? Array.Empty<AnomalySignal>()).Count(anomaly => anomaly.CreatedUtc >= cutoff);
            return Count(count, $"in {window.Key}");
        }

        private static IEnumerable<Incident> ActiveIncidents(StatisticsMetricContext context)
            => (context.Incidents ?? Array.Empty<Incident>()).Where(i => !string.Equals(i.Status, "Resolved", StringComparison.OrdinalIgnoreCase));

        private static StatisticsMetricValue Count(int value, string detail)
            => new(value.ToString(CultureInfo.InvariantCulture), detail);

        private static StatisticsMetricValue HighestRiskHost(StatisticsMetricContext context)
        {
            var incident = ActiveIncidents(context)
                .OrderByDescending(i => i.RiskScore)
                .ThenByDescending(i => i.UpdatedUtc)
                .FirstOrDefault();

            if (incident == null)
                return new StatisticsMetricValue("Learning", "No active incidents yet", "empty");

            return new StatisticsMetricValue(
                Safe(incident.PrimarySourceIp, "Unknown"),
                $"Risk {incident.RiskScore} • {Safe(incident.Title, "Incident")}");
        }

        private static StatisticsMetricValue ThreatFeedHits(StatisticsMetricContext context)
        {
            var count = (context.Anomalies ?? Array.Empty<AnomalySignal>()).Count(signal =>
                ContainsAny(signal.Category, "ThreatIntelMatch", "ReputationHit", "Threat")
                || signal.RelatedRuleIds.Any(rule => string.Equals(rule, "R003", StringComparison.OrdinalIgnoreCase)
                                                  || string.Equals(rule, "R016", StringComparison.OrdinalIgnoreCase)));
            return Count(count, "Reputation and threat-intel matches");
        }

        private static bool IsSeverity(Incident incident, string severity)
            => string.Equals(incident.Severity, severity, StringComparison.OrdinalIgnoreCase);

        private static bool IsSeverity(DetectionEvent detection, SeverityLevel severity)
            => detection.Severity == severity;

        private static bool ContainsAny(string? value, params string[] needles)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            return needles.Any(needle => value.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private static string Safe(string? value, string fallback)
            => string.IsNullOrWhiteSpace(value) ? fallback : value;

        private static string BuildBaselineDetail(BaselineStatus status)
        {
            if (status == null || status.ObservedHosts == 0)
                return "Waiting for enough host observations";

            return $"{status.ObservedHosts} hosts observed • {status.LearningWindowMinutes}m learning window";
        }
    }
}
