// SPDX-License-Identifier: MIT
// File: Services/DashboardWidgetRegistry.cs
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Carthago.Models;

namespace Carthago.Services
{
    public static class DashboardWidgetTypes
    {
        public const string EmptyState = "EmptyState";
        public const string IncidentQueue = "IncidentQueue";
        public const string IncidentSummary = "IncidentSummary";
        public const string AnomalyTimeline = "AnomalyTimeline";
        public const string StatisticsCard = "StatisticsCard";
        public const string StatisticsGrid = "StatisticsGrid";
        public const string BaselineStatus = "BaselineStatus";
        public const string MlStatus = "MlStatus";
        public const string HighRiskHosts = "HighRiskHosts";
        public const string ThreatFeedHits = "ThreatFeedHits";
        public const string RecommendedActions = "RecommendedActions";
        public const string RawForensicsShortcuts = "RawForensicsShortcuts";
        public const string CiscoStatus = "CiscoStatus";
        public const string SinkDeliveryStatus = "SinkDeliveryStatus";
        public const string DemoControls = "DemoControls";
    }

    public sealed class DashboardWidgetDescriptor
    {
        public DashboardWidgetDescriptor(
            string widgetType,
            string displayName,
            string description,
            string category,
            string requiresFeature,
            int defaultColumnSpan = 1,
            int defaultRowSpan = 1,
            bool isAdvanced = false,
            bool requiresDemoMode = false)
        {
            WidgetType = widgetType;
            DisplayName = displayName;
            Description = description;
            Category = category;
            RequiresFeature = requiresFeature;
            DefaultColumnSpan = Math.Max(1, defaultColumnSpan);
            DefaultRowSpan = Math.Max(1, defaultRowSpan);
            IsAdvanced = isAdvanced;
            RequiresDemoMode = requiresDemoMode;
        }

        public string WidgetType { get; }
        public string DisplayName { get; }
        public string Description { get; }
        public string Category { get; }
        public string RequiresFeature { get; }
        public int DefaultColumnSpan { get; }
        public int DefaultRowSpan { get; }
        public bool IsAdvanced { get; }
        public bool RequiresDemoMode { get; }
    }

    public static class DashboardWidgetRegistry
    {
        private static readonly IReadOnlyList<DashboardWidgetDescriptor> _widgets = new ReadOnlyCollection<DashboardWidgetDescriptor>(new[]
        {
            new DashboardWidgetDescriptor(DashboardWidgetTypes.IncidentQueue, "Incident queue", "Compact queue of correlated security incidents.", "Incidents", "Incidents", 2),
            new DashboardWidgetDescriptor(DashboardWidgetTypes.IncidentSummary, "Incident summary", "Highest-risk incident with evidence and current status.", "Incidents", "Incidents", 2),
            new DashboardWidgetDescriptor(DashboardWidgetTypes.AnomalyTimeline, "Anomaly timeline", "Recent anomaly-first activity without raw rows.", "Anomalies", "Anomalies", 2),
            new DashboardWidgetDescriptor(DashboardWidgetTypes.StatisticsCard, "Statistics card", "Single user-selected metric card.", "Statistics", "Statistics"),
            new DashboardWidgetDescriptor(DashboardWidgetTypes.StatisticsGrid, "Statistics grid", "Small set of recommended security metrics.", "Statistics", "Statistics", 2),
            new DashboardWidgetDescriptor(DashboardWidgetTypes.BaselineStatus, "Baseline learning", "Status of deterministic behavior baseline learning.", "Detection", "Baseline"),
            new DashboardWidgetDescriptor(DashboardWidgetTypes.MlStatus, "ML-assisted score", "Lightweight status for optional ML-assisted anomaly scoring.", "Detection", "Ml"),
            new DashboardWidgetDescriptor(DashboardWidgetTypes.HighRiskHosts, "High-risk hosts", "Hosts currently associated with the highest risk.", "Incidents", "Incidents"),
            new DashboardWidgetDescriptor(DashboardWidgetTypes.ThreatFeedHits, "Threat feed hits", "Reputation and threat-intel matches summarized as a card.", "Threat intel", "Statistics"),
            new DashboardWidgetDescriptor(DashboardWidgetTypes.RecommendedActions, "Recommended actions", "Next actions from the highest-priority incident.", "Response", "RecommendedActions", 2),
            new DashboardWidgetDescriptor(DashboardWidgetTypes.RawForensicsShortcuts, "Raw/forensics shortcuts", "Quick links to raw traffic, raw detections, and delivery logs.", "Advanced", "RawSummary", 2, isAdvanced: true),
            new DashboardWidgetDescriptor(DashboardWidgetTypes.CiscoStatus, "Cisco status", "Shortcut and summary for Cisco/syslog tooling.", "Advanced", "Cisco", isAdvanced: true),
            new DashboardWidgetDescriptor(DashboardWidgetTypes.SinkDeliveryStatus, "External delivery", "External sink delivery status and shortcut.", "Advanced", "Sink", isAdvanced: true),
            new DashboardWidgetDescriptor(DashboardWidgetTypes.DemoControls, "Demo controls", "Generate or clear the compromised-laptop developer demo.", "Demo", "Demo", 2, requiresDemoMode: true),
        });

        public static IReadOnlyList<DashboardWidgetDescriptor> All => _widgets;

        public static DashboardWidgetDescriptor? Find(string? widgetType)
            => _widgets.FirstOrDefault(widget => string.Equals(widget.WidgetType, widgetType, StringComparison.OrdinalIgnoreCase));

        public static IEnumerable<DashboardWidgetDescriptor> GetPickerOptions(bool demoModeEnabled, bool includeAdvanced = true)
        {
            foreach (var widget in _widgets)
            {
                if (!includeAdvanced && widget.IsAdvanced)
                    continue;
                if (widget.RequiresDemoMode && !demoModeEnabled)
                    continue;

                yield return widget;
            }
        }

        public static IEnumerable<DashboardWidgetDescriptor> GetAvailable(DashboardPreferences preferences, bool demoModeEnabled, bool includeAdvanced = true)
        {
            preferences ??= new DashboardPreferences();
            preferences.Normalize();

            foreach (var widget in _widgets)
            {
                if (!includeAdvanced && widget.IsAdvanced)
                    continue;
                if (widget.RequiresDemoMode && !demoModeEnabled)
                    continue;
                if (IsFeatureEnabled(preferences, widget.RequiresFeature))
                    yield return widget;
            }
        }

        public static bool IsAvailable(string? widgetType, DashboardPreferences preferences, bool demoModeEnabled)
        {
            var descriptor = Find(widgetType);
            if (descriptor == null)
                return false;
            if (descriptor.RequiresDemoMode && !demoModeEnabled)
                return false;
            return IsFeatureEnabled(preferences ?? new DashboardPreferences(), descriptor.RequiresFeature);
        }

        public static bool IsFeatureEnabled(DashboardPreferences preferences, string? feature)
        {
            preferences ??= new DashboardPreferences();
            return feature switch
            {
                "Incidents" => preferences.ShowIncidentsSection,
                "Anomalies" => preferences.ShowAnomaliesSection,
                "Statistics" => preferences.ShowStatisticsSection,
                "Timeline" => preferences.ShowTimelineSection,
                "Baseline" => preferences.ShowBaselineSection,
                "Ml" => preferences.ShowMlSection,
                "RecommendedActions" => preferences.ShowRecommendedActionsSection,
                "RawSummary" => preferences.ShowRawSummarySection || preferences.ShowForensicsShortcutsSection,
                "Cisco" => preferences.ShowCiscoSection,
                "Sink" => preferences.ShowSinkSection,
                "Demo" => preferences.ShowDemoSection,
                _ => true
            };
        }
    }
}
