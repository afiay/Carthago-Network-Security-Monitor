// SPDX-License-Identifier: MIT
// File: Services/DashboardPresetService.cs
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Carthago.Models;

namespace Carthago.Services
{
    public sealed class DashboardPresetDescriptor
    {
        public DashboardPresetDescriptor(string id, string name, string description, bool requiresDemoMode = false)
        {
            Id = id;
            Name = name;
            Description = description;
            RequiresDemoMode = requiresDemoMode;
        }

        public string Id { get; }
        public string Name { get; }
        public string Description { get; }
        public bool RequiresDemoMode { get; }
    }

    public static class DashboardPresetService
    {
        public const string MinimalSecurityOverview = "minimal-security-overview";
        public const string SocAnalystView = "soc-analyst-view";
        public const string NetworkAdminView = "network-admin-view";
        public const string DemoView = "demo-view";

        private static readonly IReadOnlyList<DashboardPresetDescriptor> _presets = new ReadOnlyCollection<DashboardPresetDescriptor>(new[]
        {
            new DashboardPresetDescriptor(MinimalSecurityOverview, "Minimal Security Overview", "Active incidents, high priority queue, anomaly count, incident queue, and timeline."),
            new DashboardPresetDescriptor(SocAnalystView, "SOC Analyst View", "Incident queue, details, risk reasons, recommended actions, timeline, and high-risk hosts."),
            new DashboardPresetDescriptor(NetworkAdminView, "Network Admin View", "Cisco status, external delivery, raw forensic shortcuts, active incidents, and threat feed hits."),
            new DashboardPresetDescriptor(DemoView, "Demo View", "Demo controls, active incidents, incident queue, timeline, and recommended actions.", requiresDemoMode: true),
        });

        public static IReadOnlyList<DashboardPresetDescriptor> All => _presets;

        public static IEnumerable<DashboardPresetDescriptor> GetAvailable(bool demoModeEnabled)
            => _presets.Where(preset => !preset.RequiresDemoMode || demoModeEnabled);

        public static DashboardPreferences ApplyPreset(string? presetId, bool demoModeEnabled)
        {
            var prefs = new DashboardPreferences
            {
                UseMinimalDashboard = true,
                ShowEmptyDashboardByDefault = false,
                SelectedPresetId = presetId
            };

            switch (presetId)
            {
                case SocAnalystView:
                    EnableIncidentAnomalyResponse(prefs);
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.IncidentQueue, "Incident queue", 0, metric: null, span: 2));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.IncidentSummary, "Highest-risk incident", 1, metric: null, span: 2));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.RecommendedActions, "Recommended actions", 2, metric: null, span: 2));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.AnomalyTimeline, "Timeline", 3, metric: null, span: 2));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.HighRiskHosts, "High-risk hosts", 4));
                    break;

                case NetworkAdminView:
                    prefs.ShowIncidentsSection = true;
                    prefs.ShowStatisticsSection = true;
                    prefs.ShowRawSummarySection = true;
                    prefs.ShowForensicsShortcutsSection = true;
                    prefs.ShowCiscoSection = true;
                    prefs.ShowSinkSection = true;
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.CiscoStatus, "Cisco status", 0));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.SinkDeliveryStatus, "External delivery", 1));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.RawForensicsShortcuts, "Raw/forensics shortcuts", 2, metric: null, span: 2));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.StatisticsCard, "Active incidents", 3, "ActiveIncidents"));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.StatisticsCard, "Threat feed hits", 4, "ThreatFeedHits"));
                    break;

                case DemoView when demoModeEnabled:
                    EnableIncidentAnomalyResponse(prefs);
                    prefs.ShowStatisticsSection = true;
                    prefs.ShowDemoSection = true;
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.DemoControls, "Demo controls", 0, metric: null, span: 2));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.StatisticsCard, "Active incidents", 1, "ActiveIncidents"));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.IncidentQueue, "Incident queue", 2, metric: null, span: 2));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.AnomalyTimeline, "Timeline", 3, metric: null, span: 2));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.RecommendedActions, "Recommended actions", 4, metric: null, span: 2));
                    break;

                default:
                    prefs.SelectedPresetId = MinimalSecurityOverview;
                    EnableIncidentAnomalyResponse(prefs);
                    prefs.ShowStatisticsSection = true;
                    prefs.ShowRawSummarySection = true;
                    prefs.ShowForensicsShortcutsSection = true;
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.StatisticsCard, "Active incidents", 0, "ActiveIncidents"));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.HighRiskHosts, "High-risk hosts", 1));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.StatisticsCard, "New anomalies", 2, "NewAnomalies15m"));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.ThreatFeedHits, "Threat feed hits", 3));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.BaselineStatus, "Baseline confidence", 4));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.AnomalyTimeline, "Anomaly timeline", 5, metric: null, span: 2));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.IncidentSummary, "Signal details", 6, metric: null, span: 2));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.RecommendedActions, "Recommended actions", 7, metric: null, span: 2));
                    prefs.Widgets.Add(Widget(DashboardWidgetTypes.RawForensicsShortcuts, "Raw/advanced shortcuts", 8, metric: null, span: 2));
                    break;
            }

            prefs.Normalize();
            return prefs;
        }

        public static DashboardPreferences CreateEmptyMinimal()
        {
            return new DashboardPreferences
            {
                UseMinimalDashboard = true,
                ShowEmptyDashboardByDefault = true,
                Widgets = new List<DashboardWidgetConfig>()
            };
        }

        private static void EnableIncidentAnomalyResponse(DashboardPreferences prefs)
        {
            prefs.ShowIncidentsSection = true;
            prefs.ShowAnomaliesSection = true;
            prefs.ShowTimelineSection = true;
            prefs.ShowRecommendedActionsSection = true;
            prefs.ShowBaselineSection = true;
        }

        private static DashboardWidgetConfig Widget(string type, string title, int order, string? metric = null, int span = 1)
        {
            var widget = new DashboardWidgetConfig
            {
                WidgetType = type,
                Title = title,
                Order = order,
                ColumnSpan = Math.Max(1, span),
                IsEnabled = true
            };

            if (!string.IsNullOrWhiteSpace(metric))
                widget.Settings["MetricKey"] = metric;

            return widget;
        }
    }
}
