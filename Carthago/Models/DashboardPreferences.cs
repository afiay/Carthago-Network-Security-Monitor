// SPDX-License-Identifier: MIT
// File: Models/DashboardPreferences.cs
using System;
using System.Collections.Generic;
using System.Linq;

namespace Carthago.Models
{
    /// <summary>
    /// Persisted configuration for the minimal, settings-driven dashboard.
    /// Defaults intentionally keep the dashboard empty so first launch is quiet.
    /// </summary>
    public sealed class DashboardPreferences
    {
        public bool UseMinimalDashboard { get; set; } = true;
        public bool ShowEmptyDashboardByDefault { get; set; } = true;

        public List<DashboardWidgetConfig> Widgets { get; set; } = new();

        public bool ShowIncidentsSection { get; set; }
        public bool ShowAnomaliesSection { get; set; }
        public bool ShowStatisticsSection { get; set; }
        public bool ShowTimelineSection { get; set; }
        public bool ShowBaselineSection { get; set; }
        public bool ShowMlSection { get; set; }
        public bool ShowRecommendedActionsSection { get; set; }
        public bool ShowRawSummarySection { get; set; }
        public bool ShowCiscoSection { get; set; }
        public bool ShowSinkSection { get; set; }
        public bool ShowForensicsShortcutsSection { get; set; }
        public bool ShowDemoSection { get; set; }

        public string? SelectedPresetId { get; set; }

        public DashboardPreferences Clone()
        {
            return new DashboardPreferences
            {
                UseMinimalDashboard = UseMinimalDashboard,
                ShowEmptyDashboardByDefault = ShowEmptyDashboardByDefault,
                Widgets = Widgets?.Select(widget => widget.Clone()).ToList() ?? new List<DashboardWidgetConfig>(),
                ShowIncidentsSection = ShowIncidentsSection,
                ShowAnomaliesSection = ShowAnomaliesSection,
                ShowStatisticsSection = ShowStatisticsSection,
                ShowTimelineSection = ShowTimelineSection,
                ShowBaselineSection = ShowBaselineSection,
                ShowMlSection = ShowMlSection,
                ShowRecommendedActionsSection = ShowRecommendedActionsSection,
                ShowRawSummarySection = ShowRawSummarySection,
                ShowCiscoSection = ShowCiscoSection,
                ShowSinkSection = ShowSinkSection,
                ShowForensicsShortcutsSection = ShowForensicsShortcutsSection,
                ShowDemoSection = ShowDemoSection,
                SelectedPresetId = SelectedPresetId
            };
        }

        public void Normalize()
        {
            Widgets ??= new List<DashboardWidgetConfig>();
            foreach (var widget in Widgets)
                widget.Normalize();
        }
    }

    public sealed class DashboardWidgetConfig
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string WidgetType { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;

        public int Row { get; set; }
        public int Column { get; set; }
        public int RowSpan { get; set; } = 1;
        public int ColumnSpan { get; set; } = 1;
        public int Order { get; set; }

        public bool IsEnabled { get; set; } = true;

        public Dictionary<string, string> Settings { get; set; } = new(StringComparer.OrdinalIgnoreCase);

        public DashboardWidgetConfig Clone()
        {
            return new DashboardWidgetConfig
            {
                Id = string.IsNullOrWhiteSpace(Id) ? Guid.NewGuid().ToString("N") : Id,
                WidgetType = WidgetType ?? string.Empty,
                Title = Title ?? string.Empty,
                Row = Row,
                Column = Column,
                RowSpan = RowSpan <= 0 ? 1 : RowSpan,
                ColumnSpan = ColumnSpan <= 0 ? 1 : ColumnSpan,
                Order = Order,
                IsEnabled = IsEnabled,
                Settings = Settings == null
                    ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    : new Dictionary<string, string>(Settings, StringComparer.OrdinalIgnoreCase)
            };
        }

        public void Normalize()
        {
            if (string.IsNullOrWhiteSpace(Id))
                Id = Guid.NewGuid().ToString("N");
            WidgetType ??= string.Empty;
            Title ??= string.Empty;
            if (RowSpan <= 0) RowSpan = 1;
            if (ColumnSpan <= 0) ColumnSpan = 1;
            Settings ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (!ReferenceEquals(Settings.Comparer, StringComparer.OrdinalIgnoreCase))
                Settings = new Dictionary<string, string>(Settings, StringComparer.OrdinalIgnoreCase);
        }
    }

    public sealed class StatisticWidgetConfig
    {
        public string MetricKey { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string TimeWindow { get; set; } = "15m";
        public string DisplayMode { get; set; } = "card";
        public bool ShowTrend { get; set; } = true;

        public StatisticWidgetConfig Clone()
        {
            return new StatisticWidgetConfig
            {
                MetricKey = MetricKey ?? string.Empty,
                Title = Title ?? string.Empty,
                TimeWindow = string.IsNullOrWhiteSpace(TimeWindow) ? "15m" : TimeWindow,
                DisplayMode = string.IsNullOrWhiteSpace(DisplayMode) ? "card" : DisplayMode,
                ShowTrend = ShowTrend
            };
        }
    }
}
