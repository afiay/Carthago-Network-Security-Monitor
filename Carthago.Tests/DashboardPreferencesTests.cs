using Carthago.Analytics.Models;
using Carthago.Models;
using Carthago.Services;
using Carthago.Tests.TestInfrastructure;

namespace Carthago.Tests;

public sealed class DashboardPreferencesTests
{
    [Fact]
    public void DashboardPreferences_Default_Is_Minimal_And_Empty()
    {
        var prefs = new DashboardPreferences();

        Assert.True(prefs.UseMinimalDashboard);
        Assert.True(prefs.ShowEmptyDashboardByDefault);
        Assert.Empty(prefs.Widgets);
        Assert.False(prefs.ShowIncidentsSection);
        Assert.False(prefs.ShowStatisticsSection);
    }

    [Fact]
    public void DashboardPreferences_OldPreferences_Load_Safely()
    {
        using var isolation = new PreferencesIsolation();

        PreferencesService.Update(prefs =>
        {
            prefs.Dashboard = null!;
            prefs.EnableWebhook = true;
        });

        PreferencesService.Load();
        var current = PreferencesService.Current;

        Assert.NotNull(current.Dashboard);
        Assert.True(current.Dashboard.UseMinimalDashboard);
        Assert.Empty(current.Dashboard.Widgets);
        Assert.True(current.EnableWebhook);
    }

    [Fact]
    public void DashboardPreset_Applies_Widgets()
    {
        var prefs = DashboardPresetService.ApplyPreset(DashboardPresetService.MinimalSecurityOverview, demoModeEnabled: false);

        Assert.True(prefs.ShowIncidentsSection);
        Assert.True(prefs.ShowAnomaliesSection);
        Assert.True(prefs.ShowStatisticsSection);
        Assert.Contains(prefs.Widgets, widget => widget.WidgetType == DashboardWidgetTypes.IncidentSummary);
        Assert.Contains(prefs.Widgets, widget => widget.WidgetType == DashboardWidgetTypes.StatisticsCard);
    }

    [Fact]
    public void StatisticsMetricRegistry_Returns_Known_Metrics()
    {
        Assert.NotNull(StatisticsMetricRegistry.Find("ActiveIncidents"));
        Assert.NotNull(StatisticsMetricRegistry.Find("HighestRiskHost"));
        Assert.NotNull(StatisticsMetricRegistry.Find("DemoIncidentCount"));
    }

    [Fact]
    public void StatisticsMetric_Calculation_Does_Not_Crash_On_Empty_Data()
    {
        var value = StatisticsMetricRegistry.Resolve("ActiveIncidents", new StatisticsMetricContext());

        Assert.Equal("0", value.Value);
        Assert.False(string.IsNullOrWhiteSpace(value.Detail));
    }

    [Fact]
    public void DashboardLayout_Reorder_Persists()
    {
        using var isolation = new PreferencesIsolation();

        PreferencesService.Update(prefs =>
        {
            prefs.Dashboard = new DashboardPreferences
            {
                ShowStatisticsSection = true,
                Widgets = new List<DashboardWidgetConfig>
                {
                    new() { Id = "a", WidgetType = DashboardWidgetTypes.StatisticsCard, Order = 1, Settings = { ["MetricKey"] = "ActiveIncidents" } },
                    new() { Id = "b", WidgetType = DashboardWidgetTypes.StatisticsCard, Order = 0, Settings = { ["MetricKey"] = "CriticalIncidents" } }
                }
            };
        });

        PreferencesService.Load();
        var ordered = PreferencesService.Current.Dashboard.Widgets.OrderBy(widget => widget.Order).Select(widget => widget.Id).ToArray();

        Assert.Equal(new[] { "b", "a" }, ordered);
    }

    [Fact]
    public void DemoWidget_Hidden_When_DemoMode_Disabled()
    {
        var prefs = DashboardPresetService.ApplyPreset(DashboardPresetService.DemoView, demoModeEnabled: false);

        Assert.DoesNotContain(prefs.Widgets, widget => widget.WidgetType == DashboardWidgetTypes.DemoControls);
    }

    [Fact]
    public void RawViews_Remain_Accessible_When_Dashboard_Minimal()
    {
        var prefs = new DashboardPreferences();
        var rawShortcut = DashboardWidgetRegistry.Find(DashboardWidgetTypes.RawForensicsShortcuts);

        Assert.NotNull(rawShortcut);
        Assert.True(rawShortcut!.IsAdvanced);
        Assert.False(DashboardWidgetRegistry.IsAvailable(DashboardWidgetTypes.RawForensicsShortcuts, prefs, demoModeEnabled: false));
    }

    [Fact]
    public void StatisticsMetric_Uses_Existing_Incident_Data()
    {
        var context = new StatisticsMetricContext
        {
            Incidents = new[]
            {
                new Incident { Id = "1", Status = "New", Severity = "Critical", RiskScore = 95, PrimarySourceIp = "192.168.1.44", Title = "Compromised laptop" },
                new Incident { Id = "2", Status = "Resolved", Severity = "High", RiskScore = 70 }
            }
        };

        var active = StatisticsMetricRegistry.Resolve("ActiveIncidents", context);
        var host = StatisticsMetricRegistry.Resolve("HighestRiskHost", context);

        Assert.Equal("1", active.Value);
        Assert.Equal("192.168.1.44", host.Value);
    }


    [Fact]
    public void DashboardLayoutService_Moves_Widget_Order_Safely()
    {
        var prefs = new DashboardPreferences
        {
            Widgets = new List<DashboardWidgetConfig>
            {
                new() { Id = "a", WidgetType = DashboardWidgetTypes.StatisticsCard, Order = 0 },
                new() { Id = "b", WidgetType = DashboardWidgetTypes.StatisticsCard, Order = 1 },
                new() { Id = "c", WidgetType = DashboardWidgetTypes.StatisticsCard, Order = 2 }
            }
        };

        Assert.True(DashboardLayoutService.MoveWidget(prefs, "c", -2));

        Assert.Equal(new[] { "c", "a", "b" }, prefs.Widgets.OrderBy(widget => widget.Order).Select(widget => widget.Id).ToArray());
    }

    [Fact]
    public void StatisticsMetric_Respects_Selected_Time_Window()
    {
        var now = DateTime.UtcNow;
        var context = new StatisticsMetricContext
        {
            NowUtc = now,
            Anomalies = new[]
            {
                new AnomalySignal { CreatedUtc = now.AddMinutes(-10), SourceIp = "192.168.1.44" },
                new AnomalySignal { CreatedUtc = now.AddMinutes(-50), SourceIp = "192.168.1.45" },
                new AnomalySignal { CreatedUtc = now.AddHours(-2), SourceIp = "192.168.1.46" }
            }
        };

        var last15 = StatisticsMetricRegistry.Resolve("NewAnomalies", context, "15m");
        var last1h = StatisticsMetricRegistry.Resolve("NewAnomalies", context, "1h");

        Assert.Equal("1", last15.Value);
        Assert.Equal("2", last1h.Value);
    }



    [Fact]
    public void WidgetPicker_Shows_Normal_Widgets_Before_Sections_Are_Enabled()
    {
        var prefs = new DashboardPreferences();

        var picker = DashboardWidgetRegistry.GetPickerOptions(demoModeEnabled: false).ToArray();

        Assert.Contains(picker, widget => widget.WidgetType == DashboardWidgetTypes.IncidentQueue);
        Assert.Contains(picker, widget => widget.WidgetType == DashboardWidgetTypes.StatisticsCard);
        Assert.DoesNotContain(picker, widget => widget.WidgetType == DashboardWidgetTypes.DemoControls);
        Assert.False(DashboardWidgetRegistry.IsAvailable(DashboardWidgetTypes.IncidentQueue, prefs, demoModeEnabled: false));
    }

}
