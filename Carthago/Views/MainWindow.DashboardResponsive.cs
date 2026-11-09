using System.Windows;
using System.Windows.Controls;
using Carthago.Views;

namespace Carthago;

public partial class MainWindow
{
    partial void ApplyDashboardResponsiveLayout(ResponsiveLayoutMode mode, bool narrowKpis)
    {
        // Preserve three fact columns at 1024px and above; allow two below 1024px.
        // This changes presentation only, not the selected incident or its source values.
        DashboardDetailFactsGrid.Columns = narrowKpis ? 2 : 3;

        // GA UI-44: keep gutters aligned when the existing six fact cards wrap to two columns.
        // The three-column margins remain identical to the original design.
        DashboardDetailDestinationCard.Margin = narrowKpis
            ? new Thickness(0, 0, 0, 6)
            : new Thickness(0, 0, 8, 6);
        DashboardDetailProtocolCard.Margin = narrowKpis
            ? new Thickness(0, 0, 8, 6)
            : new Thickness(0, 0, 0, 6);
        DashboardDetailCategoryCard.Margin = narrowKpis
            ? new Thickness(0, 0, 0, 6)
            : new Thickness(0, 0, 8, 0);

        // GA UI-159: wide side-by-side filter lanes, stacked at narrower widths.
        DashboardLiveFilterCardsGrid.Columns = mode == ResponsiveLayoutMode.Wide ? 2 : 1;
        DashboardLiveClassificationCard.Margin = mode == ResponsiveLayoutMode.Wide
            ? new Thickness(0, 0, 8, 0) : new Thickness(0, 0, 0, 8);
        DashboardLiveMetadataCard.Margin = mode == ResponsiveLayoutMode.Wide
            ? new Thickness(8, 0, 0, 0) : new Thickness(0);

        // GA UI-90: hero status flows below the title only when the shell is below 1024px.
        Grid.SetRow(DashboardHeroStatusCard, narrowKpis ? 1 : 0);
        Grid.SetColumn(DashboardHeroStatusCard, narrowKpis ? 0 : 1);
        DashboardHeroStatusCard.HorizontalAlignment = narrowKpis
            ? HorizontalAlignment.Left : HorizontalAlignment.Right;
        DashboardHeroStatusCard.Margin = narrowKpis
            ? new Thickness(0, 14, 0, 0) : new Thickness(12, 0, 0, 0);

        // Wide: chart | prioritized queue | investigation.
        // Standard/Compact: chart above the existing responsive triage grid.
        var wideFocus = mode == ResponsiveLayoutMode.Wide;
        DashboardFocusGrid.Height = wideFocus ? 540 : double.NaN;
        DashboardFocusTrafficColumn.Width = new GridLength(wideFocus ? 2.15 : 1, GridUnitType.Star);
        DashboardFocusTriageColumn.Width = wideFocus
            ? new GridLength(2.25, GridUnitType.Star) : new GridLength(0);
        DashboardFocusPrimaryRow.Height = wideFocus
            ? new GridLength(1, GridUnitType.Star) : GridLength.Auto;
        DashboardFocusSecondaryRow.Height = wideFocus
            ? new GridLength(0) : GridLength.Auto;
        Grid.SetRow(DashboardTrafficChartPanel, 0);
        Grid.SetColumn(DashboardTrafficChartPanel, 0);
        Grid.SetRow(DashboardTriageGrid, wideFocus ? 0 : 1);
        Grid.SetColumn(DashboardTriageGrid, wideFocus ? 1 : 0);
        DashboardTrafficChartPanel.Margin = wideFocus
            ? new Thickness(0, 0, 16, 0) : new Thickness(0, 0, 0, 16);
        DashboardTriageGrid.Margin = new Thickness(0);

        var overviewPanelKey = narrowKpis ? "DashboardOverviewKpiNarrowPanel" : mode switch
        {
            ResponsiveLayoutMode.Compact => "DashboardOverviewKpiCompactPanel",
            ResponsiveLayoutMode.Standard => "DashboardOverviewKpiStandardPanel",
            _ => "DashboardOverviewKpiWidePanel"
        };
        DashboardOverviewKpiItemsControl.ItemsPanel = (ItemsPanelTemplate)FindResource(overviewPanelKey);

        var additionalPanelKey = narrowKpis ? "DashboardKpiNarrowPanel" : mode switch
        {
            ResponsiveLayoutMode.Compact => "DashboardKpiCompactPanel",
            ResponsiveLayoutMode.Standard => "DashboardKpiStandardPanel",
            _ => "DashboardKpiWidePanel"
        };
        DashboardKpiItemsControl.ItemsPanel = (ItemsPanelTemplate)FindResource(additionalPanelKey);

        // Keep the observed PPS chart status readable at the same below-1024 threshold.
        // Reposition only the UI label; the original capture status and plot remain unchanged.
        Grid.SetRow(DashboardTrafficChartCaptureStatus, narrowKpis ? 1 : 0);
        Grid.SetColumn(DashboardTrafficChartCaptureStatus, narrowKpis ? 0 : 1);
        DashboardTrafficChartCaptureStatus.Margin = narrowKpis
            ? new Thickness(0, 6, 0, 0)
            : new Thickness(12, 0, 0, 0);

        // GA UI-91: dock the unavailable CLI beside the local event stream on Wide;
        // stack below the full-width, horizontally scrollable event table otherwise.
        var wideLower = mode == ResponsiveLayoutMode.Wide;
        DashboardLowerEventsColumn.Width = new GridLength(wideLower ? 2.65 : 1, GridUnitType.Star);
        DashboardLowerCliColumn.Width = wideLower
            ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
        DashboardLowerPrimaryRow.Height = GridLength.Auto;
        DashboardLowerSecondaryRow.Height = wideLower ? new GridLength(0) : GridLength.Auto;
        Grid.SetRow(DashboardLiveEventsPanel, 0);
        Grid.SetColumn(DashboardLiveEventsPanel, 0);
        Grid.SetRow(DashboardCliCompanionPanel, wideLower ? 0 : 1);
        Grid.SetColumn(DashboardCliCompanionPanel, wideLower ? 1 : 0);
        DashboardLiveEventsPanel.Margin = wideLower
            ? new Thickness(0, 0, 12, 0) : new Thickness(0, 0, 0, 10);
        DashboardCliCompanionPanel.Margin = new Thickness(0);
        DashboardCliCompanionPanel.Width = double.NaN;
        DashboardCliCompanionPanel.HorizontalAlignment = HorizontalAlignment.Stretch;

        if (mode == ResponsiveLayoutMode.Compact)
        {
            DashboardTriageGrid.Height = 1080;
            DashboardTriageTimelineColumn.Width = new GridLength(1, GridUnitType.Star);
            DashboardTriageDetailColumn.Width = new GridLength(0);
            DashboardTriagePrimaryRow.Height = new GridLength(510);
            DashboardTriageSecondaryRow.Height = new GridLength(1, GridUnitType.Star);
            PositionPanel(DashboardTimelinePanel, 0, 0);
            PositionPanel(DashboardSignalPanel, 1, 0);
            DashboardTimelinePanel.Margin = new Thickness(0, 0, 0, 10);
            DashboardSignalPanel.Margin = new Thickness(0);

            DashboardSummaryGrid.Height = 660;
            DashboardSummaryFirstColumn.Width = new GridLength(1, GridUnitType.Star);
            DashboardSummarySecondColumn.Width = new GridLength(0);
            DashboardSummaryThirdColumn.Width = new GridLength(0);
            DashboardSummaryFirstRow.Height = new GridLength(216);
            DashboardSummarySecondRow.Height = new GridLength(216);
            DashboardSummaryThirdRow.Height = new GridLength(228);
            PositionPanel(DashboardHostsPanel, 0, 0);
            PositionPanel(DashboardActionsPanel, 1, 0);
            PositionPanel(DashboardOperationsPanel, 2, 0);
            Grid.SetColumnSpan(DashboardHostsPanel, 1);
            Grid.SetColumnSpan(DashboardActionsPanel, 1);
            Grid.SetColumnSpan(DashboardOperationsPanel, 1);
            DashboardHostsPanel.Margin = new Thickness(0, 0, 0, 10);
            DashboardActionsPanel.Margin = new Thickness(0, 0, 0, 10);
            DashboardOperationsPanel.Margin = new Thickness(0);
            return;
        }

        if (mode == ResponsiveLayoutMode.Standard)
        {
            DashboardTriageGrid.Height = 500;
            DashboardTriageTimelineColumn.Width = new GridLength(1.25, GridUnitType.Star);
            DashboardTriageDetailColumn.Width = new GridLength(1.2, GridUnitType.Star);
            DashboardTriagePrimaryRow.Height = new GridLength(1, GridUnitType.Star);
            DashboardTriageSecondaryRow.Height = new GridLength(0);
            PositionPanel(DashboardTimelinePanel, 0, 0);
            PositionPanel(DashboardSignalPanel, 0, 1);
            DashboardTimelinePanel.Margin = new Thickness(0, 0, 16, 0);
            DashboardSignalPanel.Margin = new Thickness(0);

            DashboardSummaryGrid.Height = 450;
            DashboardSummaryFirstColumn.Width = new GridLength(1, GridUnitType.Star);
            DashboardSummarySecondColumn.Width = new GridLength(1, GridUnitType.Star);
            DashboardSummaryThirdColumn.Width = new GridLength(0);
            DashboardSummaryFirstRow.Height = new GridLength(210);
            DashboardSummarySecondRow.Height = new GridLength(240);
            DashboardSummaryThirdRow.Height = new GridLength(0);
            PositionPanel(DashboardHostsPanel, 0, 0);
            PositionPanel(DashboardActionsPanel, 1, 0);
            PositionPanel(DashboardOperationsPanel, 1, 1);
            Grid.SetColumnSpan(DashboardHostsPanel, 2);
            Grid.SetColumnSpan(DashboardActionsPanel, 1);
            Grid.SetColumnSpan(DashboardOperationsPanel, 1);
            DashboardHostsPanel.Margin = new Thickness(0, 0, 0, 10);
            DashboardActionsPanel.Margin = new Thickness(0, 0, 12, 0);
            DashboardOperationsPanel.Margin = new Thickness(0);
            return;
        }

        DashboardTriageGrid.Height = 540;
        DashboardTriageTimelineColumn.Width = new GridLength(1.25, GridUnitType.Star);
        DashboardTriageDetailColumn.Width = new GridLength(1.2, GridUnitType.Star);
        DashboardTriagePrimaryRow.Height = new GridLength(1, GridUnitType.Star);
        DashboardTriageSecondaryRow.Height = new GridLength(0);
        PositionPanel(DashboardTimelinePanel, 0, 0);
        PositionPanel(DashboardSignalPanel, 0, 1);
        DashboardTimelinePanel.Margin = new Thickness(0, 0, 16, 0);
        DashboardSignalPanel.Margin = new Thickness(0);

        DashboardSummaryGrid.Height = 202;
        DashboardSummaryFirstColumn.Width = new GridLength(1.02, GridUnitType.Star);
        DashboardSummarySecondColumn.Width = new GridLength(1, GridUnitType.Star);
        DashboardSummaryThirdColumn.Width = new GridLength(1, GridUnitType.Star);
        DashboardSummaryFirstRow.Height = new GridLength(1, GridUnitType.Star);
        DashboardSummarySecondRow.Height = new GridLength(0);
        DashboardSummaryThirdRow.Height = new GridLength(0);
        PositionPanel(DashboardHostsPanel, 0, 0);
        PositionPanel(DashboardActionsPanel, 0, 1);
        PositionPanel(DashboardOperationsPanel, 0, 2);
        Grid.SetColumnSpan(DashboardHostsPanel, 1);
        Grid.SetColumnSpan(DashboardActionsPanel, 1);
        Grid.SetColumnSpan(DashboardOperationsPanel, 1);
        DashboardHostsPanel.Margin = new Thickness(0, 0, 12, 0);
        DashboardActionsPanel.Margin = new Thickness(0, 0, 12, 0);
        DashboardOperationsPanel.Margin = new Thickness(0);
    }

    private static void PositionPanel(FrameworkElement element, int row, int column)
    {
        Grid.SetRow(element, row);
        Grid.SetColumn(element, column);
    }
}
