using System.Windows;
using System.Windows.Controls;
using Carthago.Views;

namespace Carthago;

public partial class MainWindow
{
    partial void ApplyDashboardResponsiveLayout(ResponsiveLayoutMode mode)
    {
        DashboardKpiItemsControl.ItemsPanel = (ItemsPanelTemplate)FindResource(mode switch
        {
            ResponsiveLayoutMode.Compact => "DashboardKpiCompactPanel",
            ResponsiveLayoutMode.Standard => "DashboardKpiStandardPanel",
            _ => "DashboardKpiWidePanel"
        });

        if (mode == ResponsiveLayoutMode.Compact)
        {
            DashboardTriageGrid.Height = 840;
            DashboardTriageTimelineColumn.Width = new GridLength(1, GridUnitType.Star);
            DashboardTriageDetailColumn.Width = new GridLength(0);
            DashboardTriagePrimaryRow.Height = new GridLength(350);
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
            DashboardTriageGrid.Height = 440;
            DashboardTriageTimelineColumn.Width = new GridLength(1.05, GridUnitType.Star);
            DashboardTriageDetailColumn.Width = new GridLength(1.65, GridUnitType.Star);
            DashboardTriagePrimaryRow.Height = new GridLength(1, GridUnitType.Star);
            DashboardTriageSecondaryRow.Height = new GridLength(0);
            PositionPanel(DashboardTimelinePanel, 0, 0);
            PositionPanel(DashboardSignalPanel, 0, 1);
            DashboardTimelinePanel.Margin = new Thickness(0, 0, 12, 0);
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

        DashboardTriageGrid.Height = 404;
        DashboardTriageTimelineColumn.Width = new GridLength(1.05, GridUnitType.Star);
        DashboardTriageDetailColumn.Width = new GridLength(1.65, GridUnitType.Star);
        DashboardTriagePrimaryRow.Height = new GridLength(1, GridUnitType.Star);
        DashboardTriageSecondaryRow.Height = new GridLength(0);
        PositionPanel(DashboardTimelinePanel, 0, 0);
        PositionPanel(DashboardSignalPanel, 0, 1);
        DashboardTimelinePanel.Margin = new Thickness(0, 0, 12, 0);
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
