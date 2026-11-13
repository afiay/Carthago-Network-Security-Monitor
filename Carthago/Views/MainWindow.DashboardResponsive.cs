using System.Windows;
using System.Windows.Controls;
using Carthago.Views;

namespace Carthago;

public partial class MainWindow
{
    partial void ApplyDashboardResponsiveLayout(ResponsiveLayoutMode mode, bool narrowKpis)
    {
        // GA UI-180: the investigation lane is narrow even in Wide mode.
        DashboardDetailFactsGrid.Columns = 2;
        DashboardDetailDestinationCard.Margin = new Thickness(0, 0, 0, 6);
        DashboardDetailProtocolCard.Margin = new Thickness(0, 0, 6, 6);
        DashboardDetailCategoryCard.Margin = new Thickness(0, 0, 0, 6);
        DashboardEvidenceSecondaryColumn.Width = new GridLength(0);
        DashboardEvidencePrimaryColumn.Width = new GridLength(1, GridUnitType.Star);
        for (var evidenceIndex = 0; evidenceIndex < 5; evidenceIndex++)
        {
            FrameworkElement card = evidenceIndex switch
            {
                0 => DashboardEvidenceCard0,
                1 => DashboardEvidenceCard1,
                2 => DashboardEvidenceCard2,
                3 => DashboardEvidenceCard3,
                _ => DashboardEvidenceCard4
            };
            Grid.SetRow(card, evidenceIndex);
            Grid.SetColumn(card, 0);
            Grid.SetColumnSpan(card, 1);
            card.Margin = new Thickness(0, 0, 0, 8);
        }

        // GA UI-159: wide side-by-side filter lanes, stacked at narrower widths.
        DashboardLiveFilterCardsGrid.Columns = mode == ResponsiveLayoutMode.Wide ? 2 : 1;
        DashboardLiveClassificationCard.Margin = mode == ResponsiveLayoutMode.Wide
            ? new Thickness(0, 0, 8, 0) : new Thickness(0, 0, 0, 8);
        DashboardLiveMetadataCard.Margin = mode == ResponsiveLayoutMode.Wide
            ? new Thickness(8, 0, 0, 0) : new Thickness(0);

        // GA UI-177: compact masthead with a separate operational navigation rail.
        var heroWide = mode == ResponsiveLayoutMode.Wide;
        Grid.SetRow(DashboardHeroStatusCard, heroWide ? 0 : 1);
        Grid.SetColumn(DashboardHeroStatusCard, heroWide ? 1 : 0);
        Grid.SetColumnSpan(DashboardHeroStatusCard, heroWide ? 1 : 2);
        DashboardHeroStatusCard.HorizontalAlignment = heroWide
            ? HorizontalAlignment.Right : HorizontalAlignment.Stretch;
        DashboardHeroStatusCard.Margin = heroWide
            ? new Thickness(12, 0, 0, 0) : new Thickness(0, 10, 0, 0);
        var heroNavStack = mode == ResponsiveLayoutMode.Compact || narrowKpis;
        DashboardHeroNavigationGrid.Columns = heroNavStack ? 1 : 3;
        for (var i = 0; i < DashboardHeroNavigationGrid.Children.Count; i++)
        {
            if (DashboardHeroNavigationGrid.Children[i] is FrameworkElement action)
                action.Margin = i == DashboardHeroNavigationGrid.Children.Count - 1
                    ? new Thickness(0)
                    : heroNavStack ? new Thickness(0, 0, 0, 6) : new Thickness(0, 0, 8, 0);
        }

        // GA UI-183: one shared workspace, with independent staggered Wide lanes.
        var wideFocus = mode == ResponsiveLayoutMode.Wide;
        var compactFocus = mode == ResponsiveLayoutMode.Compact;
        var rows = DashboardOperationsWorkspace.RowDefinitions;
        var columns = DashboardOperationsWorkspace.ColumnDefinitions;
        columns[0].Width = new GridLength(wideFocus ? 2.15 : compactFocus ? 1 : 1.4, GridUnitType.Star);
        columns[1].Width = compactFocus ? new GridLength(0) : new GridLength(wideFocus ? 1.05 : 1.6, GridUnitType.Star);
        columns[2].Width = wideFocus ? new GridLength(1.2, GridUnitType.Star) : new GridLength(0);
        rows[0].Height = wideFocus ? new GridLength(420) : GridLength.Auto;
        rows[1].Height = new GridLength(wideFocus ? 180 : compactFocus ? 600 : 660);
        rows[2].Height = compactFocus ? new GridLength(660) : GridLength.Auto;
        rows[3].Height = wideFocus ? new GridLength(0) : GridLength.Auto;
        rows[4].Height = compactFocus ? GridLength.Auto : new GridLength(0);
        TrafficPlot.Height = wideFocus ? double.NaN : 300;
        PlaceDashboardPanel(DashboardTrafficChartPanel, 0, 0, 1, wideFocus || compactFocus ? 1 : 2,
            wideFocus ? new Thickness(0,0,12,12) : new Thickness(0,0,0,12));
        PlaceDashboardPanel(DashboardTimelinePanel, wideFocus ? 0 : 1, wideFocus ? 1 : 0, 1, 1,
            wideFocus || !compactFocus ? new Thickness(0,0,12,12) : new Thickness(0,0,0,12));
        PlaceDashboardPanel(DashboardSignalPanel, wideFocus ? 0 : compactFocus ? 2 : 1,
            wideFocus ? 2 : compactFocus ? 0 : 1, wideFocus ? 2 : 1, 1, new Thickness(0,0,0,12));
        PlaceDashboardPanel(DashboardLiveEventsPanel, wideFocus ? 1 : compactFocus ? 3 : 2, 0,
            wideFocus ? 2 : 1, compactFocus ? 1 : 2,
            wideFocus ? new Thickness(0,0,12,0) : new Thickness(0,0,0,10));
        PlaceDashboardPanel(DashboardCliCompanionPanel, wideFocus ? 2 : compactFocus ? 4 : 3,
            wideFocus ? 2 : 0, 1, wideFocus || compactFocus ? 1 : 2, new Thickness(0));

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

        var wideLower = wideFocus;
        // GA UI-171: retain the wider severity-first evidence viewport on Wide and Standard;
        // Compact and below-1024 preserve a shorter readable scan surface.
        DashboardLiveEventsGrid.Height = mode == ResponsiveLayoutMode.Wide ? 440 :
            mode == ResponsiveLayoutMode.Standard ? 420 : 400;
        DashboardLiveEventsGrid.RowHeight = mode == ResponsiveLayoutMode.Compact || narrowKpis ? 48 : 44;

        // GA UI-162: keep the terminal as a full evidence companion on Wide, but
        // avoid a second 560-unit visual-only slab beneath the live table when stacked.
        // This is presentation-only: the CLI remains unavailable in every mode.
        DashboardCliCompanionPanel.MinHeight = wideLower ? 260 : 260;
        DashboardCliCapabilityRow.Height = wideLower
            ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
        DashboardCliCapabilityPanel.Visibility = wideLower
            ? Visibility.Visible : Visibility.Collapsed;

        if (mode == ResponsiveLayoutMode.Compact)
        {
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

        DashboardSummaryGrid.Height = 264;
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

    private static void PlaceDashboardPanel(FrameworkElement element, int row, int column, int rowSpan, int columnSpan, Thickness margin)
    {
        Grid.SetRow(element, row);
        Grid.SetColumn(element, column);
        Grid.SetRowSpan(element, rowSpan);
        Grid.SetColumnSpan(element, columnSpan);
        element.Margin = margin;
    }

    private static void PositionPanel(FrameworkElement element, int row, int column)
    {
        Grid.SetRow(element, row);
        Grid.SetColumn(element, column);
    }
}
