using System;
using System.Windows;
using System.Windows.Controls;
using Carthago.Views;

namespace Carthago;

public partial class MainWindow
{
    private ResponsiveLayoutMode? _responsiveLayoutMode;

    partial void ApplyDashboardResponsiveLayout(ResponsiveLayoutMode mode);

    private void InitializeResponsiveLayout()
    {
        SourceInitialized += (_, _) => ConstrainInitialSizeToWorkArea();
        Loaded += (_, _) => ApplyResponsiveLayout(force: true);
        SizeChanged += (_, _) => ApplyResponsiveLayout();
        ApplyResponsiveLayout(force: true);
    }

    private void ConstrainInitialSizeToWorkArea()
    {
        var workArea = SystemParameters.WorkArea;
        MinWidth = Math.Min(MinWidth, workArea.Width);
        MinHeight = Math.Min(MinHeight, workArea.Height);
        Width = ResponsiveLayout.ConstrainDimension(Width, MinWidth, workArea.Width);
        Height = ResponsiveLayout.ConstrainDimension(Height, MinHeight, workArea.Height);
    }

    private void ApplyResponsiveLayout(bool force = false)
    {
        var availableWidth = ActualWidth > 0 && double.IsFinite(ActualWidth) ? ActualWidth : Width;
        var mode = ResponsiveLayout.Resolve(availableWidth);

        if (!force && _responsiveLayoutMode == mode)
            return;

        _responsiveLayoutMode = mode;
        ApplyShellLayout(mode);
        ApplyDashboardResponsiveLayout(mode);
        ApplyResponsiveLayoutTo(AnomaliesFrame.Content);
        ApplyResponsiveLayoutTo(IncidentsFrame.Content);
        ApplyResponsiveLayoutTo(ThreatFeedFrame.Content);
        ApplyResponsiveLayoutTo(SinkEventsFrame.Content);
        ApplyResponsiveLayoutTo(HostIntegrityFrame.Content);
        ApplyResponsiveLayoutTo(IntegrationsFrame.Content);
        ApplyResponsiveLayoutTo(CiscoToolsPanel);
    }

    private void ApplyShellLayout(ResponsiveLayoutMode mode)
    {
        var compact = mode == ResponsiveLayoutMode.Compact;
        SidebarColumn.Width = new GridLength(mode switch
        {
            ResponsiveLayoutMode.Compact => 60,
            ResponsiveLayoutMode.Standard => 200,
            _ => 216
        });
        SidebarPanel.IsCompact = compact;
        MainContentHost.Margin = mode switch
        {
            ResponsiveLayoutMode.Compact => (Thickness)FindResource("PagePaddingCompact"),
            ResponsiveLayoutMode.Standard => (Thickness)FindResource("PagePaddingStandard"),
            _ => (Thickness)FindResource("PagePaddingWide")
        };

        if (mode == ResponsiveLayoutMode.Wide)
        {
            CommandHeaderStatusColumn.Width = new GridLength(250);
            CommandHeaderSourceColumn.Width = new GridLength(290);
            CommandHeaderAnalysisColumn.Width = new GridLength(210);
            CommandHeaderActionsColumn.Width = new GridLength(1, GridUnitType.Star);
            CommandHeaderSecondaryRow.Height = new GridLength(0);
            CommandHeaderTertiaryRow.Height = new GridLength(0);
            CommandHeaderQuaternaryRow.Height = new GridLength(0);

            PositionHeaderGroup(CommandHeaderStatusGroup, 0, 0);
            PositionHeaderGroup(CommandHeaderSourceGroup, 0, 1);
            PositionHeaderGroup(CommandHeaderAnalysisGroup, 0, 2);
            PositionHeaderGroup(CommandHeaderActionsGroup, 0, 3);

            CommandHeaderStatusGroup.Margin = new Thickness(0, 0, 12, 0);
            CommandHeaderSourceGroup.Margin = new Thickness(0, 0, 12, 0);
            CommandHeaderAnalysisGroup.Margin = new Thickness(0, 0, 12, 0);
            CommandHeaderStatusGroup.BorderThickness = new Thickness(0, 0, 1, 0);
            CommandHeaderSourceGroup.BorderThickness = new Thickness(0, 0, 1, 0);
            CommandHeaderAnalysisGroup.BorderThickness = new Thickness(0, 0, 1, 0);
            CommandHeader.MinHeight = 92;
            CommandHeader.Padding = new Thickness(12, 12, 12, 10);
            CommandHeaderActionsGroup.HorizontalAlignment = HorizontalAlignment.Right;
            return;
        }

        if (compact)
        {
            CommandHeaderStatusColumn.Width = new GridLength(1, GridUnitType.Star);
            CommandHeaderSourceColumn.Width = new GridLength(0);
            CommandHeaderAnalysisColumn.Width = new GridLength(0);
            CommandHeaderActionsColumn.Width = new GridLength(0);
            CommandHeaderSecondaryRow.Height = GridLength.Auto;
            CommandHeaderTertiaryRow.Height = GridLength.Auto;
            CommandHeaderQuaternaryRow.Height = GridLength.Auto;

            PositionHeaderGroup(CommandHeaderStatusGroup, 0, 0);
            PositionHeaderGroup(CommandHeaderActionsGroup, 1, 0);
            PositionHeaderGroup(CommandHeaderSourceGroup, 2, 0);
            PositionHeaderGroup(CommandHeaderAnalysisGroup, 3, 0);

            CommandHeaderStatusGroup.Margin = new Thickness(0, 0, 0, 8);
            CommandHeaderActionsGroup.Margin = new Thickness(0, 0, 0, 8);
            CommandHeaderSourceGroup.Margin = new Thickness(0, 0, 0, 8);
            CommandHeaderAnalysisGroup.Margin = new Thickness(0);
            CommandHeaderStatusGroup.BorderThickness = new Thickness(0, 0, 0, 1);
            CommandHeaderSourceGroup.BorderThickness = new Thickness(0, 0, 0, 1);
            CommandHeaderAnalysisGroup.BorderThickness = new Thickness(0);
            CommandHeader.MinHeight = 0;
            CommandHeader.Padding = new Thickness(8);
            CommandHeaderActionsGroup.HorizontalAlignment = HorizontalAlignment.Left;
            return;
        }

        CommandHeaderStatusColumn.Width = new GridLength(1, GridUnitType.Star);
        CommandHeaderSourceColumn.Width = new GridLength(1, GridUnitType.Star);
        CommandHeaderAnalysisColumn.Width = new GridLength(0);
        CommandHeaderActionsColumn.Width = new GridLength(0);
        CommandHeaderSecondaryRow.Height = GridLength.Auto;
        CommandHeaderTertiaryRow.Height = new GridLength(0);
        CommandHeaderQuaternaryRow.Height = new GridLength(0);

        PositionHeaderGroup(CommandHeaderStatusGroup, 0, 0);
        PositionHeaderGroup(CommandHeaderActionsGroup, 0, 1);
        PositionHeaderGroup(CommandHeaderSourceGroup, 1, 0);
        PositionHeaderGroup(CommandHeaderAnalysisGroup, 1, 1);

        CommandHeaderStatusGroup.Margin = new Thickness(0, 0, 10, 8);
        CommandHeaderActionsGroup.Margin = new Thickness(0, 0, 0, 8);
        CommandHeaderSourceGroup.Margin = new Thickness(0, 0, 10, 0);
        CommandHeaderAnalysisGroup.Margin = new Thickness(0);
        CommandHeaderStatusGroup.BorderThickness = new Thickness(0, 0, 1, 0);
        CommandHeaderSourceGroup.BorderThickness = new Thickness(0, 1, 1, 0);
        CommandHeaderAnalysisGroup.BorderThickness = new Thickness(0, 1, 0, 0);
        CommandHeader.MinHeight = 0;
        CommandHeader.Padding = compact ? new Thickness(10) : new Thickness(12, 12, 12, 10);
        CommandHeaderActionsGroup.HorizontalAlignment = HorizontalAlignment.Right;
    }

    private void ApplyResponsiveLayoutTo(object? content)
    {
        if (content is not FrameworkElement element)
            return;

        if (_responsiveLayoutMode is { } mode && element is IResponsiveLayoutAware responsive)
            responsive.ApplyResponsiveLayout(mode);

        if (!element.IsLoaded)
        {
            element.Loaded -= ResponsiveContent_Loaded;
            element.Loaded += ResponsiveContent_Loaded;
        }
    }

    private void ResponsiveContent_Loaded(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement element)
            return;

        element.Loaded -= ResponsiveContent_Loaded;
        if (_responsiveLayoutMode is { } mode && element is IResponsiveLayoutAware responsive)
            responsive.ApplyResponsiveLayout(mode);
    }

    private static void PositionHeaderGroup(FrameworkElement element, int row, int column)
    {
        Grid.SetRow(element, row);
        Grid.SetColumn(element, column);
        Grid.SetColumnSpan(element, 1);
    }
}
