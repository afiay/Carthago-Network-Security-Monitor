using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;

namespace Carthago.Views;

public enum ResponsiveLayoutMode
{
    Compact,
    Standard,
    Wide
}

public interface IResponsiveLayoutAware
{
    void ApplyResponsiveLayout(ResponsiveLayoutMode mode);
}

internal static class ResponsiveLayout
{
    internal const double StandardMinWidth = 1100d;
    internal const double WideMinWidth = 1440d;

    internal static ResponsiveLayoutMode Resolve(double width)
    {
        if (double.IsNaN(width) || width < StandardMinWidth)
            return ResponsiveLayoutMode.Compact;

        return width < WideMinWidth
            ? ResponsiveLayoutMode.Standard
            : ResponsiveLayoutMode.Wide;
    }

    internal static double ConstrainDimension(
        double desired,
        double minimum,
        double available,
        double availableUsage = 1d)
    {
        var safeAvailable = double.IsFinite(available) ? Math.Max(0, available) : 0;
        var usage = double.IsFinite(availableUsage) ? Math.Clamp(availableUsage, 0, 1) : 1;
        var maximum = safeAvailable * usage;
        var effectiveMinimum = Math.Min(Math.Max(0, minimum), maximum);
        var requested = double.IsFinite(desired) ? desired : effectiveMinimum;
        return Math.Clamp(requested, effectiveMinimum, maximum);
    }

    internal static void ApplyWhenLoaded(
        FrameworkElement element,
        Action<ResponsiveLayoutMode> apply)
    {
        element.Loaded += (_, _) =>
        {
            var windowWidth = Window.GetWindow(element)?.ActualWidth;
            var availableWidth = windowWidth is > 0 && double.IsFinite(windowWidth.Value)
                ? windowWidth.Value
                : element.ActualWidth;
            apply(Resolve(availableWidth));
        };
    }

    internal static void ApplyAdaptiveColumns(
        ResponsiveLayoutMode mode,
        IReadOnlyList<ColumnDefinition> columns,
        IReadOnlyList<RowDefinition> rows,
        IReadOnlyList<FrameworkElement> panels,
        IReadOnlyList<double> columnWeights,
        double gap)
    {
        var compact = mode == ResponsiveLayoutMode.Compact;

        for (var index = 0; index < columns.Count; index++)
            columns[index].Width = compact
                ? new GridLength(index == 0 ? 1 : 0, index == 0 ? GridUnitType.Star : GridUnitType.Pixel)
                : new GridLength(columnWeights[index], GridUnitType.Star);

        for (var index = 0; index < rows.Count; index++)
            rows[index].Height = compact || index == 0 ? GridLength.Auto : new GridLength(0);

        for (var index = 0; index < panels.Count; index++)
        {
            Grid.SetRow(panels[index], compact ? index : 0);
            Grid.SetColumn(panels[index], compact ? 0 : index);
            panels[index].Margin = compact
                ? new Thickness(0, 0, 0, index == panels.Count - 1 ? 0 : gap)
                : new Thickness(0, 0, index == panels.Count - 1 ? 0 : gap, 0);
        }
    }
}
