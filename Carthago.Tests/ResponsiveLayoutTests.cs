using Carthago.Views;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Windows;
using System.Windows.Controls;

namespace Carthago.Tests;

public sealed class ResponsiveLayoutTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1024)]
    [InlineData(1099.99)]
    public void Resolve_UsesCompactModeBelowStandardBreakpoint(double width)
    {
        Assert.Equal(ResponsiveLayoutMode.Compact, ResponsiveLayout.Resolve(width));
    }

    [Theory]
    [InlineData(1100)]
    [InlineData(1280)]
    [InlineData(1439.99)]
    public void Resolve_UsesStandardModeBelowWideBreakpoint(double width)
    {
        Assert.Equal(ResponsiveLayoutMode.Standard, ResponsiveLayout.Resolve(width));
    }

    [Theory]
    [InlineData(1440)]
    [InlineData(1920)]
    public void Resolve_UsesWideModeAtOrAboveWideBreakpoint(double width)
    {
        Assert.Equal(ResponsiveLayoutMode.Wide, ResponsiveLayout.Resolve(width));
    }

    [Fact]
    public void Resolve_UsesCompactModeForUnavailableWidth()
    {
        Assert.Equal(ResponsiveLayoutMode.Compact, ResponsiveLayout.Resolve(double.NaN));
    }

    [Theory]
    [InlineData(1440, 640, 683, 1.0, 683)]
    [InlineData(900, 520, 600, 0.94, 564)]
    [InlineData(900, 520, 500, 0.94, 470)]
    public void ConstrainDimension_FitsAvailableWorkArea(
        double desired,
        double minimum,
        double available,
        double usage,
        double expected)
    {
        Assert.Equal(
            expected,
            ResponsiveLayout.ConstrainDimension(desired, minimum, available, usage),
            precision: 3);
    }

    [Fact]
    public void ApplyWhenLoaded_UsesRenderedElementWidthWithoutAWindow()
    {
        RunInSta(() =>
        {
            var element = new Border();
            element.Measure(new Size(1280, 200));
            element.Arrange(new Rect(0, 0, 1280, 200));
            ResponsiveLayoutMode? appliedMode = null;

            ResponsiveLayout.ApplyWhenLoaded(element, mode => appliedMode = mode);
            element.RaiseEvent(new RoutedEventArgs(FrameworkElement.LoadedEvent));

            Assert.Equal(ResponsiveLayoutMode.Standard, appliedMode);
        });
    }

    [Fact]
    public void ApplyAdaptiveColumns_StacksPanelsInCompactMode()
    {
        RunInSta(() =>
        {
            var columns = new[] { new ColumnDefinition(), new ColumnDefinition() };
            var rows = new[] { new RowDefinition(), new RowDefinition() };
            var first = new Border();
            var second = new Border();

            ResponsiveLayout.ApplyAdaptiveColumns(
                ResponsiveLayoutMode.Compact,
                columns,
                rows,
                new FrameworkElement[] { first, second },
                new[] { 0.4, 0.6 },
                14);

            Assert.Equal(new GridLength(1, GridUnitType.Star), columns[0].Width);
            Assert.Equal(new GridLength(0), columns[1].Width);
            Assert.Equal(GridLength.Auto, rows[0].Height);
            Assert.Equal(GridLength.Auto, rows[1].Height);
            Assert.Equal(0, Grid.GetRow(first));
            Assert.Equal(1, Grid.GetRow(second));
            Assert.Equal(new Thickness(0, 0, 0, 14), first.Margin);
            Assert.Equal(new Thickness(0), second.Margin);
        });
    }

    [Fact]
    public void ApplyAdaptiveColumns_RestoresWeightedColumnsOutsideCompactMode()
    {
        RunInSta(() =>
        {
            var columns = new[] { new ColumnDefinition(), new ColumnDefinition(), new ColumnDefinition() };
            var rows = new[] { new RowDefinition(), new RowDefinition(), new RowDefinition() };
            var panels = new FrameworkElement[] { new Border(), new Border(), new Border() };

            ResponsiveLayout.ApplyAdaptiveColumns(
                ResponsiveLayoutMode.Standard,
                columns,
                rows,
                panels,
                new[] { 1.0, 1.0, 1.2 },
                10);

            Assert.Equal(new GridLength(1.0, GridUnitType.Star), columns[0].Width);
            Assert.Equal(new GridLength(1.0, GridUnitType.Star), columns[1].Width);
            Assert.Equal(new GridLength(1.2, GridUnitType.Star), columns[2].Width);
            Assert.Equal(GridLength.Auto, rows[0].Height);
            Assert.Equal(new GridLength(0), rows[1].Height);
            Assert.Equal(new GridLength(0), rows[2].Height);
            Assert.All(panels, panel => Assert.Equal(0, Grid.GetRow(panel)));
            Assert.Equal(2, Grid.GetColumn(panels[2]));
            Assert.Equal(new Thickness(0), panels[2].Margin);
        });
    }

    private static void RunInSta(Action assertion)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                assertion();
            }
            catch (Exception exception)
            {
                failure = exception;
            }
        });

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        if (failure is not null)
            ExceptionDispatchInfo.Capture(failure).Throw();
    }
}
