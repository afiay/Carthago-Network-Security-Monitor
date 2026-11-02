// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED.
using System;
using System.Data;
using System.Linq;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using Carthago.Services.SessionFiles;
using Microsoft.Win32;

namespace Carthago;

/// <summary>Offline read-only display; never feeds archived records to live producers.</summary>
public sealed class CarthagoSessionViewerWindow : Window
{
    private readonly CarthagoSessionSnapshot _snapshot;
    private readonly TabControl _tabs = new();

    public CarthagoSessionViewerWindow(CarthagoSessionSnapshot snapshot)
    {
        _snapshot = snapshot ?? throw new ArgumentNullException(nameof(snapshot));
        Width = 1180;
        Height = 740;
        MinWidth = 650;
        MinHeight = 420;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        var layout = new DockPanel { Margin = new Thickness(14) };
        var header = new StackPanel { Margin = new Thickness(0, 0, 0, 10) };
        header.Children.Add(new TextBlock
        {
            Text = $"Saved analysis — {_snapshot.CreatedUtc:yyyy-MM-dd HH:mm:ss} UTC",
            FontSize = 19,
            FontWeight = FontWeights.SemiBold
        });
        header.Children.Add(new TextBlock
        {
            Text = "Read-only archive. These records are not imported into live monitoring or verified as new sensor evidence.",
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 4, 0, 0)
        });
        header.Children.Add(new TextBlock
        {
            Text = "Coverage: " + string.Join("  •  ", _snapshot.Limitations),
            TextWrapping = TextWrapping.Wrap,
            Opacity = 0.8,
            Margin = new Thickness(0, 5, 0, 0)
        });
        var exportButton = new Button
        {
            Content = "Export this session to Excel...",
            HorizontalAlignment = HorizontalAlignment.Left,
            Margin = new Thickness(0, 9, 0, 0),
            Padding = new Thickness(12, 5, 12, 5)
        };
        exportButton.Click += ExportOpenedSessionToExcel_Click;
        header.Children.Add(exportButton);
        DockPanel.SetDock(header, Dock.Top);
        layout.Children.Add(header);

        foreach (string category in CarthagoSessionSnapshot.CategoryOrder)
        {
            _snapshot.Categories.TryGetValue(category, out var records);
            _tabs.Items.Add(new TabItem
            {
                Header = $"{category} ({records?.Count ?? 0})",
                Tag = category
            });
        }
        _tabs.SelectionChanged += (_, __) => LoadSelectedCategory();
        layout.Children.Add(_tabs);
        Content = layout;
        _tabs.SelectedIndex = 0;
    }

    private async void ExportOpenedSessionToExcel_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = "Export opened Carthago session",
            Filter = "Excel workbook (*.xlsx)|*.xlsx",
            AddExtension = true,
            DefaultExt = ".xlsx",
            FileName = $"carthago-session-{_snapshot.CreatedUtc:yyyyMMdd-HHmmss}.xlsx"
        };
        if (dialog.ShowDialog(this) != true) return;
        var exportButton = sender as Button;
        if (exportButton != null) exportButton.IsEnabled = false;
        try
        {
            await new CarthagoExcelExportService().ExportAsync(dialog.FileName, _snapshot);
            MessageBox.Show(this, "Saved the opened session as an Excel workbook.", "Carthago", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, $"Excel export failed: {exception.Message}", "Carthago", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally { if (exportButton != null) exportButton.IsEnabled = true; }
    }

    private void LoadSelectedCategory()
    {
        if (_tabs.SelectedItem is not TabItem tab || tab.Content is not null || tab.Tag is not string category)
            return;
        _snapshot.Categories.TryGetValue(category, out var records);
        var table = new DataTable(category) { Locale = System.Globalization.CultureInfo.InvariantCulture };
        var columns = (records ?? new()).SelectMany(CarthagoExcelExportService.GetColumnNames)
            .Distinct(StringComparer.Ordinal).ToList();
        if (columns.Count == 0) columns.Add("Status");
        foreach (string column in columns) table.Columns.Add(column, typeof(string));
        foreach (JsonElement record in records ?? new())
        {
            DataRow row = table.NewRow();
            foreach (string column in columns)
                row[column] = CarthagoExcelExportService.GetCellValue(record, column);
            table.Rows.Add(row);
        }
        tab.Content = new DataGrid
        {
            IsReadOnly = true,
            AutoGenerateColumns = true,
            CanUserAddRows = false,
            CanUserDeleteRows = false,
            EnableRowVirtualization = true,
            EnableColumnVirtualization = true,
            SelectionMode = DataGridSelectionMode.Extended,
            ItemsSource = table.DefaultView
        };
    }
}
