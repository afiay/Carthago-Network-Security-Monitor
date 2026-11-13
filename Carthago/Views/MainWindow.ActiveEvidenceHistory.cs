// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Carthago.Services.Sensors;

namespace Carthago;

public partial class MainWindow
{
    private static CheckBox AddActiveEvidenceOptIn(DockPanel panel)
    {
        var save = new CheckBox { Content = "Save completed observation to local active history (30 days)",
            IsChecked = false, Margin = new Thickness(0, 0, 0, 10) };
        DockPanel.SetDock(save, Dock.Bottom);
        panel.Children.Add(save);
        return save;
    }

    // Keep storage failures distinct from probe outcomes, and never save a cancelled probe.
    private static async Task<string> SaveActiveEvidenceAsync(Func<ActiveEvidenceRow> project)
    {
        try
        {
            bool saved = await Task.Run(() => new ActiveEvidenceStore().Save(project()));
            return saved ? "\n\nActive history: saved." : "\n\nActive history: not saved (storage or retention failure).";
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        { return "\n\nActive history: not saved (invalid observation)."; }
    }

    private sealed record ActiveHistoryChoice(Guid Id, string Label);

    private void OpenActiveEvidenceHistory_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Window { Owner = this, Title = "Active sensor history", Width = 820, Height = 580,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, ShowInTaskbar = false };
        var panel = new DockPanel { Margin = new Thickness(16) };
        var filters = new StackPanel();
        filters.Children.Add(new TextBlock { Text = "Active probe observations only. Last 30 days / 5,000 retained; up to 200 results. " +
            "Not authenticated baselines or detection events. HTTP values and SNMP text are hashed.",
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 10) });
        var line = new StackPanel { Orientation = Orientation.Horizontal };
        var sensor = new ComboBox { Width = 130, ItemsSource = new[] { "All" }.Concat(Enum.GetNames<ActiveSensorKind>()), SelectedIndex = 0 };
        var target = new TextBox { Width = 180, Margin = new Thickness(8, 0, 8, 0), ToolTip = "Exact target IPv4, or blank for all" };
        var refresh = new Button { Content = "Refresh", Padding = new Thickness(10, 4, 10, 4) };
        line.Children.Add(sensor); line.Children.Add(target); line.Children.Add(refresh); filters.Children.Add(line);
        var choices = new ComboBox { Margin = new Thickness(0, 8, 0, 4), DisplayMemberPath = "Label" };
        filters.Children.Add(choices);
        var baselineActions = new StackPanel { Orientation = Orientation.Horizontal };
        var approve = new Button { Content = "Approve selected baseline", Margin = new Thickness(0, 0, 8, 0) };
        var compare = new Button { Content = "Compare selected with approved baseline" };
        baselineActions.Children.Add(approve); baselineActions.Children.Add(compare); filters.Children.Add(baselineActions);
        var status = new TextBlock { Margin = new Thickness(0, 8, 0, 8), TextWrapping = TextWrapping.Wrap };
        filters.Children.Add(status);
        DockPanel.SetDock(filters, Dock.Top); panel.Children.Add(filters);
        var output = new TextBox { IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, FontFamily = new System.Windows.Media.FontFamily("Consolas") };
        panel.Children.Add(output); dialog.Content = panel;
        bool closed = false;
        dialog.Closed += (_, _) => closed = true;
        async Task Load()
        {
            if (!refresh.IsEnabled) return;
            refresh.IsEnabled = false;
            var kind = sensor.SelectedIndex > 0 && Enum.TryParse<ActiveSensorKind>(sensor.SelectedItem?.ToString(), out var parsed)
                ? (ActiveSensorKind?)parsed : null;
            string? ip = string.IsNullOrWhiteSpace(target.Text) ? null : target.Text.Trim();
            try
            {
                var result = await Task.Run(() => new ActiveEvidenceStore().Read(kind, ip));
                if (closed) return;
                status.Text = $"{result.Rows.Count} observation(s). {result.Error}";
                choices.ItemsSource = result.Rows.Select(r => new ActiveHistoryChoice(r.Id,
                    $"{new DateTime(r.ObservedTicks, DateTimeKind.Utc):u} | {r.Sensor} | {r.Target} | {r.ProbeKey} | {r.Status}")).ToArray();
                choices.SelectedIndex = result.Rows.Count > 0 ? 0 : -1;
                output.Text = string.Join("\n\n", result.Rows.Select(r =>
                    $"{new DateTime(r.ObservedTicks, DateTimeKind.Utc):u} | {r.Sensor} | {r.Target} | {r.Status}\n" +
                    $"Adapter: {r.AdapterId} | Source: {r.Source} | Probe: {r.ProbeKey}\n{r.EvidenceJson}"));
            }
            finally { if (!closed) refresh.IsEnabled = true; }
        }
        approve.Click += async (_, _) =>
        {
            if (choices.SelectedItem is not ActiveHistoryChoice item || !approve.IsEnabled) return;
            if (MessageBox.Show(dialog, "Approve this observation as the comparison reference for its exact scope? " +
                "This replaces any previous approval for that scope; it does not establish trust.", "Approve baseline",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
            approve.IsEnabled = compare.IsEnabled = false;
            try
            {
                bool ok = await Task.Run(() => new ActiveEvidenceStore().Approve(item.Id));
                if (!closed) status.Text = ok ? "Baseline approved." : "Approval failed: unavailable, inconclusive or capacity reached.";
            }
            finally { if (!closed) approve.IsEnabled = compare.IsEnabled = true; }
        };
        compare.Click += async (_, _) =>
        {
            if (choices.SelectedItem is not ActiveHistoryChoice item || !compare.IsEnabled) return;
            approve.IsEnabled = compare.IsEnabled = false;
            try
            {
                var result = await Task.Run(() => new ActiveEvidenceStore().CompareApproved(item.Id));
                if (!closed)
                {
                    status.Text = result.Status + " — " + result.Note;
                    output.Text = string.Join("\n", result.Changes.Select(c => $"{c.Kind} | {c.Field}: {c.Before} → {c.After}"));
                }
            }
            finally { if (!closed) approve.IsEnabled = compare.IsEnabled = true; }
        };
        refresh.Click += async (_, _) => await Load();
        dialog.Loaded += async (_, _) => await Load();
        dialog.ShowDialog();
    }
}
