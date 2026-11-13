// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Carthago.Services;
using Carthago.Services.Sensors;

namespace Carthago;

public partial class MainWindow
{
    private void OpenActiveSensorManager_Click(object sender, RoutedEventArgs e)
    {
        if (StopButton.IsEnabled || !DeviceComboBox.IsEnabled || _lanCaptureDiscovery is not null)
        {
            MessageBox.Show(this, "Stop monitoring and finish LAN discovery before scheduled active checks.", "Active sensors");
            return;
        }
        if ((DeviceComboBox.SelectedItem as ComboBoxItem)?.Tag is not LanCaptureSelection host)
        {
            MessageBox.Show(this, "Select an authorized LAN host using Scan LAN or Add IP.", "Active sensors");
            return;
        }
        var id = CaptureDeviceLabelFormatter.ParseDeviceGuid(host.Device.Name);
        var adapter = id.HasValue ? LocalLanDiscovery.GetLocalInterfaces(id.Value).FirstOrDefault(a =>
            LocalLanDiscovery.PlanProbeTargets(new[] { a }).Contains(host.Address)) : null;
        if (adapter is null)
        {
            MessageBox.Show(this, "Target is outside the selected adapter's current local IPv4 scope.", "Active sensors");
            return;
        }
        var manager = new ActiveSensorManager();
        var dialog = new Window { Owner = this, Title = "Active sensor manager — session only", Width = 820, Height = 650,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, ShowInTaskbar = false };
        var panel = new DockPanel { Margin = new Thickness(16) };
        var inputs = new StackPanel();
        inputs.Children.Add(new TextBlock { Text = $"Approved target: {host.Address} via {adapter.Name} ({adapter.Address})\n" +
            "Add profiles, then explicitly start. One probe at a time; first check immediately, minimum five-minute interval. " +
            "Closing stops all checks. Profiles are not saved. Gateway and SNMP remain manual-only.",
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 10) });
        inputs.Children.Add(new TextBlock { Text = "Sensor" });
        var kind = new ComboBox { ItemsSource = new[] { ActiveSensorKind.Tcp, ActiveSensorKind.Dns, ActiveSensorKind.Tls, ActiveSensorKind.Http },
            SelectedIndex = 0, Margin = new Thickness(0, 3, 0, 7) };
        inputs.Children.Add(kind);
        inputs.Children.Add(new TextBlock { Text = "DNS hostname (required for DNS/TLS/HTTP; ignored for TCP)" });
        var name = new TextBox { MaxLength = 254, Margin = new Thickness(0, 3, 0, 7) }; inputs.Children.Add(name);
        inputs.Children.Add(new TextBlock { Text = "Port (TLS/HTTP only)" });
        var port = new ComboBox { ItemsSource = new[] { 443, 8443, 80, 8080, 5986, 636, 8883 }, SelectedIndex = 0,
            Margin = new Thickness(0, 3, 0, 7) }; inputs.Children.Add(port);
        inputs.Children.Add(new TextBlock { Text = "Interval (minutes)" });
        var interval = new ComboBox { ItemsSource = new[] { 5, 15, 30, 60, 240, 1440 }, SelectedIndex = 0,
            Margin = new Thickness(0, 3, 0, 7) }; inputs.Children.Add(interval);
        var save = new CheckBox { Content = "Save completed observations to local active history", IsChecked = false,
            Margin = new Thickness(0, 0, 0, 8) }; inputs.Children.Add(save);
        var add = new Button { Content = "Approve and add profile", Padding = new Thickness(8, 4, 8, 4) }; inputs.Children.Add(add);
        DockPanel.SetDock(inputs, Dock.Top); panel.Children.Add(inputs);
        var actions = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var remove = new Button { Content = "Remove selected", Margin = new Thickness(0, 0, 8, 0) };
        var start = new Button { Content = "Start approved profiles", Margin = new Thickness(0, 0, 8, 0) };
        var stop = new Button { Content = "Stop", IsEnabled = false, Margin = new Thickness(0, 0, 8, 0) };
        var close = new Button { Content = "Close" };
        foreach (var button in new[] { remove, start, stop, close }) { button.Padding = new Thickness(8, 4, 8, 4); actions.Children.Add(button); }
        DockPanel.SetDock(actions, Dock.Bottom); panel.Children.Add(actions);
        var message = new TextBlock { Text = "Stopped — no scheduled network activity.", TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 8, 0, 8) };
        DockPanel.SetDock(message, Dock.Bottom); panel.Children.Add(message);
        var list = new ListBox { FontFamily = new System.Windows.Media.FontFamily("Consolas") };
        panel.Children.Add(list); dialog.Content = panel;
        CancellationTokenSource? active = null;
        bool closeRequested = false;
        void Refresh()
        {
            var selected = (list.SelectedItem as ListBoxItem)?.Tag;
            list.Items.Clear();
            foreach (var state in manager.Snapshot())
            {
                var p = state.Profile;
                var row = new ListBoxItem { Tag = p.Id, Content = $"{p.Kind} {p.HostName} {p.Port} | {p.Interval.TotalMinutes:0} min | " +
                    $"{(state.Running ? "Running" : state.LastOutcome)}\n" +
                    $"Last: {state.LastRunUtc?.ToLocalTime().ToString("g") ?? "Never"} | Next: " +
                    $"{(state.ScopeBlocked ? "Blocked" : state.NextDueUtc.ToLocalTime().ToString("g"))} | Failures: {state.ConsecutiveFailures} | History: {state.HistoryStatus}" };
                list.Items.Add(row);
                if (Equals(selected, p.Id)) list.SelectedItem = row;
            }
        }
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        timer.Tick += (_, _) => Refresh();
        timer.Start();
        add.Click += (_, _) =>
        {
            if (active is not null) return;
            try
            {
                manager.Add(ActiveSensorProfile.Create(id!.Value, adapter, host.Address, (ActiveSensorKind)kind.SelectedItem,
                    name.Text, (int)port.SelectedItem, TimeSpan.FromMinutes((int)interval.SelectedItem), save.IsChecked == true));
                message.Text = "Profile approved for this session. Start to enable checks.";
                Refresh();
            }
            catch (Exception ex) { message.Text = ex.Message; }
        };
        remove.Click += (_, _) =>
        {
            if (active is null && (list.SelectedItem as ListBoxItem)?.Tag is Guid profileId)
            { manager.Remove(profileId); Refresh(); }
        };
        start.Click += async (_, _) =>
        {
            if (active is not null || manager.Snapshot().Count == 0) return;
            using var cancellation = new CancellationTokenSource();
            active = cancellation;
            start.IsEnabled = add.IsEnabled = remove.IsEnabled = false;
            stop.IsEnabled = true;
            message.Text = "Running approved profiles.";
            try { await Task.Run(() => manager.RunAsync(cancellation.Token), cancellation.Token); }
            catch (OperationCanceledException) { }
            catch (Exception) { message.Text = "Scheduler stopped unexpectedly."; }
            finally
            {
                active = null;
                stop.IsEnabled = false;
                start.IsEnabled = add.IsEnabled = remove.IsEnabled = true;
                if (closeRequested) dialog.Close();
                else { message.Text = "Stopped — no scheduled network activity."; Refresh(); }
            }
        };
        stop.Click += (_, _) => { active?.Cancel(); stop.IsEnabled = false; message.Text = "Stopping; waiting for current probe cleanup…"; };
        close.Click += (_, _) => dialog.Close();
        dialog.Closing += (_, args) =>
        {
            if (active is null) return;
            args.Cancel = true; closeRequested = true; active.Cancel();
            message.Text = "Stopping; waiting for current probe cleanup…";
        };
        dialog.Closed += (_, _) => timer.Stop();
        dialog.ShowDialog();
    }
}
