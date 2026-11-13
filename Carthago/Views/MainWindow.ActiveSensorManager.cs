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
        var profileStore = new ActiveSensorProfileStore();
        var dialog = new Window { Owner = this, Title = "Active sensor manager — session authorization", Width = 900, Height = 760,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, ShowInTaskbar = false };
        var panel = new DockPanel { Margin = new Thickness(16) };
        var inputs = new StackPanel();
        inputs.Children.Add(new TextBlock { Text = $"Approved target: {host.Address} via {adapter.Name} ({adapter.Address})\n" +
            "Add profiles, then explicitly start. One probe at a time; first check immediately, minimum five-minute interval. " +
            "Closing stops all checks. Saved configurations require fresh approval. Gateway and SNMP remain manual-only.",
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
        inputs.Children.Add(new TextBlock { Text = "Saved configurations (inactive until reapproved)", Margin = new Thickness(0, 8, 0, 4) });
        var saved = new ComboBox { DisplayMemberPath = "Label", Margin = new Thickness(0, 0, 0, 5) };
        inputs.Children.Add(saved);
        var savedActions = new WrapPanel();
        var remember = new Button { Content = "Save selected session profile", Margin = new Thickness(0, 0, 8, 4) };
        var restore = new Button { Content = "Reapprove saved profile", Margin = new Thickness(0, 0, 8, 4) };
        var forget = new Button { Content = "Delete saved profile", Margin = new Thickness(0, 0, 8, 4) };
        foreach (var button in new[] { remember, restore, forget })
        { button.Padding = new Thickness(8, 4, 8, 4); savedActions.Children.Add(button); }
        inputs.Children.Add(savedActions);
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
        void RefreshSaved()
        {
            var selection = (saved.SelectedItem as SavedActiveSensorProfile)?.Id;
            var read = profileStore.Read();
            saved.ItemsSource = read.Rows;
            saved.SelectedItem = read.Rows.FirstOrDefault(r => r.Id == selection);
            if (saved.SelectedIndex < 0 && read.Rows.Count > 0) saved.SelectedIndex = 0;
            if (read.Error is not null) message.Text = read.Error;
        }
        RefreshSaved();
        remember.Click += (_, _) =>
        {
            if (active is not null || (list.SelectedItem as ListBoxItem)?.Tag is not Guid profileId) return;
            var selected = manager.Snapshot().FirstOrDefault(s => s.Profile.Id == profileId);
            if (selected is null) return;
            message.Text = profileStore.Save(selected.Profile)
                ? "Configuration saved. No execution authorization is persisted."
                : "Could not save configuration (storage unavailable or capacity reached).";
            RefreshSaved();
        };
        restore.Click += (_, _) =>
        {
            if (active is not null || saved.SelectedItem is not SavedActiveSensorProfile selected) return;
            try
            {
                // Resolve again, since a saved profile must not inherit the original dialog's scope.
                var live = LocalLanDiscovery.GetLocalInterfaces(id!.Value).FirstOrDefault(a =>
                    a.Address.Equals(adapter.Address) && a.Mask.Equals(adapter.Mask) &&
                    LocalLanDiscovery.PlanProbeTargets(new[] { a }).Contains(host.Address));
                if (live is null) { message.Text = "Selected live scope has changed. Close and select the current host."; return; }
                var profile = selected.ApproveForSession(id.Value, live, host.Address);
                if (MessageBox.Show(dialog, $"Authorize this configuration for this session?\n{selected.Label}\n" +
                    $"Adapter: {selected.AdapterId}\nNo probes run until Start.",
                    "Reapprove active profile", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
                manager.Add(profile);
                message.Text = "Reapproved for this session. Start to enable checks.";
                Refresh();
            }
            catch (Exception ex) when (ex is not OutOfMemoryException) { message.Text = ex.Message; }
        };
        forget.Click += (_, _) =>
        {
            if (active is not null || saved.SelectedItem is not SavedActiveSensorProfile selected) return;
            if (MessageBox.Show(dialog, "Delete this saved configuration? Any separately approved session profile remains active until removed.",
                "Delete saved profile", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
            message.Text = profileStore.Delete(selected.Id) ? "Saved configuration deleted." : "Could not delete configuration.";
            RefreshSaved();
        };
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        timer.Tick += (_, _) =>
        {
            Refresh();
            if (active is not null && !active.IsCancellationRequested && manager.HasReservation)
                message.Text = "Running approved profiles — machine-wide ownership held.";
        };
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
            start.IsEnabled = add.IsEnabled = remove.IsEnabled = remember.IsEnabled = restore.IsEnabled = forget.IsEnabled = false;
            stop.IsEnabled = true;
            message.Text = "Starting — acquiring machine-wide scheduler ownership…";
            string? failure = null;
            try { await Task.Run(() => manager.RunAsync(cancellation.Token), cancellation.Token); }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
            catch (InvalidOperationException ex) { failure = ex.Message; }
            catch (Exception ex) when (ex is not OutOfMemoryException) { failure = "Scheduler stopped unexpectedly."; }
            finally
            {
                active = null;
                stop.IsEnabled = false;
                start.IsEnabled = add.IsEnabled = remove.IsEnabled = remember.IsEnabled = restore.IsEnabled = forget.IsEnabled = true;
                if (closeRequested) dialog.Close();
                else { message.Text = failure ?? "Stopped — no scheduled network activity."; Refresh(); }
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
