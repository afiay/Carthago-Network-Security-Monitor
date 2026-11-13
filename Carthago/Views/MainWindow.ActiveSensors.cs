// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using Carthago.Services;
using Carthago.Services.Sensors;

namespace Carthago;

public partial class MainWindow
{
    private void CheckLanTcpExposure_Click(object sender, RoutedEventArgs e)
    {
        if (StopButton.IsEnabled || !DeviceComboBox.IsEnabled || _lanCaptureDiscovery is not null)
        {
            MessageBox.Show(this, "Stop monitoring and finish LAN discovery before checking TCP exposure.", "Active sensor");
            return;
        }
        if ((DeviceComboBox.SelectedItem as ComboBoxItem)?.Tag is not LanCaptureSelection host)
        {
            MessageBox.Show(this, "Select a LAN host filter first (Scan LAN or Add IP).", "Active sensor");
            return;
        }
        var id = CaptureDeviceLabelFormatter.ParseDeviceGuid(host.Device.Name);
        var adapter = id.HasValue
            ? LocalLanDiscovery.GetLocalInterfaces(id.Value).FirstOrDefault(a =>
                LocalLanDiscovery.PlanProbeTargets(new[] { a }).Contains(host.Address))
            : null;
        if (adapter is null)
        {
            MessageBox.Show(this, "The target is no longer in the selected active adapter's local IPv4 scope.", "Active sensor");
            return;
        }

        var dialog = new Window
        {
            Owner = this, Title = "Active sensor — TCP exposure", Width = 590, Height = 440,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, ShowInTaskbar = false
        };
        var panel = new DockPanel { Margin = new Thickness(16) };
        var header = new TextBlock
        {
            Text = $"Target: {host.Address} via {adapter.Name} ({adapter.Address})\n" +
                "Confirm you are authorized to check this host. One TCP connect per listed port; no payload or login. " +
                "Results are point-in-time reachability, not vulnerability or protocol proof.",
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12)
        };
        DockPanel.SetDock(header, Dock.Top);
        panel.Children.Add(header);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var run = new Button { Content = "Run authorized check", Padding = new Thickness(10, 5, 10, 5), Margin = new Thickness(0, 0, 8, 0) };
        var close = new Button { Content = "Close", Padding = new Thickness(10, 5, 10, 5) };
        buttons.Children.Add(run);
        buttons.Children.Add(close);
        DockPanel.SetDock(buttons, Dock.Bottom);
        panel.Children.Add(buttons);
        var output = new TextBox
        {
            IsReadOnly = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Margin = new Thickness(0, 0, 0, 12),
            Text = "TCP ports: " + string.Join(", ", TcpExposureSensor.DefaultPorts)
        };
        var saveHistory = AddActiveEvidenceOptIn(panel);
        panel.Children.Add(output);
        dialog.Content = panel;
        CancellationTokenSource? active = null;
        bool closed = false;
        bool closeRequested = false;
        dialog.Closing += (_, args) =>
        {
            if (active is null) return;
            args.Cancel = true;
            closeRequested = true;
            active.Cancel();
            output.Text = "Cancelling; waiting for probe and storage cleanup…";
        };
        dialog.Closed += (_, _) => closed = true;
        close.Click += (_, _) => dialog.Close();
        run.Click += async (_, _) =>
        {
            if (active is not null) return;
            using var cancellation = new CancellationTokenSource();
            active = cancellation;
            bool persist = saveHistory.IsChecked == true;
            saveHistory.IsEnabled = false;
            run.IsEnabled = false;
            close.Content = "Cancel / close";
            output.Text = "Checking selected host…";
            try
            {
                var observations = await TcpExposureSensor.ScanAsync(adapter, host.Address, cancellation.Token);
                if (!closed)
                    output.Text = string.Join(Environment.NewLine, observations.Select(o =>
                        $"TCP {o.Port}: {o.Status} ({o.Duration.TotalMilliseconds:0} ms)" +
                        (o.SocketError.HasValue ? $" — {o.SocketError}" : ""))) +
                        "\n\nOpen = TCP handshake completed. Refused = explicit connection refusal. " +
                        "Timeout/unreachable/error do not establish that a port is closed.";
                if (persist && !closed && !closeRequested && !cancellation.IsCancellationRequested)
                {
                    var saved = await SaveActiveEvidenceAsync(() => ActiveEvidenceProjection.From(id!.Value, observations));
                    if (!closed) output.Text += saved;
                }
            }
            catch (OperationCanceledException) { if (!closed) output.Text = "Check cancelled."; }
            catch (Exception ex) { if (!closed) output.Text = "Check failed: " + ex.Message; }
            finally
            {
                active = null;
                if (closeRequested) dialog.Close();
                else if (!closed) { close.Content = "Close"; saveHistory.IsEnabled = true; run.IsEnabled = true; }
            }
        };
        dialog.ShowDialog();
    }
}
