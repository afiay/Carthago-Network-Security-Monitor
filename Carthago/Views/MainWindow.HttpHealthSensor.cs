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
    private void CheckLanHttpHealth_Click(object sender, RoutedEventArgs e)
    {
        if (StopButton.IsEnabled || !DeviceComboBox.IsEnabled || _lanCaptureDiscovery is not null)
        {
            MessageBox.Show(this, "Stop monitoring and finish LAN discovery before HTTP inspection.", "Active sensor");
            return;
        }
        if ((DeviceComboBox.SelectedItem as ComboBoxItem)?.Tag is not LanCaptureSelection host)
        {
            MessageBox.Show(this, "Select a LAN host using Scan LAN or Add IP first.", "Active sensor");
            return;
        }
        var id = CaptureDeviceLabelFormatter.ParseDeviceGuid(host.Device.Name);
        var adapter = id.HasValue ? LocalLanDiscovery.GetLocalInterfaces(id.Value).FirstOrDefault(a =>
            LocalLanDiscovery.PlanProbeTargets(new[] { a }).Contains(host.Address)) : null;
        if (adapter is null)
        {
            MessageBox.Show(this, "Target is no longer in the selected adapter's local IPv4 scope.", "Active sensor");
            return;
        }
        var dialog = new Window { Owner = this, Title = "Active sensor — HTTP/HTTPS health", Width = 660, Height = 520,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, ShowInTaskbar = false };
        var panel = new DockPanel { Margin = new Thickness(16) };
        var inputs = new StackPanel();
        inputs.Children.Add(new TextBlock { Text = $"Target: {host.Address} via {adapter.Name} ({adapter.Address})\n" +
            "One authorized HEAD / request. No redirects followed, credentials, proxy or body reads. HTTPS requires platform trust (revocation not checked). " +
            "Header presence alone does not establish a secure configuration.",
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) });
        inputs.Children.Add(new TextBlock { Text = "Port (80/8080 HTTP, 443/8443 HTTPS)" });
        var port = new ComboBox { ItemsSource = HttpHealthSensor.AllowedPorts, SelectedIndex = 0, Margin = new Thickness(0, 4, 0, 10) };
        inputs.Children.Add(port);
        inputs.Children.Add(new TextBlock { Text = "Expected DNS hostname (Host header / HTTPS SNI)" });
        var name = new TextBox { MaxLength = 254, Margin = new Thickness(0, 4, 0, 12) };
        inputs.Children.Add(name);
        DockPanel.SetDock(inputs, Dock.Top); panel.Children.Add(inputs);
        var actions = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var run = new Button { Content = "Run authorized check", Padding = new Thickness(10, 5, 10, 5), Margin = new Thickness(0, 0, 8, 0) };
        var close = new Button { Content = "Close", Padding = new Thickness(10, 5, 10, 5) };
        actions.Children.Add(run); actions.Children.Add(close);
        DockPanel.SetDock(actions, Dock.Bottom); panel.Children.Add(actions);
        var output = new TextBox { IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(0, 0, 0, 12),
            Text = "No request sent." };
        panel.Children.Add(output); dialog.Content = panel;
        CancellationTokenSource? active = null;
        bool closed = false;
        dialog.Closed += (_, _) => { closed = true; active?.Cancel(); };
        close.Click += (_, _) => dialog.Close();
        run.Click += async (_, _) =>
        {
            if (active is not null) return;
            using var cancellation = new CancellationTokenSource();
            active = cancellation;
            run.IsEnabled = port.IsEnabled = name.IsEnabled = false;
            close.Content = "Cancel / close";
            try
            {
                output.Text = "Checking selected web endpoint…";
                var result = await HttpHealthSensor.CheckAsync(adapter, host.Address, (int)port.SelectedItem, name.Text, cancellation.Token);
                if (closed) return;
                output.Text = $"{result.Status} | HTTP status: {result.StatusCode?.ToString() ?? "Not established"}\n" +
                    $"Elapsed: {result.Duration.TotalMilliseconds:0} ms | Redirect: {result.Redirect} (not followed)\n" +
                    (result.Certificate is null ? "" : $"TLS policy: {result.Certificate.PolicyErrors}\n") +
                    "\nObserved selected headers:\n" +
                    string.Join("\n", result.Headers.SelectMany(h => h.Values.Select(v => h.Name + ": " + v))) +
                    "\n\nMissing headers, HTTP error statuses and redirects are observations, not vulnerability findings. No redirect destination text is retained.";
            }
            catch (OperationCanceledException) { if (!closed) output.Text = "Check cancelled."; }
            catch (Exception ex) { if (!closed) output.Text = "Check not completed: " + ex.Message; }
            finally
            {
                active = null;
                if (!closed) { run.IsEnabled = port.IsEnabled = name.IsEnabled = true; close.Content = "Close"; }
            }
        };
        dialog.ShowDialog();
    }
}
