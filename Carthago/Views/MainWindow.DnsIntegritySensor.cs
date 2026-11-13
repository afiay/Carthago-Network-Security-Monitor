// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Net;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using Carthago.Services;
using Carthago.Services.Sensors;

namespace Carthago;

public partial class MainWindow
{
    private void CheckLanDnsIntegrity_Click(object sender, RoutedEventArgs e)
    {
        if (StopButton.IsEnabled || !DeviceComboBox.IsEnabled || _lanCaptureDiscovery is not null)
        {
            MessageBox.Show(this, "Stop monitoring and finish LAN discovery before checking DNS.", "Active sensor");
            return;
        }
        if ((DeviceComboBox.SelectedItem as ComboBoxItem)?.Tag is not LanCaptureSelection host)
        {
            MessageBox.Show(this, "Select a LAN DNS resolver using Scan LAN or Add IP first.", "Active sensor");
            return;
        }
        var id = CaptureDeviceLabelFormatter.ParseDeviceGuid(host.Device.Name);
        var adapter = id.HasValue
            ? LocalLanDiscovery.GetLocalInterfaces(id.Value).FirstOrDefault(a =>
                LocalLanDiscovery.PlanProbeTargets(new[] { a }).Contains(host.Address))
            : null;
        if (adapter is null)
        {
            MessageBox.Show(this, "The selected resolver is no longer in the active adapter's local IPv4 scope.", "Active sensor");
            return;
        }

        var dialog = new Window
        {
            Owner = this, Title = "Active sensor — DNS integrity", Width = 640, Height = 500,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, ShowInTaskbar = false
        };
        var panel = new DockPanel { Margin = new Thickness(16) };
        var inputs = new StackPanel();
        inputs.Children.Add(new TextBlock
        {
            Text = $"Resolver: {host.Address}:53 UDP via {adapter.Name} ({adapter.Address})\n" +
                "One authorized A query. Enter a hostname you are permitted to disclose to this resolver. " +
                "Optional expected IPv4 addresses must be independently verified; a difference is not proof of compromise.",
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12)
        });
        inputs.Children.Add(new TextBlock { Text = "DNS hostname (ASCII / punycode)" });
        var name = new TextBox { MaxLength = 254, Margin = new Thickness(0, 4, 0, 10) };
        inputs.Children.Add(name);
        inputs.Children.Add(new TextBlock { Text = "Expected IPv4 addresses (optional, comma-separated, max 16)" });
        var expected = new TextBox { MaxLength = 270, Margin = new Thickness(0, 4, 0, 12) };
        inputs.Children.Add(expected);
        DockPanel.SetDock(inputs, Dock.Top);
        panel.Children.Add(inputs);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var run = new Button { Content = "Run authorized query", Padding = new Thickness(10, 5, 10, 5), Margin = new Thickness(0, 0, 8, 0) };
        var close = new Button { Content = "Close", Padding = new Thickness(10, 5, 10, 5) };
        buttons.Children.Add(run);
        buttons.Children.Add(close);
        DockPanel.SetDock(buttons, Dock.Bottom);
        panel.Children.Add(buttons);
        var output = new TextBox
        {
            IsReadOnly = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Margin = new Thickness(0, 0, 0, 12),
            Text = "No query sent. Without a baseline, addresses are observations only."
        };
        panel.Children.Add(output);
        dialog.Content = panel;
        CancellationTokenSource? active = null;
        bool closed = false;
        dialog.Closed += (_, _) => { closed = true; active?.Cancel(); };
        close.Click += (_, _) => dialog.Close();
        run.Click += async (_, _) =>
        {
            if (active is not null) return;
            using var cancellation = new CancellationTokenSource();
            active = cancellation;
            run.IsEnabled = false;
            name.IsEnabled = expected.IsEnabled = false;
            close.Content = "Cancel / close";
            try
            {
                var baseline = string.IsNullOrWhiteSpace(expected.Text)
                    ? Array.Empty<IPAddress>()
                    : expected.Text.Split(',').Select(value =>
                    {
                        if (!IPAddress.TryParse(value.Trim(), out var ip) ||
                            ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
                            value.Trim() != ip.ToString())
                            throw new ArgumentException("Expected addresses must be complete dotted IPv4 addresses.");
                        return ip;
                    }).ToArray();
                output.Text = "Querying selected resolver…";
                var observation = await DnsIntegritySensor.CheckAsync(adapter, host.Address, name.Text, baseline, cancellation.Token);
                if (!closed)
                    output.Text = $"{observation.Name} — {observation.Status}\n" +
                        $"Resolver: {observation.Resolver} | {observation.Duration.TotalMilliseconds:0} ms\n" +
                        $"DNS response code: {observation.ResponseCode?.ToString() ?? "Not established"}\n" +
                        $"Observed IPv4: {string.Join(", ", observation.Addresses)}\n" +
                        $"Expected IPv4: {string.Join(", ", baseline.Select(ip => ip.ToString()))}\n" +
                        (observation.SocketError.HasValue ? $"Socket: {observation.SocketError}\n" : "") +
                        "\nA mismatch is not proof of DNS poisoning. Truncation, no address and errors are inconclusive.";
            }
            catch (OperationCanceledException) { if (!closed) output.Text = "Query cancelled."; }
            catch (Exception ex) { if (!closed) output.Text = "Query not completed: " + ex.Message; }
            finally
            {
                active = null;
                if (!closed)
                {
                    run.IsEnabled = name.IsEnabled = expected.IsEnabled = true;
                    close.Content = "Close";
                }
            }
        };
        dialog.ShowDialog();
    }
}
