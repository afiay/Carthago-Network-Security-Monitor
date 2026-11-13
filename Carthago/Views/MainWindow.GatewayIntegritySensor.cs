// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Carthago.Services;
using Carthago.Services.Sensors;
using SharpPcap;

namespace Carthago;

public partial class MainWindow
{
    private void CheckGatewayIntegrity_Click(object sender, RoutedEventArgs e)
    {
        if (StopButton.IsEnabled || !DeviceComboBox.IsEnabled || _lanCaptureDiscovery is not null)
        {
            MessageBox.Show(this, "Stop monitoring and finish LAN discovery before gateway inspection.", "Active sensor");
            return;
        }
        var selected = (DeviceComboBox.SelectedItem as ComboBoxItem)?.Tag;
        var device = selected is LanCaptureSelection host ? host.Device : selected as ILiveDevice;
        var id = CaptureDeviceLabelFormatter.ParseDeviceGuid(device?.Name);
        if (device is null || !id.HasValue)
        {
            MessageBox.Show(this, "Select a local Wi-Fi or Ethernet Npcap adapter.", "Active sensor");
            return;
        }
        var network = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n =>
            Guid.TryParse(n.Id, out var guid) && guid == id.Value);
        var gateways = network?.GetIPProperties().GatewayAddresses.Select(g => g.Address).Distinct().ToArray()
            ?? Array.Empty<IPAddress>();
        var pairs = LocalLanDiscovery.GetLocalInterfaces(id.Value).SelectMany(a =>
            gateways.Where(g => LocalLanDiscovery.PlanProbeTargets(new[] { a }).Contains(g))
                .Select(g => (Adapter: a, Gateway: g))).ToArray();
        if (pairs.Length == 0)
        {
            MessageBox.Show(this, "No configured IPv4 gateway in the selected adapter's supported local scope.", "Active sensor");
            return;
        }
        var dialog = new Window { Owner = this, Title = "Active sensor — Gateway integrity", Width = 660, Height = 520,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, ShowInTaskbar = false };
        var panel = new DockPanel { Margin = new Thickness(16) };
        var inputs = new StackPanel();
        inputs.Children.Add(new TextBlock { Text = "Two authorized ARP requests to a configured gateway. " +
            "Direct MAC claims are retained separately from the pre-probe Windows cache. ARP is unauthenticated; " +
            "conflicts or differences are not proof of spoofing.",
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) });
        inputs.Children.Add(new TextBlock { Text = "Configured gateway / source address" });
        var choice = new ComboBox { ItemsSource = pairs.Select(p => $"{p.Gateway} via {p.Adapter.Address} ({p.Adapter.Name})").ToArray(),
            SelectedIndex = 0, Margin = new Thickness(0, 4, 0, 10) };
        inputs.Children.Add(choice);
        inputs.Children.Add(new TextBlock { Text = "Independently verified expected gateway MAC (optional)" });
        var baseline = new TextBox { MaxLength = 20, Margin = new Thickness(0, 4, 0, 12) };
        inputs.Children.Add(baseline);
        DockPanel.SetDock(inputs, Dock.Top); panel.Children.Add(inputs);
        var actions = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var run = new Button { Content = "Run authorized check", Padding = new Thickness(10, 5, 10, 5), Margin = new Thickness(0, 0, 8, 0) };
        var close = new Button { Content = "Close", Padding = new Thickness(10, 5, 10, 5) };
        actions.Children.Add(run); actions.Children.Add(close);
        DockPanel.SetDock(actions, Dock.Bottom); panel.Children.Add(actions);
        var output = new TextBox { IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(0, 0, 0, 12), Text = "No ARP request sent." };
        panel.Children.Add(output); dialog.Content = panel;
        CancellationTokenSource? active = null;
        bool closeRequested = false;
        // Do not release the modal owner while Npcap capture is still open.
        dialog.Closing += (_, args) =>
        {
            if (active is null) return;
            args.Cancel = true;
            closeRequested = true;
            active.Cancel();
            output.Text = "Cancelling and releasing capture adapter…";
        };
        close.Click += (_, _) => dialog.Close();
        run.Click += async (_, _) =>
        {
            if (active is not null) return;
            using var cancellation = new CancellationTokenSource();
            active = cancellation;
            run.IsEnabled = choice.IsEnabled = baseline.IsEnabled = false;
            close.Content = "Cancel / close";
            try
            {
                var pair = pairs[choice.SelectedIndex];
                var expected = baseline.Text;
                output.Text = "Checking configured gateway…";
                var result = await Task.Run(() => GatewayIntegritySensor.CheckAsync(device, pair.Adapter,
                    pair.Gateway, expected, cancellation.Token), cancellation.Token);
                output.Text = $"{result.Status} | Gateway: {result.Gateway} | Source: {result.Source}\n" +
                    $"Direct ARP claims: {string.Join(", ", result.DirectMacs)}\n" +
                    $"Pre-probe cached MAC: {result.CachedMac ?? "Not established"}\n" +
                    $"Expected MAC: {result.ExpectedMac ?? "Not configured"}\n" +
                    $"Cache differs from at least one direct claim: {result.CacheDiffers}\n" +
                    $"Claim limit reached: {result.ClaimLimitReached}\n\n" +
                    "No reply does not prove the gateway is offline. A match does not authenticate a gateway; investigate changes and failover.";
            }
            catch (OperationCanceledException) { output.Text = "Check cancelled."; }
            catch (Exception ex) { output.Text = "Check not completed: " + ex.Message; }
            finally
            {
                active = null;
                if (closeRequested) dialog.Close();
                else { run.IsEnabled = choice.IsEnabled = baseline.IsEnabled = true; close.Content = "Close"; }
            }
        };
        dialog.ShowDialog();
    }
}
