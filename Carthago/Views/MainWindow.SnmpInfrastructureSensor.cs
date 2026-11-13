// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Carthago.Services;
using Carthago.Services.Sensors;

namespace Carthago;

public partial class MainWindow
{
    private void CheckLanSnmpInfrastructure_Click(object sender, RoutedEventArgs e)
    {
        if (StopButton.IsEnabled || !DeviceComboBox.IsEnabled || _lanCaptureDiscovery is not null)
        {
            MessageBox.Show(this, "Stop monitoring and finish LAN discovery before SNMP inspection.", "Active sensor");
            return;
        }
        if ((DeviceComboBox.SelectedItem as ComboBoxItem)?.Tag is not LanCaptureSelection host)
        {
            MessageBox.Show(this, "Select an authorized LAN SNMP agent using Scan LAN or Add IP.", "Active sensor");
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
        var dialog = new Window { Owner = this, Title = "Active sensor — SNMPv3 infrastructure", Width = 660, Height = 560,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, ShowInTaskbar = false };
        var panel = new DockPanel { Margin = new Thickness(16) };
        var inputs = new StackPanel();
        inputs.Children.Add(new TextBlock { Text = $"Agent: {host.Address}:161 UDP via {adapter.Name} ({adapter.Address})\n" +
            "SNMPv3 authPriv, SHA-256 / AES-128, read-only GET. Use an authorized read-only account. " +
            "Credentials are not saved or displayed in results. No fallback to older SNMP versions.",
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) });
        inputs.Children.Add(new TextBlock { Text = "SNMPv3 user" });
        var user = new TextBox { MaxLength = 32, Margin = new Thickness(0, 4, 0, 10) }; inputs.Children.Add(user);
        inputs.Children.Add(new TextBlock { Text = "Authentication passphrase" });
        var auth = new PasswordBox { MaxLength = 128, Margin = new Thickness(0, 4, 0, 10) }; inputs.Children.Add(auth);
        inputs.Children.Add(new TextBlock { Text = "Privacy passphrase" });
        var privacy = new PasswordBox { MaxLength = 128, Margin = new Thickness(0, 4, 0, 12) }; inputs.Children.Add(privacy);
        DockPanel.SetDock(inputs, Dock.Top); panel.Children.Add(inputs);
        var actions = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var run = new Button { Content = "Run authorized GET", Padding = new Thickness(10, 5, 10, 5), Margin = new Thickness(0, 0, 8, 0) };
        var close = new Button { Content = "Close", Padding = new Thickness(10, 5, 10, 5) };
        actions.Children.Add(run); actions.Children.Add(close);
        DockPanel.SetDock(actions, Dock.Bottom); panel.Children.Add(actions);
        var output = new TextBox { IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(0, 0, 0, 12), Text = "No request sent." };
        panel.Children.Add(output); dialog.Content = panel;
        CancellationTokenSource? active = null;
        bool closed = false;
        dialog.Closed += (_, _) => { closed = true; active?.Cancel(); auth.Clear(); privacy.Clear(); };
        close.Click += (_, _) => dialog.Close();
        run.Click += async (_, _) =>
        {
            if (active is not null) return;
            using var cancellation = new CancellationTokenSource();
            active = cancellation;
            run.IsEnabled = user.IsEnabled = auth.IsEnabled = privacy.IsEnabled = false;
            close.Content = "Cancel / close";
            try
            {
                var username = user.Text;
                var authPhrase = auth.Password;
                var privacyPhrase = privacy.Password;
                auth.Clear(); privacy.Clear();
                output.Text = "Querying selected SNMPv3 agent…";
                var result = await Task.Run(() => SnmpInfrastructureSensor.CheckAsync(adapter, host.Address,
                    username, authPhrase, privacyPhrase, cancellation.Token), cancellation.Token);
                if (closed) return;
                var evi = result.Evidence;
                output.Text = $"{result.Status} | {result.Duration.TotalMilliseconds:0} ms\n" +
                    (evi is null ? "No authenticated inventory evidence.\n" :
                    $"Name: {evi.Name ?? "Not established"}\nDescription: {evi.Description ?? "Not established"}\n" +
                    $"Object ID: {evi.ObjectId ?? "Not established"}\nAgent uptime: {evi.UptimeCentiseconds?.ToString() ?? "Not established"} centiseconds\n" +
                    $"Interface count: {evi.InterfaceCount?.ToString() ?? "Not established"}\n") +
                    "\nAgent uptime is not necessarily device uptime. Reports, timeout and errors are not proof that credentials are wrong or the device is offline.";
            }
            catch (OperationCanceledException) { if (!closed) output.Text = "Check cancelled."; }
            catch (ArgumentException) { if (!closed) output.Text = "Invalid scope or credentials. Use ASCII user and 8–128 printable ASCII passphrases."; }
            catch (Exception) { if (!closed) output.Text = "SNMP check could not be completed."; }
            finally
            {
                active = null;
                if (!closed) { run.IsEnabled = user.IsEnabled = auth.IsEnabled = privacy.IsEnabled = true; close.Content = "Close"; }
            }
        };
        dialog.ShowDialog();
    }
}
