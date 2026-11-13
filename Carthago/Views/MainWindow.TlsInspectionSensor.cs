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
    private void CheckLanTlsInspection_Click(object sender, RoutedEventArgs e)
    {
        if (StopButton.IsEnabled || !DeviceComboBox.IsEnabled || _lanCaptureDiscovery is not null)
        {
            MessageBox.Show(this, "Stop monitoring and finish LAN discovery before TLS inspection.", "Active sensor");
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
        var dialog = new Window { Owner = this, Title = "Active sensor — TLS inspection", Width = 660, Height = 550,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, ShowInTaskbar = false };
        var panel = new DockPanel { Margin = new Thickness(16) };
        var inputs = new StackPanel();
        inputs.Children.Add(new TextBlock { Text = $"Target: {host.Address} via {adapter.Name} ({adapter.Address})\n" +
            "One authorized TLS handshake; enter the expected DNS identity (SNI). No application data or credentials. " +
            "Invalid certificates are rejected and their observed evidence displayed. Revocation is not checked.",
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) });
        inputs.Children.Add(new TextBlock { Text = "Direct TLS port" });
        var port = new ComboBox { ItemsSource = TlsInspectionSensor.AllowedPorts, SelectedIndex = 0, Margin = new Thickness(0, 4, 0, 10) };
        inputs.Children.Add(port);
        inputs.Children.Add(new TextBlock { Text = "Expected DNS hostname (ASCII / punycode)" });
        var name = new TextBox { MaxLength = 254, Margin = new Thickness(0, 4, 0, 10) };
        inputs.Children.Add(name);
        inputs.Children.Add(new TextBlock { Text = "Expected certificate SHA-256 (optional, 64 hex characters)" });
        var hash = new TextBox { MaxLength = 64, Margin = new Thickness(0, 4, 0, 12) };
        inputs.Children.Add(hash);
        DockPanel.SetDock(inputs, Dock.Top);
        panel.Children.Add(inputs);
        var actions = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var run = new Button { Content = "Run authorized inspection", Padding = new Thickness(10, 5, 10, 5), Margin = new Thickness(0, 0, 8, 0) };
        var close = new Button { Content = "Close", Padding = new Thickness(10, 5, 10, 5) };
        actions.Children.Add(run); actions.Children.Add(close);
        DockPanel.SetDock(actions, Dock.Bottom); panel.Children.Add(actions);
        var output = new TextBox { IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(0, 0, 0, 12),
            Text = "No handshake attempted." };
        var saveHistory = AddActiveEvidenceOptIn(panel);
        panel.Children.Add(output); dialog.Content = panel;
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
        dialog.Closed += (_, _) => { closed = true; active?.Cancel(); };
        close.Click += (_, _) => dialog.Close();
        run.Click += async (_, _) =>
        {
            if (active is not null) return;
            bool persist = saveHistory.IsChecked == true;
            saveHistory.IsEnabled = false;
            using var cancellation = new CancellationTokenSource();
            active = cancellation;
            run.IsEnabled = port.IsEnabled = name.IsEnabled = hash.IsEnabled = false;
            close.Content = "Cancel / close";
            try
            {
                output.Text = "Inspecting selected TLS endpoint…";
                var result = await TlsInspectionSensor.CheckAsync(adapter, host.Address, (int)port.SelectedItem,
                    name.Text, hash.Text, cancellation.Token);
                if (closed) return;
                var cert = result.Certificate;
                output.Text = $"{result.Status} | {result.HostName} | {result.Duration.TotalMilliseconds:0} ms\n" +
                    $"TLS: {result.Protocol ?? "Not established"} | Cipher: {result.CipherSuite ?? "Not established"}\n" +
                    (cert is null ? "No certificate evidence.\n" :
                    $"Subject: {cert.Subject}\nIssuer: {cert.Issuer}\nSerial: {cert.SerialNumber}\n" +
                    $"SHA-256: {cert.Sha256}\nDNS SAN: {cert.DnsNames ?? "Not established"} ({cert.DnsNameEvidence})\n" +
                    $"Validity: {cert.Validity} | {cert.NotBeforeUtc:u} to {cert.NotAfterUtc:u}\n" +
                    $"Days until expiry at observation: {(cert.NotAfterUtc - result.ObservedUtc).TotalDays:0.0}\n" +
                    $"Platform policy: {cert.PolicyErrors}\nChain flags: {string.Join(", ", cert.ChainErrors)}\n" +
                    $"Expected fingerprint: {(cert.FingerprintMatches.HasValue ? cert.FingerprintMatches.Value ? "Match" : "Difference" : "Not configured")}\n") +
                    "\nRevocation not checked. Fingerprint differences and untrusted certificates are not proof of compromise.";
                if (persist && !closed && !closeRequested && !cancellation.IsCancellationRequested)
                {
                    var saved = await SaveActiveEvidenceAsync(() => ActiveEvidenceProjection.From(id!.Value, result));
                    if (!closed) output.Text += saved;
                }
            }
            catch (OperationCanceledException) { if (!closed) output.Text = "Inspection cancelled."; }
            catch (Exception ex) { if (!closed) output.Text = "Inspection not completed: " + ex.Message; }
            finally
            {
                active = null;
                if (closeRequested) dialog.Close();
                if (!closed) saveHistory.IsEnabled = true;
                if (!closed) { run.IsEnabled = port.IsEnabled = name.IsEnabled = hash.IsEnabled = true; close.Content = "Close"; }
            }
        };
        dialog.ShowDialog();
    }
}
