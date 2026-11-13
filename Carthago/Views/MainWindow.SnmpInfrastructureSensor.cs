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
        var dialog = new Window { Owner = this, Title = "Active sensor — SNMPv3 infrastructure", Width = 720, Height = 690,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, ShowInTaskbar = false };
        var panel = new DockPanel { Margin = new Thickness(16) };
        var inputs = new StackPanel();
        inputs.Children.Add(new TextBlock { Text = $"Agent: {host.Address}:161 UDP via {adapter.Name} ({adapter.Address})\n" +
            "SNMPv3 authPriv, SHA-256 / AES-128, read-only GET. Use an authorized read-only account. " +
            "Credentials are never displayed in results. Optional current-user encrypted vault; no fallback to older SNMP versions.",
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) });
        inputs.Children.Add(new TextBlock { Text = "SNMPv3 user" });
        var user = new TextBox { MaxLength = 32, Margin = new Thickness(0, 4, 0, 10) }; inputs.Children.Add(user);
        inputs.Children.Add(new TextBlock { Text = "Authentication passphrase" });
        var auth = new PasswordBox { MaxLength = 128, Margin = new Thickness(0, 4, 0, 10) }; inputs.Children.Add(auth);
        inputs.Children.Add(new TextBlock { Text = "Privacy passphrase" });
        var privacy = new PasswordBox { MaxLength = 128, Margin = new Thickness(0, 4, 0, 12) }; inputs.Children.Add(privacy);
        var vault = new SnmpCredentialVault();
        var scope = SnmpCredentialScope.Create(id!.Value, adapter, host.Address);
        var vaultStatus = new TextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 6) };
        var useStored = new CheckBox { Content = "Use saved credential for this authorized GET", Margin = new Thickness(0, 0, 0, 8) };
        var vaultActions = new WrapPanel();
        var remember = new Button { Content = "Save / replace encrypted credential", Margin = new Thickness(0, 0, 8, 6) };
        var forget = new Button { Content = "Delete saved credential", Margin = new Thickness(0, 0, 8, 6) };
        vaultActions.Children.Add(remember); vaultActions.Children.Add(forget);
        inputs.Children.Add(vaultStatus); inputs.Children.Add(useStored); inputs.Children.Add(vaultActions);
        void RefreshVault()
        {
            var present = vault.GetGeneration(scope).HasValue;
            vaultStatus.Text = present ? "Saved encrypted credential record present (decryption not checked)." :
                "No available saved credential record.";
            useStored.IsEnabled = present;
            if (!present) useStored.IsChecked = false;
        }
        bool CurrentScope() => LocalLanDiscovery.GetLocalInterfaces(id.Value).Any(a =>
            a.Address.Equals(adapter.Address) && a.Mask.Equals(adapter.Mask) &&
            LocalLanDiscovery.PlanProbeTargets(new[] { a }).Contains(host.Address));
        RefreshVault();
        DockPanel.SetDock(inputs, Dock.Top); panel.Children.Add(inputs);
        var actions = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var run = new Button { Content = "Run authorized GET", Padding = new Thickness(10, 5, 10, 5), Margin = new Thickness(0, 0, 8, 0) };
        var close = new Button { Content = "Close", Padding = new Thickness(10, 5, 10, 5) };
        actions.Children.Add(run); actions.Children.Add(close);
        DockPanel.SetDock(actions, Dock.Bottom); panel.Children.Add(actions);
        var output = new TextBox { IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(0, 0, 0, 12), Text = "No request sent." };
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
        dialog.Closed += (_, _) => { closed = true; active?.Cancel(); auth.Clear(); privacy.Clear(); };
        close.Click += (_, _) => dialog.Close();
        remember.Click += (_, _) =>
        {
            if (active is not null) return;
            try
            {
                if (!CurrentScope()) { output.Text = "Network scope changed; select the agent again."; return; }
                var secret = new SnmpCredential(user.Text, auth.Password, privacy.Password);
                if (MessageBox.Show(dialog, "Save or replace this credential encrypted for the current Windows user and exact selected agent? " +
                    "This does not authorize unattended monitoring.", "SNMP credential vault",
                    MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
                output.Text = vault.Save(scope, secret).HasValue ? "Encrypted credential saved. No network request sent." :
                    "Credential storage unavailable or full.";
                RefreshVault();
            }
            catch (ArgumentException) { output.Text = "Invalid scope or credentials."; }
            catch (Exception ex) when (ex is not OutOfMemoryException) { output.Text = "Credential storage unavailable."; }
            finally { auth.Clear(); privacy.Clear(); user.Clear(); }
        };
        forget.Click += (_, _) =>
        {
            if (active is not null) return;
            if (MessageBox.Show(dialog, "Delete the stored credential for this exact agent?", "SNMP credential vault",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
            output.Text = vault.Delete(scope) ? "Saved credential removed." : "No credential removed or storage unavailable.";
            RefreshVault();
        };
        run.Click += async (_, _) =>
        {
            if (active is not null) return;
            bool persist = saveHistory.IsChecked == true;
            saveHistory.IsEnabled = false;
            using var cancellation = new CancellationTokenSource();
            active = cancellation;
            run.IsEnabled = user.IsEnabled = auth.IsEnabled = privacy.IsEnabled = remember.IsEnabled = forget.IsEnabled = useStored.IsEnabled = false;
            close.Content = "Cancel / close";
            try
            {
                if (!CurrentScope()) { output.Text = "Network scope changed; select the agent again."; return; }
                var stored = useStored.IsChecked == true;
                SnmpCredential? secret;
                if (stored)
                {
                    var generation = vault.GetGeneration(scope);
                    secret = generation.HasValue ? vault.Load(scope, generation.Value) : null;
                    if (secret is null) { output.Text = "Saved credential unavailable; no request sent."; return; }
                }
                else secret = new SnmpCredential(user.Text, auth.Password, privacy.Password);
                auth.Clear(); privacy.Clear(); user.Clear();
                output.Text = "Querying selected SNMPv3 agent…";
                var result = await Task.Run(() => SnmpInfrastructureSensor.CheckAsync(adapter, host.Address,
                    secret.User, secret.Authentication, secret.Privacy, cancellation.Token), cancellation.Token);
                if (closed) return;
                var evi = result.Evidence;
                output.Text = $"{result.Status} | {result.Duration.TotalMilliseconds:0} ms\n" +
                    (evi is null ? "No authenticated inventory evidence.\n" :
                    $"Name: {evi.Name ?? "Not established"}\nDescription: {evi.Description ?? "Not established"}\n" +
                    $"Object ID: {evi.ObjectId ?? "Not established"}\nAgent uptime: {evi.UptimeCentiseconds?.ToString() ?? "Not established"} centiseconds\n" +
                    $"Interface count: {evi.InterfaceCount?.ToString() ?? "Not established"}\n") +
                    "\nAgent uptime is not necessarily device uptime. Reports, timeout and errors are not proof that credentials are wrong or the device is offline.";
                if (persist && !closed && !closeRequested && !cancellation.IsCancellationRequested)
                {
                    var saved = await SaveActiveEvidenceAsync(() => ActiveEvidenceProjection.From(id!.Value, result));
                    if (!closed) output.Text += saved;
                }
            }
            catch (OperationCanceledException) { if (!closed) output.Text = "Check cancelled."; }
            catch (ArgumentException) { if (!closed) output.Text = "Invalid scope or credentials. Use ASCII user and 8–128 printable ASCII passphrases."; }
            catch (Exception) { if (!closed) output.Text = "SNMP check could not be completed."; }
            finally
            {
                auth.Clear(); privacy.Clear(); user.Clear();
                active = null;
                if (closeRequested) dialog.Close();
                if (!closed) saveHistory.IsEnabled = true;
                if (!closed) { run.IsEnabled = user.IsEnabled = auth.IsEnabled = privacy.IsEnabled = remember.IsEnabled = forget.IsEnabled = true; RefreshVault(); close.Content = "Close"; }
            }
        };
        dialog.ShowDialog();
    }
}
