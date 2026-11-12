// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Carthago.Services;
using SharpPcap;

namespace Carthago;

public partial class MainWindow
{
    private CancellationTokenSource? _lanCaptureDiscovery;
    private bool _lanCaptureWindowClosed;

    private void CancelLanCaptureDiscovery()
    {
        _lanCaptureWindowClosed = true;
        _lanCaptureDiscovery?.Cancel();
    }

    private void AddLanCaptureTarget_Click(object sender, RoutedEventArgs e)
    {
        if (!DeviceComboBox.IsEnabled || StopButton.IsEnabled)
        {
            MessageBox.Show("Stop monitoring before adding a LAN host filter.", "Add LAN IP");
            return;
        }

        var selected = (DeviceComboBox.SelectedItem as ComboBoxItem)?.Tag;
        var device = selected is LanCaptureSelection host ? host.Device : selected as ILiveDevice;
        var id = CaptureDeviceLabelFormatter.ParseDeviceGuid(device?.Name);
        var localInterface = id.HasValue
            ? LocalLanDiscovery.GetLocalInterfaces(id.Value).FirstOrDefault()
            : null;
        if (device is null || !id.HasValue || localInterface is null)
        {
            MessageBox.Show("Select the Wi-Fi or Ethernet Npcap adapter for the phone's subnet first.",
                "Add LAN IP");
            return;
        }

        var address = PromptForLanAddress(localInterface);
        if (address is null) return;

        var existing = DeviceComboBox.Items.OfType<ComboBoxItem>()
            .FirstOrDefault(item => item.Tag is LanCaptureSelection target &&
                ReferenceEquals(target.Device, device) && target.Address.Equals(address));
        if (existing is not null)
        {
            DeviceComboBox.SelectedItem = existing;
            return;
        }

        var parent = DeviceComboBox.Items.OfType<ComboBoxItem>()
            .FirstOrDefault(item => ReferenceEquals(item.Tag, device));
        if (parent is null) return;
        var networkAdapter = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(adapter => Guid.TryParse(adapter.Id, out var guid) && guid == id.Value);
        var adapterName = networkAdapter?.Name ?? "selected adapter";
        var isGateway = networkAdapter?.GetIPProperties().GatewayAddresses
            .Any(gateway => gateway.Address.Equals(address)) == true;
        var peer = new LanCapturePeer(address, "Not observed", null,
            "Manually entered (presence not yet confirmed)");
        var item = new ComboBoxItem
        {
            Content = LanCaptureDiscovery.FormatLabel(peer, adapterName, isGateway),
            Tag = new LanCaptureSelection(device, address, localInterface),
            ToolTip = $"Known local IPv4: {address}\nPresence has not yet been confirmed. " +
                "Starting capture sends one ARP presence check. Only traffic that reaches this PC can appear."
        };
        var index = DeviceComboBox.Items.IndexOf(parent) + 1;
        while (index < DeviceComboBox.Items.Count &&
               DeviceComboBox.Items[index] is ComboBoxItem next &&
               next.Tag is LanCaptureSelection target && ReferenceEquals(target.Device, device))
            index++;
        DeviceComboBox.Items.Insert(index, item);
        DeviceComboBox.SelectedItem = item;
        DeviceComboBox.IsDropDownOpen = true;
    }

    private System.Net.IPAddress? PromptForLanAddress(LocalLanInterface adapter)
    {
        var dialog = new Window
        {
            Owner = this,
            Title = "Add known LAN IP",
            Width = 430,
            Height = 225,
            ResizeMode = ResizeMode.NoResize,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ShowInTaskbar = false
        };
        var panel = new StackPanel { Margin = new Thickness(20) };
        panel.Children.Add(new TextBlock
        {
            Text = $"Add a sleeping or quiet device on {adapter.Name} ({adapter.Address}).",
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 10)
        });
        var bytes = adapter.Address.GetAddressBytes();
        var input = new TextBox
        {
            Text = $"{bytes[0]}.{bytes[1]}.{bytes[2]}.",
            Height = 30,
            Padding = new Thickness(7, 4, 7, 4)
        };
        panel.Children.Add(input);
        var validation = new TextBlock
        {
            Text = "The address must be inside the selected adapter's local subnet.",
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 7, 0, 12)
        };
        panel.Children.Add(validation);
        var actions = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right
        };
        var cancel = new Button { Content = "Cancel", Width = 82, Height = 28, Margin = new Thickness(0, 0, 8, 0) };
        var add = new Button { Content = "Add host", Width = 92, Height = 28, IsDefault = true };
        cancel.IsCancel = true;
        cancel.Click += (_, _) => dialog.DialogResult = false;
        System.Net.IPAddress? result = null;
        add.Click += (_, _) =>
        {
            if (!LanCaptureDiscovery.TryParseManualTarget(input.Text, adapter,
                    out var parsed, out var error))
            {
                validation.Text = error;
                validation.Foreground = System.Windows.Media.Brushes.IndianRed;
                input.Focus();
                return;
            }
            result = parsed;
            dialog.DialogResult = true;
        };
        actions.Children.Add(cancel);
        actions.Children.Add(add);
        panel.Children.Add(actions);
        dialog.Content = panel;
        dialog.Loaded += (_, _) =>
        {
            input.Focus();
            input.CaretIndex = input.Text.Length;
        };
        return dialog.ShowDialog() == true ? result : null;
    }

    private async void DiscoverLanCapture_Click(object sender, RoutedEventArgs e)
    {
        if (_lanCaptureDiscovery is not null || _lanCaptureWindowClosed)
            return;
        if (!DeviceComboBox.IsEnabled || StopButton.IsEnabled)
        {
            MessageBox.Show("Stop monitoring before discovering LAN host filters.", "LAN discovery");
            return;
        }

        var selected = (DeviceComboBox.SelectedItem as ComboBoxItem)?.Tag;
        var device = selected switch
        {
            LanCaptureSelection host => host.Device,
            ILiveDevice adapter => adapter,
            _ => null
        };
        var id = CaptureDeviceLabelFormatter.ParseDeviceGuid(device?.Name);
        if (device is null || !id.HasValue)
        {
            MessageBox.Show("Select your Wi-Fi or Ethernet Npcap adapter first.", "LAN discovery");
            return;
        }

        using var cts = new CancellationTokenSource();
        _lanCaptureDiscovery = cts;
        DiscoverLanCaptureButton.IsEnabled = false;
        AddLanCaptureTargetButton.IsEnabled = false;
        DiscoverLanCaptureButton.Content = "Discovering...";
        try
        {
            var peers = await Task.Run(
                () => LanCaptureDiscovery.DiscoverAsync(device, id.Value, cts.Token), cts.Token);
            if (_lanCaptureWindowClosed || cts.IsCancellationRequested ||
                !DeviceComboBox.IsEnabled || StopButton.IsEnabled)
                return;

            // A user may switch interfaces while the scan runs. Never apply a
            // previous interface's results to a newly selected adapter.
            var current = (DeviceComboBox.SelectedItem as ComboBoxItem)?.Tag;
            var currentDevice = current is LanCaptureSelection scoped ? scoped.Device : current as ILiveDevice;
            if (!ReferenceEquals(currentDevice, device))
                return;

            var parent = DeviceComboBox.Items.OfType<ComboBoxItem>()
                .FirstOrDefault(item => ReferenceEquals(item.Tag, device));
            if (parent is null) return;
            var priorAddress = (current as LanCaptureSelection)?.Address;
            foreach (var stale in DeviceComboBox.Items.OfType<ComboBoxItem>()
                .Where(item => item.Tag is LanCaptureSelection host && ReferenceEquals(host.Device, device)).ToArray())
                DeviceComboBox.Items.Remove(stale);

            var networkAdapter = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(adapter => Guid.TryParse(adapter.Id, out var guid) && guid == id.Value);
            var adapterName = networkAdapter?.Name ?? "selected adapter";
            var gatewayAddresses = networkAdapter?.GetIPProperties().GatewayAddresses
                .Select(gateway => gateway.Address)
                .Where(address => address.AddressFamily == AddressFamily.InterNetwork)
                .ToArray() ?? Array.Empty<System.Net.IPAddress>();
            var localInterface = LocalLanDiscovery.GetLocalInterfaces(id.Value).FirstOrDefault();
            var index = DeviceComboBox.Items.IndexOf(parent) + 1;
            ComboBoxItem? restored = null;
            foreach (var peer in peers)
            {
                var item = new ComboBoxItem
                {
                    Content = LanCaptureDiscovery.FormatLabel(peer, adapterName,
                        gatewayAddresses.Any(address => address.Equals(peer.Address))),
                    Tag = new LanCaptureSelection(device, peer.Address, localInterface),
                    ToolTip = $"{peer.Evidence}\nMAC: {peer.Mac}\nIPv4: {peer.Address}\n" +
                        "Hostnames and cached neighbors are not proof of identity or current presence. " +
                        "This is a host filter, not a remote capture source. It can show only packets for this IP " +
                        "that are already visible to the selected adapter."
                };
                DeviceComboBox.Items.Insert(index++, item);
                if (peer.Address.Equals(priorAddress)) restored = item;
            }

            DeviceComboBox.SelectedItem = restored ?? parent;
            if (peers.Count == 0)
                MessageBox.Show("No local IPv4 peers answered direct ARP requests on the selected adapter. " +
                    "Check that the phone is awake and on the same Wi-Fi, and compare its IPv4 address with the PC subnet. " +
                    "Client isolation or a VPN may prevent discovery.", "LAN discovery");
            else
                DeviceComboBox.IsDropDownOpen = true;
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (!_lanCaptureWindowClosed)
                MessageBox.Show($"LAN discovery failed: {ex.Message}", "LAN discovery");
        }
        finally
        {
            _lanCaptureDiscovery = null;
            if (!_lanCaptureWindowClosed)
            {
                DiscoverLanCaptureButton.Content = "Scan LAN";
                DiscoverLanCaptureButton.IsEnabled = true;
                AddLanCaptureTargetButton.IsEnabled = true;
            }
        }
    }
}
