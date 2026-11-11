// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Net.NetworkInformation;
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

    private async void DiscoverLanCapture_Click(object sender, RoutedEventArgs e)
    {
        if (_lanCaptureDiscovery is not null || _lanCaptureWindowClosed)
            return;
        if (!DeviceComboBox.IsEnabled || StopButton.IsEnabled)
        {
            MessageBox.Show("Stop monitoring before discovering LAN capture targets.", "LAN discovery");
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
        DiscoverLanCaptureButton.Content = "Discovering...";
        try
        {
            var peers = await Task.Run(() => LanCaptureDiscovery.DiscoverAsync(id.Value, cts.Token), cts.Token);
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

            var adapterName = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(adapter => Guid.TryParse(adapter.Id, out var guid) && guid == id.Value)?.Name
                ?? "selected adapter";
            var index = DeviceComboBox.Items.IndexOf(parent) + 1;
            ComboBoxItem? restored = null;
            foreach (var peer in peers)
            {
                var item = new ComboBoxItem
                {
                    Content = LanCaptureDiscovery.FormatLabel(peer, adapterName),
                    Tag = new LanCaptureSelection(device, peer.Address),
                    ToolTip = $"{peer.Evidence}\nMAC: {peer.Mac}\nIPv4: {peer.Address}\n" +
                        "Hostnames and cached neighbors are not proof of identity or current presence. " +
                        "Capture is limited to this IP and packets visible to the selected adapter."
                };
                DeviceComboBox.Items.Insert(index++, item);
                if (peer.Address.Equals(priorAddress)) restored = item;
            }

            DeviceComboBox.SelectedItem = restored ?? parent;
            if (peers.Count == 0)
                MessageBox.Show("No LAN peers found on this adapter. Check the phone's Wi-Fi connection or client isolation.", "LAN discovery");
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
                DiscoverLanCaptureButton.Content = "Discover LAN";
                DiscoverLanCaptureButton.IsEnabled = true;
            }
        }
    }
}
