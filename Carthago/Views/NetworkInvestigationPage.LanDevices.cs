// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Views
{
    public partial class NetworkInvestigationPage
    {
        private TrafficRecord[] _lanRecentTraffic = Array.Empty<TrafficRecord>();
        private IReadOnlyDictionary<string, string> _lanNeighborMacs = new Dictionary<string, string>();
        private IReadOnlyCollection<string> _lanPingReplies = Array.Empty<string>();
        private CancellationTokenSource? _lanLookup;
        private DateTime _lanLastRefreshUtc;

        private void UpdateLanSnapshot(TrafficRecord[] traffic)
        {
            _lanRecentTraffic = traffic;
            RenderLanDevices();

            // No network probes on navigation. Read the ARP cache in the
            // background at most once every 45 seconds.
            if (_lanLookup is null &&
                DateTime.UtcNow - _lanLastRefreshUtc > TimeSpan.FromSeconds(45))
                _ = RefreshLanDevicesAsync(sendIcmp: false);
        }

        private void RenderLanDevices()
        {
            var rows = LocalLanDiscovery.Merge(_lanRecentTraffic, _lanNeighborMacs, _lanPingReplies);
            LanDevicesGrid.ItemsSource = rows;
            LanDeviceStatusText.Text =
                $"{rows.Count} locally identified IP(s). " +
                "Neighbor-cache entries may be stale; no scan can guarantee every device " +
                "(sleeping hosts, blocked ICMP, VLANs, or Wi-Fi client isolation).";
        }

        private async Task RefreshLanDevicesAsync(bool sendIcmp)
        {
            if (_lanLookup is not null)
                return;

            using var cts = new CancellationTokenSource();
            _lanLookup = cts;
            LanDiscoverButton.IsEnabled = false;
            LanRefreshButton.IsEnabled = false;
            LanDeviceStatusText.Text = sendIcmp
                ? "Discovering local private IPv4 peers (up to 512 ICMP probes)..."
                : "Reading Windows neighbor cache without sending probes...";

            try
            {
                var result = await LocalLanDiscovery.ScanAsync(sendIcmp, cts.Token);
                if (cts.IsCancellationRequested)
                    return;

                _lanNeighborMacs = result.NeighborMacs;
                if (sendIcmp)
                    _lanPingReplies = result.PingReplies;
                _lanLastRefreshUtc = DateTime.UtcNow;
                RenderLanDevices();
                if (sendIcmp)
                    LanDeviceStatusText.Text += $" Probed {result.TargetsProbed} local IPv4 addresses.";
            }
            catch (OperationCanceledException)
            {
                LanDeviceStatusText.Text = "LAN discovery canceled.";
            }
            catch (Exception ex)
            {
                LanDeviceStatusText.Text = $"LAN discovery failed: {ex.Message}. Captured records remain available.";
            }
            finally
            {
                if (ReferenceEquals(_lanLookup, cts))
                    _lanLookup = null;
                LanDiscoverButton.IsEnabled = true;
                LanRefreshButton.IsEnabled = true;
            }
        }

        private async void LanDiscover_Click(object sender, RoutedEventArgs e)
            => await RefreshLanDevicesAsync(sendIcmp: true);

        private async void LanRefresh_Click(object sender, RoutedEventArgs e)
            => await RefreshLanDevicesAsync(sendIcmp: false);
    }
}
