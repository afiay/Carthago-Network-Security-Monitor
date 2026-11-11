// SPDX-License-Identifier: MIT
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;

namespace Carthago.Services
{
    public sealed record LocalLanInterface(string Name, IPAddress Address, IPAddress Mask);
    public sealed record LocalLanDeviceRow(string Address, string Mac, string State, string Evidence);
    public sealed record LocalLanScanResult(
        IReadOnlyDictionary<string, string> NeighborMacs,
        IReadOnlyCollection<string> PingReplies,
        int TargetsProbed);

    /// <summary>
    /// Separate from the packet capture source picker. Read-only local neighbor
    /// cache by default; bounded, opt-in ICMP discovery of private IPv4 peers.
    /// Neither cached neighbors nor silence establish a host's live state.
    /// </summary>
    public static class LocalLanDiscovery
    {
        private static readonly Regex ArpLine = new(
            @"(?<![\d.])(?<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<mac>(?:[0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2})\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        public static bool IsLocalHostAddress(IPAddress? ip)
        {
            if (ip is null || IPAddress.IsLoopback(ip))
                return false;
            if (ip.IsIPv4MappedToIPv6)
                ip = ip.MapToIPv4();
            var b = ip.GetAddressBytes();
            if (ip.AddressFamily == AddressFamily.InterNetwork)
                return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                    (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254);
            return ip.AddressFamily == AddressFamily.InterNetworkV6 &&
                !ip.IsIPv6Multicast && (ip.IsIPv6LinkLocal || (b[0] & 0xfe) == 0xfc);
        }

        public static IReadOnlyList<LocalLanInterface> GetLocalInterfaces()
        {
            var result = new List<LocalLanInterface>();
            foreach (var network in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (network.OperationalStatus != OperationalStatus.Up ||
                    network.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                    continue;

                foreach (var address in network.GetIPProperties().UnicastAddresses)
                {
                    if (address.Address.AddressFamily != AddressFamily.InterNetwork ||
                        address.IPv4Mask is null || !IsLocalHostAddress(address.Address))
                        continue;
                    result.Add(new LocalLanInterface(network.Name, address.Address, address.IPv4Mask));
                }
            }
            return result;
        }

        public static IReadOnlyList<IPAddress> PlanProbeTargets(
            IEnumerable<LocalLanInterface> interfaces, int maximum = 512)
        {
            if (interfaces is null) throw new ArgumentNullException(nameof(interfaces));
            if (maximum <= 0) throw new ArgumentOutOfRangeException(nameof(maximum));

            var targets = new Dictionary<uint, IPAddress>();
            foreach (var adapter in interfaces)
            {
                if (adapter.Address.AddressFamily != AddressFamily.InterNetwork ||
                    adapter.Mask.AddressFamily != AddressFamily.InterNetwork ||
                    !IsLocalHostAddress(adapter.Address))
                    continue;

                var own = ToUInt32(adapter.Address);
                var mask = ToUInt32(adapter.Mask);
                var subnet = own & mask;
                var local24 = own & 0xffffff00u;

                // Even on /16 networks, only probe the current local /24,
                // intersected with the actual interface subnet.
                for (uint offset = 1; offset <= 254 && targets.Count < maximum; offset++)
                {
                    var candidate = local24 | offset;
                    if (candidate == own || (candidate & mask) != subnet)
                        continue;
                    var ip = FromUInt32(candidate);
                    if (IsLocalHostAddress(ip))
                        targets.TryAdd(candidate, ip);
                }
                if (targets.Count >= maximum) break;
            }
            return targets.Values.ToArray();
        }

        public static IReadOnlyList<LocalLanDeviceRow> Merge(
            IEnumerable<TrafficRecord> recentTraffic,
            IReadOnlyDictionary<string, string>? neighborMacs,
            IEnumerable<string>? pingReplies)
        {
            if (recentTraffic is null) throw new ArgumentNullException(nameof(recentTraffic));
            var hosts = new Dictionary<string, HostEvidence>(StringComparer.OrdinalIgnoreCase);
            void Add(string? value, string? mac, bool observed, bool neighbor, bool ping)
            {
                if (!IPAddress.TryParse(value, out var ip) || !IsLocalHostAddress(ip))
                    return;
                var address = ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString();
                if (!hosts.TryGetValue(address, out var item))
                    hosts[address] = item = new HostEvidence();
                item.Observed |= observed;
                item.Neighbor |= neighbor;
                item.Replied |= ping;
                if (string.IsNullOrWhiteSpace(item.Mac) && !string.IsNullOrWhiteSpace(mac))
                    item.Mac = mac.Trim();
            }

            foreach (var record in recentTraffic)
            {
                if (record is null) continue;
                Add(record.Source, record.MacSource, true, false, false);
                Add(record.Destination, record.MacDestination, true, false, false);
            }

            if (neighborMacs is not null)
                foreach (var neighbor in neighborMacs)
                    Add(neighbor.Key, neighbor.Value, false, true, false);

            if (pingReplies is not null)
                foreach (var address in pingReplies)
                    Add(address, null, false, false, true);

            return hosts.Select(pair =>
                new LocalLanDeviceRow(pair.Key,
                    string.IsNullOrWhiteSpace(pair.Value.Mac) ? "Not recorded" : pair.Value.Mac,
                    pair.Value.Replied ? "Responded to ICMP" :
                        pair.Value.Observed ? "Traffic observed" : "Cached neighbor (unconfirmed)",
                    string.Join(" + ", new[]
                    {
                        pair.Value.Observed ? "Captured packets" : null,
                        pair.Value.Neighbor ? "Windows neighbor cache" : null,
                        pair.Value.Replied ? "ICMP echo reply" : null
                    }.Where(s => s is not null))))
                .OrderByDescending(row => row.State == "Responded to ICMP")
                .ThenByDescending(row => row.State == "Traffic observed")
                .ThenBy(row => IPAddress.Parse(row.Address).GetAddressBytes().Length)
                .ThenBy(row => row.Address, StringComparer.OrdinalIgnoreCase)
                .Take(512)
                .ToArray();
        }

        public static async Task<LocalLanScanResult> ScanAsync(bool sendIcmp, CancellationToken token = default)
        {
            var interfaces = GetLocalInterfaces();
            var targets = PlanProbeTargets(interfaces);
            var responses = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);

            if (sendIcmp)
            {
                using var semaphore = new SemaphoreSlim(24);
                var jobs = targets.Select(async ip =>
                {
                    await semaphore.WaitAsync(token).ConfigureAwait(false);
                    try
                    {
                        using var ping = new Ping();
                        try
                        {
                            var reply = await ping.SendPingAsync(ip, 400).ConfigureAwait(false);
                            if (reply.Status == IPStatus.Success)
                                responses.TryAdd(ip.ToString(), 0);
                        }
                        catch (PingException) { /* Peer cannot answer ICMP. */ }
                    }
                    finally { semaphore.Release(); }
                });
                await Task.WhenAll(jobs).ConfigureAwait(false);
            }

            token.ThrowIfCancellationRequested();
            var neighbors = await ReadNeighborCacheAsync(token).ConfigureAwait(false);
            var permitted = new HashSet<string>(targets.Select(ip => ip.ToString()), StringComparer.OrdinalIgnoreCase);
            foreach (var adapter in interfaces)
                permitted.Add(adapter.Address.ToString());
            return new LocalLanScanResult(
                neighbors.Where(pair => permitted.Contains(pair.Key))
                    .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase),
                responses.Keys.ToArray(), sendIcmp ? targets.Count : 0);
        }

        public static IReadOnlyDictionary<string, string> ParseArpOutput(string? content)
        {
            var found = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(content))
                return found;
            foreach (Match match in ArpLine.Matches(content))
            {
                if (!IPAddress.TryParse(match.Groups["ip"].Value, out var ip) ||
                    !IsLocalHostAddress(ip))
                    continue;
                var mac = match.Groups["mac"].Value.Replace('-', ':').ToUpperInvariant();
                // Exclude layer-2 broadcast and multicast entries, not physical hosts.
                if (mac == "FF:FF:FF:FF:FF:FF" ||
                    (Convert.ToByte(mac[..2], 16) & 1) != 0)
                    continue;
                found[ip.ToString()] = mac;
            }
            return found;
        }

        private static async Task<IReadOnlyDictionary<string, string>> ReadNeighborCacheAsync(CancellationToken token)
        {
            try
            {
                using var process = new Process
                {
                    StartInfo = new ProcessStartInfo("arp.exe", "-a")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = false
                    }
                };
                if (!process.Start())
                    return new Dictionary<string, string>();

                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                timeout.CancelAfter(TimeSpan.FromSeconds(6));
                try
                {
                    var output = process.StandardOutput.ReadToEndAsync(timeout.Token);
                    await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
                    return ParseArpOutput(await output.ConfigureAwait(false));
                }
                catch (OperationCanceledException)
                {
                    if (!process.HasExited)
                        process.Kill(entireProcessTree: true);
                    token.ThrowIfCancellationRequested();
                    return new Dictionary<string, string>();
                }
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
            {
                return new Dictionary<string, string>();
            }
        }

        private static uint ToUInt32(IPAddress ip)
        {
            var b = ip.GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }

        private static IPAddress FromUInt32(uint value) => new(new byte[]
        {
            (byte)(value >> 24), (byte)(value >> 16),
            (byte)(value >> 8), (byte)value
        });

        private sealed class HostEvidence
        {
            public string Mac = "";
            public bool Observed;
            public bool Neighbor;
            public bool Replied;
        }
    }
}
