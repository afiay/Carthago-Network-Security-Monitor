// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using SharpPcap;

namespace Carthago.Services;

public sealed record LanCaptureSelection(
    ILiveDevice Device,
    IPAddress Address,
    LocalLanInterface? LocalInterface = null);

public sealed record LanCapturePeer(IPAddress Address, string Mac, string? HostName, string Evidence);

public static class LanCaptureDiscovery
{
    // BPF host selection applies only to packets visible to the local adapter.
    // A host-scoped capture must never fall back to an unfiltered capture.
    public static string ComposeFilter(string? existingFilter, IPAddress? address)
    {
        var configured = existingFilter?.Trim() ?? string.Empty;
        if (address is null)
            return configured;
        if (address.AddressFamily != AddressFamily.InterNetwork ||
            !LocalLanDiscovery.IsLocalHostAddress(address))
            throw new ArgumentException("LAN capture requires a local IPv4 address.", nameof(address));

        // ARP is the one peer-presence protocol a normal switched LAN still
        // exposes to the local adapter. Include it without implying that the
        // adapter can see the peer's separate routed Internet traffic.
        var hostFilter = $"(ip host {address}) or (arp host {address})";
        return configured.Length == 0 ? hostFilter : $"({configured}) and ({hostFilter})";
    }

    public static string FormatLabel(LanCapturePeer peer, string adapterName, bool isGateway = false)
    {
        var name = NormalizeHostName(peer.HostName);
        var host = name is null ? peer.Address.ToString() : $"{name} ({peer.Address})";
        var role = isGateway ? "gateway" : "host";
        return $"LAN {role} filter: {host} · {adapterName} · visible-to-PC";
    }

    public static string FormatVisibilityNotice(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        return $"{address} is a discovered host, not a remote sensor. " +
            $"This filter can capture only packets involving {address} that reach this PC's selected adapter. " +
            "On normal switched Wi-Fi or Ethernet, phone-to-Internet traffic travels between the phone and router " +
            "and is not delivered to this PC.\n\n" +
            "For full phone-to-Internet capture, run Carthago on the gateway or hotspot path, use an authorized " +
            "switch/router mirror port, or place an approved sensor on that path.";
    }

    public static bool TryParseManualTarget(
        string? value,
        LocalLanInterface adapter,
        out IPAddress? address,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        address = null;
        error = null;
        var text = value?.Trim() ?? string.Empty;
        var parts = text.Split('.', StringSplitOptions.None);
        if (parts.Length != 4 || parts.Any(part =>
                !byte.TryParse(part, out _)))
        {
            error = "Enter a complete dotted IPv4 address, for example 192.168.1.123.";
            return false;
        }

        address = new IPAddress(parts.Select(byte.Parse).ToArray());
        if (!LocalLanDiscovery.PlanProbeTargets(new[] { adapter }).Contains(address))
        {
            address = null;
            error = $"The address must be another host in the selected adapter's local {adapter.Address} subnet.";
            return false;
        }

        return true;
    }

    public static string? NormalizeHostName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var cleaned = new string(value.Where(c => !char.IsControl(c)).ToArray()).Trim().TrimEnd('.');
        if (cleaned.Length == 0 || IPAddress.TryParse(cleaned, out _)) return null;
        return cleaned.Length > 80 ? cleaned[..80] : cleaned;
    }

    public static IReadOnlyList<LanCapturePeer> BuildPeers(LocalLanScanResult scan)
    {
        // Scoped neighbor-cache entries are the actual link-layer evidence;
        // do not invent a peer from a routed ICMP reply alone.
        var replies = new HashSet<string>(scan.PingReplies, StringComparer.OrdinalIgnoreCase);
        var arpReplies = new HashSet<string>(scan.ArpReplies, StringComparer.OrdinalIgnoreCase);
        var result = new List<LanCapturePeer>();
        foreach (var entry in scan.NeighborMacs)
        {
            if (!IPAddress.TryParse(entry.Key, out var address) ||
                address.AddressFamily != AddressFamily.InterNetwork ||
                !LocalLanDiscovery.IsLocalHostAddress(address))
                continue;
            var directArp = arpReplies.Contains(entry.Key);
            var pingReply = replies.Contains(entry.Key);
            var evidence = directArp
                ? pingReply ? "Direct ARP response + ICMP reply" : "Direct ARP response"
                : pingReply ? "Neighbor cache + ICMP reply" : "Neighbor cache (unconfirmed)";
            result.Add(new LanCapturePeer(address, entry.Value, null, evidence));
        }
        return result.OrderBy(p => p.Address.ToString(), StringComparer.Ordinal).Take(512).ToArray();
    }

    public static async Task<IReadOnlyList<LanCapturePeer>> DiscoverAsync(Guid interfaceId, CancellationToken token)
    {
        var scan = await LocalLanDiscovery.ScanAsync(true, token, interfaceId).ConfigureAwait(false);
        return await BuildNamedPeersAsync(scan, token).ConfigureAwait(false);
    }

    public static async Task<IReadOnlyList<LanCapturePeer>> DiscoverAsync(
        ILiveDevice device, Guid interfaceId, CancellationToken token)
    {
        var adapter = LocalLanDiscovery.GetLocalInterfaces(interfaceId).FirstOrDefault()
            ?? throw new InvalidOperationException("The selected adapter has no active private IPv4 address.");
        var scan = await NpcapArpDiscovery.ScanAsync(device, adapter, token).ConfigureAwait(false);
        return await BuildNamedPeersAsync(scan, token).ConfigureAwait(false);
    }

    private static async Task<IReadOnlyList<LanCapturePeer>> BuildNamedPeersAsync(
        LocalLanScanResult scan, CancellationToken token)
    {
        var peers = BuildPeers(scan).ToArray();

        // Names are optional OS resolver evidence, not device identity.
        // Limit DNS work independently of the bounded local scan.
        using var slots = new SemaphoreSlim(8);
        var jobs = Enumerable.Range(0, Math.Min(peers.Length, 64)).Select(async index =>
        {
            await slots.WaitAsync(token).ConfigureAwait(false);
            try
            {
                using var budget = CancellationTokenSource.CreateLinkedTokenSource(token);
                budget.CancelAfter(TimeSpan.FromSeconds(1));
                try
                {
                    var entry = await Dns.GetHostEntryAsync(peers[index].Address.ToString(),
                        budget.Token).ConfigureAwait(false);
                    peers[index] = peers[index] with { HostName = NormalizeHostName(entry.HostName) };
                }
                catch (SocketException) { /* No name available. */ }
                catch (OperationCanceledException) when (!token.IsCancellationRequested) { /* DNS budget expired. */ }
            }
            finally { slots.Release(); }
        });
        await Task.WhenAll(jobs).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        return peers;
    }
}
