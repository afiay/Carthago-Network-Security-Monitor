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

public sealed record LanCaptureSelection(ILiveDevice Device, IPAddress Address);

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

        var hostFilter = $"ip host {address}";
        return configured.Length == 0 ? hostFilter : $"({configured}) and ({hostFilter})";
    }

    public static string FormatLabel(LanCapturePeer peer, string adapterName)
    {
        var name = NormalizeHostName(peer.HostName);
        var host = name is null ? peer.Address.ToString() : $"{name} ({peer.Address})";
        return $"Npcap: LAN {host} via {adapterName}";
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
        var result = new List<LanCapturePeer>();
        foreach (var entry in scan.NeighborMacs)
        {
            if (!IPAddress.TryParse(entry.Key, out var address) ||
                address.AddressFamily != AddressFamily.InterNetwork ||
                !LocalLanDiscovery.IsLocalHostAddress(address))
                continue;
            result.Add(new LanCapturePeer(address, entry.Value, null,
                replies.Contains(entry.Key) ? "Neighbor cache + ICMP reply" : "Neighbor cache (unconfirmed)"));
        }
        return result.OrderBy(p => p.Address.ToString(), StringComparer.Ordinal).Take(512).ToArray();
    }

    public static async Task<IReadOnlyList<LanCapturePeer>> DiscoverAsync(Guid interfaceId, CancellationToken token)
    {
        var scan = await LocalLanDiscovery.ScanAsync(true, token, interfaceId).ConfigureAwait(false);
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
