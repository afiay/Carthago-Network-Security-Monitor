// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using PacketDotNet;
using SharpPcap;

namespace Carthago.Services;

/// <summary>
/// Performs a short Ethernet ARP request/reply exchange on an already selected
/// Npcap adapter. Unlike ICMP, ARP is required for directly connected IPv4
/// peers and is unaffected by a phone's ping/firewall policy.
/// </summary>
public static class NpcapArpDiscovery
{
    private const ushort EthernetArp = 0x0806;
    private const ushort EthernetIpv4 = 0x0800;
    private const ushort EthernetVlan = 0x8100;
    private const ushort EthernetProviderVlan = 0x88A8;

    public static byte[] BuildRequest(
        PhysicalAddress sourceMac, IPAddress sourceAddress, IPAddress targetAddress)
    {
        ArgumentNullException.ThrowIfNull(sourceMac);
        ArgumentNullException.ThrowIfNull(sourceAddress);
        ArgumentNullException.ThrowIfNull(targetAddress);
        var mac = sourceMac.GetAddressBytes();
        if (mac.Length != 6 || mac.All(value => value == 0) || (mac[0] & 1) != 0)
            throw new ArgumentException("A unicast 6-byte adapter MAC address is required.", nameof(sourceMac));
        if (sourceAddress.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("An IPv4 source address is required.", nameof(sourceAddress));
        if (targetAddress.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("An IPv4 target address is required.", nameof(targetAddress));

        var frame = new byte[42];
        frame.AsSpan(0, 6).Fill(0xFF);
        mac.CopyTo(frame, 6);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(12, 2), EthernetArp);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(14, 2), 1); // Ethernet
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(16, 2), EthernetIpv4);
        frame[18] = 6;
        frame[19] = 4;
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(20, 2), 1); // request
        mac.CopyTo(frame, 22);
        sourceAddress.GetAddressBytes().CopyTo(frame, 28);
        targetAddress.GetAddressBytes().CopyTo(frame, 38);
        return frame;
    }

    public static bool TryParseReply(
        ReadOnlySpan<byte> frame,
        IPAddress localAddress,
        out IPAddress? senderAddress,
        out string? senderMac)
    {
        senderAddress = null;
        senderMac = null;
        if (localAddress is null || localAddress.AddressFamily != AddressFamily.InterNetwork || frame.Length < 42)
            return false;

        var etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(12, 2));
        var arpOffset = 14;
        if (etherType is EthernetVlan or EthernetProviderVlan)
        {
            if (frame.Length < 46) return false;
            etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(16, 2));
            arpOffset = 18;
        }
        if (etherType != EthernetArp || frame.Length < arpOffset + 28)
            return false;

        var arp = frame[arpOffset..];
        if (BinaryPrimitives.ReadUInt16BigEndian(arp[..2]) != 1 ||
            BinaryPrimitives.ReadUInt16BigEndian(arp.Slice(2, 2)) != EthernetIpv4 ||
            arp[4] != 6 || arp[5] != 4 ||
            BinaryPrimitives.ReadUInt16BigEndian(arp.Slice(6, 2)) != 2)
            return false;

        var mac = arp.Slice(8, 6);
        if (mac.ToArray().All(value => value == 0) || (mac[0] & 1) != 0 ||
            !arp.Slice(24, 4).SequenceEqual(localAddress.GetAddressBytes()))
            return false;

        senderAddress = new IPAddress(arp.Slice(14, 4));
        senderMac = string.Join(":", mac.ToArray().Select(value => value.ToString("X2")));
        return !senderAddress.Equals(localAddress);
    }

    internal static IReadOnlyDictionary<string, string> MergeNeighborEvidence(
        IReadOnlyCollection<IPAddress> targets,
        IReadOnlyDictionary<string, string> cached,
        IReadOnlyDictionary<string, string> direct)
    {
        ArgumentNullException.ThrowIfNull(targets);
        ArgumentNullException.ThrowIfNull(cached);
        ArgumentNullException.ThrowIfNull(direct);
        var permitted = new HashSet<string>(
            targets.Select(address => address.ToString()), StringComparer.OrdinalIgnoreCase);
        var merged = cached
            .Where(entry => permitted.Contains(entry.Key))
            .ToDictionary(entry => entry.Key, entry => entry.Value, StringComparer.OrdinalIgnoreCase);
        foreach (var entry in direct)
            if (permitted.Contains(entry.Key))
                merged[entry.Key] = entry.Value;
        return merged;
    }

    public static async Task<LocalLanScanResult> ScanAsync(
        ILiveDevice device, LocalLanInterface adapter, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(adapter);
        token.ThrowIfCancellationRequested();
        var targets = LocalLanDiscovery.PlanProbeTargets(new[] { adapter });
        var permitted = new HashSet<IPAddress>(targets);
        var found = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var sourceMac = device.MacAddress
            ?? throw new InvalidOperationException("The selected Npcap adapter has no usable MAC address.");

        void OnPacketArrival(object _, PacketCapture capture)
        {
            try
            {
                if (TryParseReply(capture.Data, adapter.Address, out var address, out var mac) &&
                    address is not null && mac is not null && permitted.Contains(address))
                    found[address.ToString()] = mac;
            }
            catch
            {
                // A malformed captured frame must not abort the discovery run.
            }
        }

        bool openAttempted = false, startAttempted = false, attached = false;
        await ReservedNpcapOperation.RunAsync(async () =>
        {
            token.ThrowIfCancellationRequested();
            attached = true;
            device.OnPacketArrival += OnPacketArrival;
            openAttempted = true;
            device.Open(new DeviceConfiguration
            {
                Mode = DeviceModes.Promiscuous,
                ReadTimeout = 100,
                Snaplen = 96,
                Immediate = true
            });
            if (device.LinkType != LinkLayers.Ethernet)
                throw new NotSupportedException($"LAN ARP discovery requires an Ethernet-style Npcap link, not {device.LinkType}.");
            device.Filter = "arp";
            startAttempted = true;
            device.StartCapture();

            // Two compact passes tolerate ordinary Wi-Fi loss while keeping
            // the selector responsive. The second pass skips peers already seen.
            for (var pass = 0; pass < 2; pass++)
            {
                var sent = 0;
                foreach (var target in targets)
                {
                    token.ThrowIfCancellationRequested();
                    if (found.ContainsKey(target.ToString())) continue;
                    device.SendPacket(BuildRequest(sourceMac, adapter.Address, target));
                    if (++sent % 64 == 0)
                        await Task.Delay(8, token).ConfigureAwait(false);
                }
                await Task.Delay(pass == 0 ? 250 : 850, token).ConfigureAwait(false);
            }
        }, () => ReservedNpcapOperation.Cleanup(
            () => { if (startAttempted) device.StopCapture(); },
            () => { if (openAttempted) device.Close(); },
            () => { if (attached) device.OnPacketArrival -= OnPacketArrival; }), token).ConfigureAwait(false);

        token.ThrowIfCancellationRequested();
        // Phones commonly enter Wi-Fi power-save and miss a burst scan. Keep
        // valid entries from this adapter's neighbor cache selectable, but
        // only direct replies receive live ARP evidence in the result.
        var cached = await LocalLanDiscovery.ReadNeighborCacheAsync(token, adapter.Address)
            .ConfigureAwait(false);
        var merged = MergeNeighborEvidence(targets, cached, found);
        return new LocalLanScanResult(merged, Array.Empty<string>(), targets.Count, found.Keys.ToArray());
    }
}
