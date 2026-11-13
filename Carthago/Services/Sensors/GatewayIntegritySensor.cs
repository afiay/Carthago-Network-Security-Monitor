// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using PacketDotNet;
using SharpPcap;

namespace Carthago.Services.Sensors;

public enum GatewayIntegrityStatus { NoReply, Observed, BaselineMatch, BaselineDifference, ConflictingClaims }
public sealed record GatewayIntegrityObservation(IPAddress Source, IPAddress Gateway,
    GatewayIntegrityStatus Status, IReadOnlyList<string> DirectMacs, string? CachedMac,
    bool CacheDiffers, string? ExpectedMac, bool ClaimLimitReached, DateTimeOffset ObservedUtc);

/// <summary>Two targeted ARP requests, with distinct claims retained independently of neighbor cache.</summary>
public static class GatewayIntegritySensor
{
    internal const int MaxClaims = 16;

    internal static string? NormalizeMac(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        string hex = value.Trim().Replace(":", "").Replace("-", "");
        if (hex.Length != 12 || hex.Any(c => !Uri.IsHexDigit(c))) return null;
        var bytes = Convert.FromHexString(hex);
        return WindowsLanArpResolver.FormatMac(bytes, 6);
    }

    internal static bool TryMatchReply(ReadOnlySpan<byte> frame, IPAddress local, IPAddress gateway,
        PhysicalAddress localMac, out string? mac)
    {
        mac = null;
        if (!NpcapArpDiscovery.TryParseReply(frame, local, out var sender, out var parsed) ||
            !gateway.Equals(sender) || parsed is null) return false;
        var own = localMac.GetAddressBytes();
        if (own.Length != 6) return false;
        int offset = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(12, 2)) is 0x8100 or 0x88A8 ? 18 : 14;
        // Require Ethernet source == ARP sender and both destination MACs == this adapter.
        if (!frame.Slice(0, 6).SequenceEqual(own) ||
            !frame.Slice(offset + 18, 6).SequenceEqual(own) ||
            !frame.Slice(6, 6).SequenceEqual(frame.Slice(offset + 8, 6)) ||
            frame.Slice(6, 6).SequenceEqual(own)) return false;
        mac = parsed;
        return true;
    }

    internal static GatewayIntegrityObservation Evaluate(IPAddress source, IPAddress gateway,
        IEnumerable<string> direct, string? cached, string? expected, bool limitReached = false)
    {
        var claims = direct.Select(NormalizeMac).Where(m => m is not null).Select(m => m!)
            .Distinct(StringComparer.Ordinal).OrderBy(m => m, StringComparer.Ordinal).Take(MaxClaims).ToArray();
        cached = NormalizeMac(cached);
        expected = NormalizeMac(expected);
        var status = claims.Length > 1 || limitReached ? GatewayIntegrityStatus.ConflictingClaims :
            claims.Length == 0 ? GatewayIntegrityStatus.NoReply :
            expected is null ? GatewayIntegrityStatus.Observed :
            claims[0] == expected ? GatewayIntegrityStatus.BaselineMatch : GatewayIntegrityStatus.BaselineDifference;
        return new(source, gateway, status, Array.AsReadOnly(claims), cached,
            cached is not null && claims.Length != 0 && claims.Any(m => m != cached),
            expected, limitReached, DateTimeOffset.UtcNow);
    }

    public static async Task<GatewayIntegrityObservation> CheckAsync(ILiveDevice device,
        LocalLanInterface adapter, IPAddress gateway, string? expectedMac, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(adapter);
        ArgumentNullException.ThrowIfNull(gateway);
        token.ThrowIfCancellationRequested();
        if (!LocalLanDiscovery.PlanProbeTargets(new[] { adapter }).Contains(gateway))
            throw new ArgumentException("Gateway must be inside the selected local IPv4 scope.", nameof(gateway));
        var expected = NormalizeMac(expectedMac);
        if (!string.IsNullOrWhiteSpace(expectedMac) && expected is null)
            throw new ArgumentException("Expected MAC must be a nonzero unicast 6-byte MAC.", nameof(expectedMac));
        // Verify the live adapter, source IP and configured gateway again at execution.
        var id = CaptureDeviceLabelFormatter.ParseDeviceGuid(device.Name);
        if (!id.HasValue || !LocalLanDiscovery.GetLocalInterfaces(id.Value).Any(a =>
                a.Address.Equals(adapter.Address) && a.Mask.Equals(adapter.Mask)) ||
            !NetworkInterface.GetAllNetworkInterfaces().Any(n =>
                Guid.TryParse(n.Id, out var guid) && guid == id.Value &&
                n.GetIPProperties().GatewayAddresses.Any(g => g.Address.Equals(gateway))))
            throw new InvalidOperationException("The selected adapter or configured gateway has changed.");
        var mac = device.MacAddress ?? throw new InvalidOperationException("Adapter MAC unavailable.");
        var request = NpcapArpDiscovery.BuildRequest(mac, adapter.Address, gateway);

        // Read cache before probing: the ARP exchange itself may refresh it.
        var cache = await LocalLanDiscovery.ReadNeighborCacheAsync(token, adapter.Address).ConfigureAwait(false);
        cache.TryGetValue(gateway.ToString(), out var cached);
        var claims = new HashSet<string>(StringComparer.Ordinal);
        var gate = new object();
        bool collecting = false, overflow = false;
        void OnPacket(object _, PacketCapture packet)
        {
            if (!TryMatchReply(packet.Data, adapter.Address, gateway, mac, out var claim) || claim is null) return;
            lock (gate)
            {
                if (!collecting || claims.Contains(claim)) return;
                if (claims.Count < MaxClaims) claims.Add(claim);
                else overflow = true;
            }
        }

        bool openAttempted = false, startAttempted = false, attached = false;
        await ReservedNpcapOperation.RunAsync(async () =>
        {
            token.ThrowIfCancellationRequested();
            // Mark attempted operations before calling native code: partial
            // initialization must also be cleaned up.
            attached = true;
            device.OnPacketArrival += OnPacket;
            openAttempted = true;
            device.Open(new DeviceConfiguration { Mode = DeviceModes.Promiscuous, ReadTimeout = 100, Snaplen = 96, Immediate = true });
            if (device.LinkType != LinkLayers.Ethernet)
                throw new NotSupportedException("Gateway integrity requires an Ethernet-style Npcap adapter.");
            device.Filter = "arp or (vlan and arp)";
            startAttempted = true;
            device.StartCapture();
            lock (gate) collecting = true;
            // Do not stop after the first reply: retain competing claims across both windows.
            for (int pass = 0; pass < 2; pass++)
            {
                token.ThrowIfCancellationRequested();
                device.SendPacket(request);
                await Task.Delay(pass == 0 ? 350 : 850, token).ConfigureAwait(false);
            }
        }, () =>
        {
            lock (gate) collecting = false;
            ReservedNpcapOperation.Cleanup(
                () => { if (startAttempted) device.StopCapture(); },
                () => { if (openAttempted) device.Close(); },
                () => { if (attached) device.OnPacketArrival -= OnPacket; });
        }, token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        lock (gate) return Evaluate(adapter.Address, gateway, claims, cached, expected, overflow);
    }
}
