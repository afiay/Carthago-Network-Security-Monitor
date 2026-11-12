// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Services;

internal static class EndpointIpEnrichment
{
    private static readonly object Sync = new();
    private static HashSet<IPAddress>? _localAddresses;
    private static long _refreshAfter;

    // Scope is a routing/address property. Local-host membership is independent:
    // a host can own a globally routable address, and a private IP can be remote.
    internal static string Classify(string? ip)
    {
        if (!IPAddress.TryParse(ip, out var address)) return "Unknown";
        address = Normalize(address);
        if (IPAddress.IsLoopback(address)) return "Loopback";
        var b = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            if (b[0] == 0) return "UnspecifiedOrReserved";
            if (b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)) return "Private";
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return "SharedCGNAT";
            if (b[0] == 169 && b[1] == 254) return "LinkLocal";
            if (b[0] >= 224 && b[0] <= 239) return "Multicast";
            if (b[0] >= 240 || (b[0] == 192 && b[1] == 0 && b[2] == 0)) return "Reserved";
            if ((b[0] == 192 && b[1] == 0 && b[2] == 2)
                || (b[0] == 198 && b[1] == 51 && b[2] == 100)
                || (b[0] == 203 && b[1] == 0 && b[2] == 113)) return "Documentation";
            if (b[0] == 198 && (b[1] == 18 || b[1] == 19)) return "Benchmark";
            return "Public";
        }
        if (address.AddressFamily != AddressFamily.InterNetworkV6) return "Unknown";
        if (address.Equals(IPAddress.IPv6Any)) return "UnspecifiedOrReserved";
        if (address.IsIPv6Multicast) return "Multicast";
        if (address.IsIPv6LinkLocal) return "LinkLocal";
        if (address.IsIPv6SiteLocal || (b[0] & 0xfe) == 0xfc) return "Private";
        if (b[0] == 0x20 && b[1] == 1 && b[2] == 0x0d && b[3] == 0xb8) return "Documentation";
        if (b[0] == 0x3f && b[1] == 0xff && (b[2] & 0xf0) == 0) return "Documentation";
        // Conservative global-unicast candidate, not proof of Internet reachability.
        if ((b[0] & 0xe0) != 0x20) return "Reserved";
        return "Public";
    }

    internal static IPAddress Normalize(IPAddress address)
        => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    internal static bool? IsLocal(string? ip, HashSet<IPAddress>? addresses)
    {
        if (!IPAddress.TryParse(ip, out var address)) return null;
        address = Normalize(address);
        if (IPAddress.IsLoopback(address)) return true;
        if (addresses is null) return null;
        return addresses.Contains(address);
    }

    internal static void Apply(TrafficRecord record)
    {
        var addresses = GetLocalAddresses();
        Apply(record, addresses);
    }

    internal static void Apply(TrafficRecord record, HashSet<IPAddress>? addresses)
    {
        record.SrcIpScope = Classify(record.Source);
        record.DstIpScope = Classify(record.Destination);
        record.SrcIsLocalHost = IsLocal(record.Source, addresses);
        record.DstIsLocalHost = IsLocal(record.Destination, addresses);
    }

    private static HashSet<IPAddress>? GetLocalAddresses()
    {
        lock (Sync)
        {
            long now = Environment.TickCount64;
            if (now < _refreshAfter) return _localAddresses;
            _refreshAfter = now + 30_000;
            try
            {
                var next = new HashSet<IPAddress>();
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;
                    foreach (var ip in nic.GetIPProperties().UnicastAddresses)
                        next.Add(Normalize(ip.Address));
                }
                _localAddresses = next;
            }
            catch
            {
                // Unknown is not proof that an address belongs to another host.
                _localAddresses = null;
            }
            return _localAddresses;
        }
    }
}
