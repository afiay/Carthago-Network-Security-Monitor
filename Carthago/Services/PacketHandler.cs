// SPDX-License-Identifier: MIT
// Windows capture adapter; raw-frame parsing is owned by Carthago.Core.
using System;
using System.Net;
using System.Net.Sockets;
using SharpPcap;
using PacketDotNet;
using Carthago.Models;
using Carthago.Services.Flow;
using Carthago.Services.Fingerprints;

namespace Carthago.Services
{
    public class PacketHandler
    {
        private readonly PortablePacketProcessor _processor;

        public PacketHandler() : this(() => DateTime.UtcNow) { }

        internal PacketHandler(Func<DateTime> utcNow)
            : this(utcNow, HandshakeBuffer.Shared, LatencyTracker.Shared) { }

        internal PacketHandler(Func<DateTime> utcNow, HandshakeBufferState handshakes, LatencyTrackerState latency)
        {
            if (handshakes is null) throw new ArgumentNullException(nameof(handshakes));
            if (latency is null) throw new ArgumentNullException(nameof(latency));
            _processor = new PortablePacketProcessor(utcNow,
                (port, protocol) => PortServiceResolver.GetServiceName(port, protocol),
                der => X509Ja4X.FromCertificateDer(der), () => DateTime.Now,
                handshakes, latency, (isError, message) =>
                { if (isError) Console.Error.WriteLine(message); else Console.WriteLine(message); });
        }

        public TrafficRecord? ParsePacket(PacketCapture e)
        {
            var raw = e.GetPacket();
            return raw?.Data is null ? null : ParseFrame(raw.Data, raw.LinkLayerType);
        }

        internal TrafficRecord? ParseFrame(byte[] data, LinkLayers linkLayerType)
            => _processor.ParseFrame(data, (int)linkLayerType);

        internal static bool IsWithinRedisReplyWindow(DateTime requestUtc, DateTime replyUtc)
            => PortablePacketProcessor.IsWithinRedisReplyWindow(requestUtc, replyUtc);
    }

    public static class IpUtils
    {
        public static bool IsPrivateIp(string ip)
        {
            if (!IPAddress.TryParse(ip, out var address)) return false;
            if (IPAddress.IsLoopback(address)) return true;
            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (address.IsIPv4MappedToIPv6) return IsPrivateIp(address.MapToIPv4().ToString());
                var b = address.GetAddressBytes();
                if (b[0] == 0xFC || b[0] == 0xFD) return true; // Unique local
                if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true; // link-local
                if (b[0] == 0xFE && (b[1] & 0xC0) == 0xC0) return true; // site-local (deprecated)
                return false;
            }
            var v4 = address.GetAddressBytes();
            return (v4[0] == 10) ||
                   (v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31) ||
                   (v4[0] == 192 && v4[1] == 168) ||
                   (v4[0] == 127) ||
                   (v4[0] == 169 && v4[1] == 254);
        }
    }
}
