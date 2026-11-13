// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Net;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography;
using Carthago.Services.Benchmarking;

namespace Carthago.Services.Baseline
{
    // Deliberately narrow offline candidate: classic little-endian microsecond
    // Ethernet PCAP containing only complete IPv4 UDP standard A queries.
    // This does not authenticate the sensor, reviewer or benign classification.
    internal static class ReviewedDnsPacketIntake
    {
        internal static bool Matches(ReadOnlySpan<byte> manifest, string manifestDigest,
            ReadOnlySpan<byte> capture, string source, string sensor, string interfaceId, string network)
            => TryGetObservations(manifest, manifestDigest, capture, source, sensor, interfaceId, network, out _);

        internal static bool TryGetObservations(ReadOnlySpan<byte> manifest, string manifestDigest,
            ReadOnlySpan<byte> capture, string source, string sensor, string interfaceId, string network,
            out string[] observations)
        {
            observations = Array.Empty<string>();
            QualifiedDnsScope scope;
            try { scope = QualifiedDnsScope.Create(source, sensor, interfaceId, network); }
            catch (ArgumentException) { return false; }
            if (!IPAddress.TryParse(source, out var address)) return false;
            if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
            byte[] ip = address.GetAddressBytes();
            if (ip.Length != 4 || capture.Length < 24 || capture.Length > 32 * 1024 * 1024 ||
                U32(capture) != 0xa1b2c3d4 || U16(capture.Slice(4)) != 2 ||
                U16(capture.Slice(6)) != 4 || U32(capture.Slice(20)) != 1) return false;
            uint snap = U32(capture.Slice(16));
            if (snap == 0 || snap > 65535) return false;
            // Reuse Q9 record framing and timestamp validation; retain the narrower
            // DNS format policy above and reject every truncated or unrelated frame.
            Smb2LabCaptureRunner.Capture parsed;
            try { parsed = Smb2LabCaptureRunner.ParseClassicPcap(capture.ToArray()); }
            catch (InvalidDataException) { return false; }
            if (parsed.Frames.Count == 0) return false;
            foreach (var frame in parsed.Frames)
                if (frame.Truncated || !IsQuery(frame.Bytes, ip)) return false;
            if (!ReviewedDnsManifestBinding.Matches(manifest, manifestDigest,
                capture, scope, new DateTimeOffset(parsed.Frames[0].Utc),
                new DateTimeOffset(parsed.Frames[^1].Utc))) return false;
            var unique = new HashSet<string>(StringComparer.Ordinal);
            foreach (var frame in parsed.Frames)
            {
                // Ignore PCAP headers, Ethernet addresses/padding and mutable IP headers.
                // Exact UTC timestamp, IPv4 endpoints and UDP datagram define v1 identity.
                var ipBytes = frame.Bytes.AsSpan(14);
                int total = Be(ipBytes.Slice(2));
                byte[] identity = new byte[8 + 8 + total - 20];
                BinaryPrimitives.WriteInt64LittleEndian(identity, frame.Utc.Ticks);
                ipBytes.Slice(12, 8).CopyTo(identity.AsSpan(8));
                ipBytes.Slice(20, total - 20).CopyTo(identity.AsSpan(16));
                // UDP checksum can differ due to capture offload; omit it.
                identity[22] = 0; identity[23] = 0;
                unique.Add(Convert.ToHexString(SHA256.HashData(identity)));
            }
            observations = new string[unique.Count];
            unique.CopyTo(observations);
            Array.Sort(observations, StringComparer.Ordinal);
            return true;
        }

        private static uint U32(ReadOnlySpan<byte> b) => BinaryPrimitives.ReadUInt32LittleEndian(b);
        private static ushort U16(ReadOnlySpan<byte> b) => BinaryPrimitives.ReadUInt16LittleEndian(b);
        private static ushort Be(ReadOnlySpan<byte> b) => BinaryPrimitives.ReadUInt16BigEndian(b);

        private static bool IsQuery(ReadOnlySpan<byte> frame, ReadOnlySpan<byte> source)
        {
            if (frame.Length < 54 || Be(frame.Slice(12)) != 0x0800) return false;
            var ip = frame.Slice(14);
            if (ip[0] != 0x45 || ip[9] != 17 || (Be(ip.Slice(6)) & 0xbfff) != 0 ||
                !ip.Slice(12, 4).SequenceEqual(source)) return false;
            int total = Be(ip.Slice(2));
            if (total < 45 || total > ip.Length) return false;
            // Permit only Ethernet minimum-frame padding, not arbitrary trailing bytes.
            if (ip.Length > Math.Max(total, 46)) return false;
            var udp = ip.Slice(20, total - 20);
            if (Be(udp) == 0 || Be(udp.Slice(2)) != 53 || Be(udp.Slice(4)) != udp.Length) return false;
            var dns = udp.Slice(8);
            // Standard query, RD optional; exactly one question, no other sections.
            if ((Be(dns.Slice(2)) & 0xfeff) != 0 || Be(dns.Slice(4)) != 1 ||
                Be(dns.Slice(6)) != 0 || Be(dns.Slice(8)) != 0 || Be(dns.Slice(10)) != 0) return false;
            int p = 12, labels = 0;
            while (p < dns.Length)
            {
                int n = dns[p++];
                if (n == 0) return labels > 0 && p <= 255 + 12 &&
                    dns.Length - p == 4 && Be(dns.Slice(p)) == 1 && Be(dns.Slice(p + 2)) == 1;
                if (n > 63 || n > dns.Length - p || p + n > 255 + 12) return false;
                p += n;
                labels++;
            }
            return false;
        }
    }
}
