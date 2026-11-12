// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Net;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>Bounded complete UDP DNS evidence for a standard IN/A question.
    /// Accepts a query, a direct single-A answer or a no-answer NXDOMAIN.
    /// Never converts CNAME chains, multiple answers, truncation or incomplete data into a single A observation.
    /// Authority/additional records are skipped only after bounded wire-envelope validation.
    /// </summary>
    internal static class DnsAObservationInspector
    {
        internal readonly record struct Observation(ushort TransactionId, string Name, bool IsResponse,
            bool IsNxdomain, string? Address, int? Ttl);

        internal static bool TryInspect(ReadOnlySpan<byte> wire, out Observation observation)
        {
            observation = default;
            if (wire.Length is < 17 or > 4096) return false;
            var flags = BinaryPrimitives.ReadUInt16BigEndian(wire.Slice(2, 2));
            // Standard opcode, no TC or reserved Z bit; AD/CD are legitimate.
            if ((flags & 0x7a40) != 0) return false;
            bool response = (flags & 0x8000) != 0;
            int rcode = flags & 15;
            int qd = BinaryPrimitives.ReadUInt16BigEndian(wire.Slice(4, 2));
            int an = BinaryPrimitives.ReadUInt16BigEndian(wire.Slice(6, 2));
            int ns = BinaryPrimitives.ReadUInt16BigEndian(wire.Slice(8, 2));
            int ar = BinaryPrimitives.ReadUInt16BigEndian(wire.Slice(10, 2));
            if (qd != 1 || ns + ar > 32
                || (!response && (rcode != 0 || an != 0 || ns != 0))
                || (response && !((rcode == 0 && an == 1) || (rcode == 3 && an == 0))))
                return false;

            // First question cannot legitimately refer to a prior DNS name.
            int pos = 12;
            while (pos < wire.Length)
            {
                int count = wire[pos++];
                if (count == 0) break;
                if (count > 63 || count > wire.Length - pos) return false;
                pos += count;
            }
            if (pos + 4 > wire.Length || wire[pos - 1] != 0) return false;
            var bytes = wire.ToArray(); // bounded to 4 KiB, only on UDP/53
            if (!DnsWireNameCodec.TryReadQuestion(bytes, 12, out var question, out int next, out _)
                || question == null || next != pos
                || !DnsWireNameCodec.TryGetSafeAsciiQName(question, out var qname)
                || string.IsNullOrWhiteSpace(qname) || qname.Length > 253
                || BinaryPrimitives.ReadUInt16BigEndian(wire.Slice(pos, 2)) != 1
                || BinaryPrimitives.ReadUInt16BigEndian(wire.Slice(pos + 2, 2)) != 1)
                return false;
            pos += 4;
            string? ip = null;
            int? ttl = null;
            if (an == 1)
            {
                if (!ReadRecord(bytes, ref pos, out var owner, out ushort type, out ushort klass, out uint seconds, out int start, out int length)
                    || owner == null || !string.Equals(DnsWireNameCodec.CanonicalIdentityKey(owner), DnsWireNameCodec.CanonicalIdentityKey(question), StringComparison.Ordinal)
                    || type != 1 || klass != 1 || length != 4 || seconds > int.MaxValue)
                    return false;
                ip = new IPAddress(bytes.AsSpan(start, 4)).ToString();
                ttl = (int)seconds;
            }
            for (int i = 0; i < ns + ar; i++)
                if (!ReadRecord(bytes, ref pos, out _, out _, out _, out _, out _, out _)) return false;
            if (pos != bytes.Length) return false;
            observation = new Observation(BinaryPrimitives.ReadUInt16BigEndian(wire), qname,
                response, response && rcode == 3, ip, ttl);
            return true;
        }

        private static bool ReadRecord(byte[] bytes, ref int pos, out DnsWireName? owner,
            out ushort type, out ushort klass, out uint ttl, out int start, out int length)
        {
            owner = null; type = klass = 0; ttl = 0; start = length = 0;
            if (!DnsWireNameCodec.TryReadQuestion(bytes, pos, out owner, out int next, out _)
                || owner == null || next < pos || next > bytes.Length - 10) return false;
            type = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(next, 2));
            klass = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(next + 2, 2));
            ttl = BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(next + 4, 4));
            length = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(next + 8, 2));
            start = next + 10;
            if (length > bytes.Length - start) return false;
            pos = start + length;
            return true;
        }
    }
}
