// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    // Narrow definite-length BER subset: complete SNMPv1/v2c SET with
    // integer or octet-string values. Separate enterprise and exact UPS reboot
    // predicates. No community, OID or value retained.
    internal static class SnmpEnterpriseSetInspector
    {
        // RFC 1628 UPS-MIB upsRebootWithDuration.0 (not an enterprise OID).
        private static readonly byte[] UpsRebootOid = { 0x2B, 6, 1, 2, 1, 33, 1, 8, 4, 0 };

        internal static bool TryInspect(ReadOnlySpan<byte> packet) => TryInspectSet(packet, false);
        internal static bool TryInspectUpsReboot(ReadOnlySpan<byte> packet) => TryInspectSet(packet, true);

        private static bool TryInspectSet(ReadOnlySpan<byte> packet, bool upsReboot)
        {
            if (packet.Length is < 20 or > 4096) return false;
            int p = 0;
            if (!Take(packet, ref p, 0x30, out var message) || p != packet.Length) return false;
            p = 0;
            if (!Take(message, ref p, 0x02, out var version) || version.Length != 1 ||
                version[0] > 1 ||
                !Take(message, ref p, 0x04, out var community) || community.Length is < 1 or > 255 ||
                !Take(message, ref p, 0xA3, out var request) || p != message.Length) return false;
            p = 0;
            if (!Take(request, ref p, 0x02, out var id) || !Integer(id) ||
                !Take(request, ref p, 0x02, out var error) || !Zero(error) ||
                !Take(request, ref p, 0x02, out var index) || !Zero(index) ||
                !Take(request, ref p, 0x30, out var list) || p != request.Length) return false;
            p = 0;
            int count = 0;
            bool enterprise = false;
            while (p < list.Length)
            {
                if (++count > 32 || !Take(list, ref p, 0x30, out var binding)) return false;
                int b = 0;
                if (!Take(binding, ref b, 0x06, out var oid) || !ValidOid(oid) ||
                    b >= binding.Length) return false;
                byte tag = binding[b];
                if (tag != 0x02 && tag != 0x04) return false;
                if (!Take(binding, ref b, tag, out var value) || b != binding.Length ||
                    (tag == 0x02 ? !Integer(value) : value.Length > 1024)) return false;
                // A reboot candidate is a single exact scalar binding with a
                // nonnegative canonical signed Integer32 duration. No other
                // UPS controls, enterprise objects or mixed SETs are admitted.
                if (upsReboot)
                {
                    if (count != 1 || tag != 0x02 || (value[0] & 0x80) != 0 ||
                        !oid.SequenceEqual(UpsRebootOid)) return false;
                    enterprise = true;
                    continue;
                }

                // 1.3.6.1.4.1.<enterprise>.<object>; prefix alone is not an object.
                if (oid.Length >= 7 && oid[0] == 0x2B && oid[1] == 6 &&
                    oid[2] == 1 && oid[3] == 4 && oid[4] == 1)
                {
                    int end = 5;
                    while ((oid[end++] & 0x80) != 0) { }
                    if (end < oid.Length && oid[5] != 0) enterprise = true;
                }
            }
            return count > 0 && enterprise;
        }

        private static bool Zero(ReadOnlySpan<byte> value) => value.Length == 1 && value[0] == 0;

        private static bool Integer(ReadOnlySpan<byte> value) =>
            value.Length is >= 1 and <= 4 &&
            (value.Length == 1 || !((value[0] == 0 && (value[1] & 0x80) == 0) ||
                (value[0] == 0xFF && (value[1] & 0x80) != 0)));

        private static bool ValidOid(ReadOnlySpan<byte> value)
        {
            if (value.Length is < 2 or > 128) return false;
            int arcs = 0, bytes = 0;
            uint arc = 0;
            foreach (byte item in value)
            {
                if (bytes == 0 && item == 0x80) return false;
                if (++bytes > 5 || arc > (uint.MaxValue >> 7)) return false;
                arc = (arc << 7) | (uint)(item & 0x7F);
                if ((item & 0x80) == 0) { arcs++; bytes = 0; arc = 0; }
            }
            return bytes == 0 && arcs >= 2;
        }

        private static bool Take(ReadOnlySpan<byte> data, ref int position, byte tag,
            out ReadOnlySpan<byte> value)
        {
            value = default;
            if (data.Length - position < 2 || data[position++] != tag) return false;
            int length = data[position++];
            if ((length & 0x80) != 0)
            {
                int octets = length & 0x7F;
                if (octets is < 1 or > 2 || data.Length - position < octets ||
                    data[position] == 0) return false;
                length = 0;
                for (int i = 0; i < octets; i++) length = (length << 8) | data[position++];
                if (length < 128) return false;
            }
            if (length > data.Length - position) return false;
            value = data.Slice(position, length);
            position += length;
            return true;
        }
    }
}
