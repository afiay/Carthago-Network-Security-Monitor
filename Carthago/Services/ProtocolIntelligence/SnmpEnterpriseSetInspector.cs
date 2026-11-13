// SPDX-License-Identifier: MIT
using System;
using Carthago.Models;

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

        // RFC 3416 GETBULK: narrow, all-repeaters subset. The requested
        // response cardinality is a demand estimate, never a response outcome.
        internal static bool TryInspectHighDemandBulk(ReadOnlySpan<byte> packet)
        {
            if (packet.Length is < 20 or > 4096) return false;
            int p = 0;
            if (!Take(packet, ref p, 0x30, out var message) || p != packet.Length) return false;
            p = 0;
            if (!Take(message, ref p, 0x02, out var version) ||
                version.Length != 1 || version[0] != 1 ||
                !Take(message, ref p, 0x04, out var community) || community.Length is < 1 or > 255 ||
                !Take(message, ref p, 0xA5, out var request) || p != message.Length) return false;
            p = 0;
            if (!Take(request, ref p, 0x02, out var id) || !Integer(id) ||
                !Take(request, ref p, 0x02, out var nonRepeaters) || !Zero(nonRepeaters) ||
                !Take(request, ref p, 0x02, out var maxRepetitions) || !Integer(maxRepetitions) ||
                (maxRepetitions[0] & 0x80) != 0 || maxRepetitions.Length > 2 ||
                !Take(request, ref p, 0x30, out var list) || p != request.Length) return false;
            int repetitions = 0;
            foreach (byte b in maxRepetitions) repetitions = (repetitions << 8) | b;
            if (repetitions is < 64 or > 1024) return false;
            p = 0;
            int count = 0;
            while (p < list.Length)
            {
                if (++count > 8 || !Take(list, ref p, 0x30, out var binding)) return false;
                int b = 0;
                if (!Take(binding, ref b, 0x06, out var oid) || !ValidOid(oid) ||
                    !Take(binding, ref b, 0x05, out var value) || !value.IsEmpty ||
                    b != binding.Length) return false;
            }
            return count > 0;
        }

        // RFC 3418 system group: exact unordered sysDescr.0, sysObjectID.0,
        // sysName.0 GET; all three distinct, no other bindings or values.
        internal static bool TryInspectSystemFingerprintGet(ReadOnlySpan<byte> packet)
        {
            if (packet.Length is < 20 or > 4096) return false;
            int p = 0;
            if (!Take(packet, ref p, 0x30, out var message) || p != packet.Length) return false;
            p = 0;
            if (!Take(message, ref p, 0x02, out var version) ||
                version.Length != 1 || version[0] > 1 ||
                !Take(message, ref p, 0x04, out var community) || community.Length is < 1 or > 255 ||
                !Take(message, ref p, 0xA0, out var request) || p != message.Length) return false;
            p = 0;
            if (!Take(request, ref p, 0x02, out var id) || !Integer(id) ||
                !Take(request, ref p, 0x02, out var error) || !Zero(error) ||
                !Take(request, ref p, 0x02, out var index) || !Zero(index) ||
                !Take(request, ref p, 0x30, out var list) || p != request.Length) return false;
            p = 0;
            int seen = 0;
            while (p < list.Length)
            {
                if (!Take(list, ref p, 0x30, out var binding)) return false;
                int b = 0;
                if (!Take(binding, ref b, 0x06, out var oid) || oid.Length != 8 ||
                    oid[0] != 0x2B || oid[1] != 6 || oid[2] != 1 || oid[3] != 2 ||
                    oid[4] != 1 || oid[5] != 1 || oid[7] != 0 ||
                    !Take(binding, ref b, 0x05, out var value) || !value.IsEmpty ||
                    b != binding.Length) return false;
                int bit = oid[6] switch { 1 => 1, 2 => 2, 5 => 4, _ => 0 };
                if (bit == 0 || (seen & bit) != 0) return false;
                seen |= bit;
            }
            return seen == 7;
        }

        // RFC 1213 legacy TCP connection and UDP listener table roots.
        // Exact unordered GETNEXT pair; no claim of a completed table walk.
        internal static bool TryInspectConnectionTableGetNext(ReadOnlySpan<byte> packet)
        {
            if (packet.Length is < 20 or > 4096) return false;
            int p = 0;
            if (!Take(packet, ref p, 0x30, out var message) || p != packet.Length) return false;
            p = 0;
            if (!Take(message, ref p, 0x02, out var version) ||
                version.Length != 1 || version[0] > 1 ||
                !Take(message, ref p, 0x04, out var community) || community.Length is < 1 or > 255 ||
                !Take(message, ref p, 0xA1, out var request) || p != message.Length) return false;
            p = 0;
            if (!Take(request, ref p, 0x02, out var id) || !Integer(id) ||
                !Take(request, ref p, 0x02, out var error) || !Zero(error) ||
                !Take(request, ref p, 0x02, out var index) || !Zero(index) ||
                !Take(request, ref p, 0x30, out var list) || p != request.Length) return false;
            p = 0;
            int seen = 0;
            while (p < list.Length)
            {
                if (!Take(list, ref p, 0x30, out var binding)) return false;
                int b = 0;
                if (!Take(binding, ref b, 0x06, out var oid) || oid.Length != 7 ||
                    oid[0] != 0x2B || oid[1] != 6 || oid[2] != 1 || oid[3] != 2 ||
                    oid[4] != 1 || !Take(binding, ref b, 0x05, out var value) ||
                    !value.IsEmpty || b != binding.Length) return false;
                int bit = oid[5] == 6 && oid[6] == 13 ? 1 :
                    oid[5] == 7 && oid[6] == 5 ? 2 : 0;
                if (bit == 0 || (seen & bit) != 0) return false;
                seen |= bit;
            }
            return seen == 3;
        }

        // RFC 2863 ifAdminStatus and RFC 4293 ipForwarding.
        // Exactly one canonical INTEGER down/not-forwarding (2) binding.
        // Reuse the established complete BER reader; no community/OID retained.
        internal static IndustrialBatchOperation InspectNetworkControlSet(ReadOnlySpan<byte> packet)
        {
            if (packet.Length is < 20 or > 4096) return IndustrialBatchOperation.None;
            int p = 0;
            if (!Take(packet, ref p, 0x30, out var message) || p != packet.Length)
                return IndustrialBatchOperation.None;
            p = 0;
            if (!Take(message, ref p, 0x02, out var version) || version.Length != 1 ||
                version[0] > 1 || !Take(message, ref p, 0x04, out var community) ||
                community.Length is < 1 or > 255 || !Take(message, ref p, 0xA3, out var request) ||
                p != message.Length) return IndustrialBatchOperation.None;
            p = 0;
            if (!Take(request, ref p, 0x02, out var id) || !Integer(id) ||
                !Take(request, ref p, 0x02, out var error) || !Zero(error) ||
                !Take(request, ref p, 0x02, out var index) || !Zero(index) ||
                !Take(request, ref p, 0x30, out var list) || p != request.Length)
                return IndustrialBatchOperation.None;
            p = 0;
            if (!Take(list, ref p, 0x30, out var binding) || p != list.Length)
                return IndustrialBatchOperation.None;
            p = 0;
            if (!Take(binding, ref p, 0x06, out var oid) || !ValidOid(oid) ||
                !Take(binding, ref p, 0x02, out var value) || p != binding.Length ||
                value.Length != 1 || value[0] != 2) return IndustrialBatchOperation.None;

            if (oid.SequenceEqual(IpForwardingOid)) return IndustrialBatchOperation.SnmpIpv4ForwardingDisable;
            if (oid.Length <= IfAdminStatusPrefix.Length ||
                !oid[..IfAdminStatusPrefix.Length].SequenceEqual(IfAdminStatusPrefix))
                return IndustrialBatchOperation.None;
            var arc = oid[IfAdminStatusPrefix.Length..];
            // One positive canonical IF-MIB InterfaceIndex (1..Int32.MaxValue).
            if (arc.Length is < 1 or > 5 || arc[0] == 0x80)
                return IndustrialBatchOperation.None;
            uint ifIndex = 0;
            for (int i = 0; i < arc.Length; i++)
            {
                if (((arc[i] & 0x80) != 0) != (i < arc.Length - 1) ||
                    ifIndex > ((uint)int.MaxValue >> 7)) return IndustrialBatchOperation.None;
                ifIndex = (ifIndex << 7) | (uint)(arc[i] & 0x7F);
            }
            return ifIndex is >= 1 and <= int.MaxValue
                ? IndustrialBatchOperation.SnmpInterfaceAdminDown : IndustrialBatchOperation.None;
        }

        private static readonly byte[] IpForwardingOid = { 0x2B, 6, 1, 2, 1, 4, 1, 0 };
        private static readonly byte[] IfAdminStatusPrefix = { 0x2B, 6, 1, 2, 1, 2, 2, 1, 7 };

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
