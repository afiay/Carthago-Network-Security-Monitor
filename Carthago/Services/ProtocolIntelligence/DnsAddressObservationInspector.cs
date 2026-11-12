// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;

namespace Carthago.Services.ProtocolIntelligence;

// Separate enrichment-only parser: complete standard UDP IN/A or IN/AAAA.
// Only answer-section records reachable from the question can seed candidates.
internal static class DnsAddressObservationInspector
{
    internal readonly record struct AddressAnswer(string Address, uint Ttl);
    internal sealed record Observation(ushort TransactionId, string Name, ushort QuestionType,
        bool IsResponse, IReadOnlyList<AddressAnswer> Answers);
    private sealed record Alias(string Target, uint Ttl);
    private sealed record AddressRecord(string Owner, AddressAnswer Answer);

    internal static bool TryInspect(ReadOnlySpan<byte> wire, out Observation? observation)
    {
        observation = null;
        if (wire.Length is < 17 or > 4096) return false;
        var bytes = wire.ToArray();
        ushort flags = U16(bytes, 2);
        if ((flags & 0x7a40) != 0) return false;
        bool response = (flags & 0x8000) != 0;
        int rcode = flags & 15;
        int qd = U16(bytes, 4), an = U16(bytes, 6), ns = U16(bytes, 8), ar = U16(bytes, 10);
        if (qd != 1 || an + ns + ar > 64
            || (!response && (rcode != 0 || an != 0 || ns != 0))
            || (response && (rcode != 0 && rcode != 3 || rcode == 3 && an != 0)))
            return false;

        // The initial question cannot legitimately point to an earlier name.
        int pos = 12;
        while (pos < bytes.Length)
        {
            int len = bytes[pos++];
            if (len == 0) break;
            if (len > 63 || len > bytes.Length - pos) return false;
            pos += len;
        }
        if (pos > bytes.Length - 4 || bytes[pos - 1] != 0
            || !ReadName(bytes, 12, out var name, out int next) || next != pos)
            return false;
        ushort qtype = U16(bytes, pos);
        if ((qtype != 1 && qtype != 28) || U16(bytes, pos + 2) != 1) return false;
        pos += 4;

        var aliases = new Dictionary<string, Alias>(StringComparer.Ordinal);
        var addresses = new List<AddressRecord>();
        for (int i = 0; i < an + ns + ar; i++)
        {
            if (!DnsWireNameCodec.TryReadQuestion(bytes, pos, out var ownerWire, out next, out _)
                || ownerWire == null || next > bytes.Length - 10) return false;
            ushort type = U16(bytes, next), klass = U16(bytes, next + 2);
            uint ttl = BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(next + 4, 4));
            int length = U16(bytes, next + 8);
            int start = next + 10;
            if (length > bytes.Length - start) return false;
            pos = start + length;
            // Additional/authority records are envelope-validated but never used.
            if (i >= an || klass != 1) continue;
            if (type != 5 && type != 1 && type != 28) continue;
            if (!SafeName(ownerWire, out var owner)) return false;
            if (type == 5)
            {
                if (!ReadName(bytes, start, out var target, out int end) || end != pos) return false;
                if (aliases.TryGetValue(owner, out var old))
                {
                    if (old.Target != target) return false;
                    ttl = Math.Min(ttl, old.Ttl);
                }
                aliases[owner] = new Alias(target, ttl);
            }
            else
            {
                if (length != (type == 1 ? 4 : 16)) return false;
                if (type == qtype)
                    addresses.Add(new AddressRecord(owner, new AddressAnswer(new IPAddress(bytes.AsSpan(start, length)).ToString(), ttl)));
            }
        }
        if (pos != bytes.Length) return false;

        var result = new List<AddressAnswer>();
        if (response && rcode == 0)
        {
            string terminal = name;
            uint chainTtl = uint.MaxValue;
            var visited = new HashSet<string>(StringComparer.Ordinal);
            while (aliases.TryGetValue(terminal, out var alias))
            {
                if (!visited.Add(terminal) || visited.Count > 16) return false;
                // A CNAME owner cannot simultaneously provide the queried address.
                if (addresses.Exists(a => a.Owner == terminal)) return false;
                chainTtl = Math.Min(chainTtl, alias.Ttl);
                terminal = alias.Target;
            }
            var unique = new Dictionary<string, uint>(StringComparer.Ordinal);
            foreach (var entry in addresses)
            {
                if (entry.Owner != terminal) continue;
                uint ttl = Math.Min(chainTtl, entry.Answer.Ttl);
                if (unique.TryGetValue(entry.Answer.Address, out uint old)) ttl = Math.Min(ttl, old);
                unique[entry.Answer.Address] = ttl;
            }
            foreach (var entry in unique) result.Add(new AddressAnswer(entry.Key, entry.Value));
        }
        observation = new Observation(U16(bytes, 0), name, qtype, response, result.AsReadOnly());
        return true;
    }

    private static ushort U16(byte[] bytes, int at) => BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(at, 2));

    private static bool ReadName(byte[] bytes, int at, out string name, out int next)
    {
        name = "";
        return DnsWireNameCodec.TryReadQuestion(bytes, at, out var wire, out next, out _)
            && wire != null && SafeName(wire, out name);
    }

    private static bool SafeName(DnsWireName wire, out string name)
    {
        name = "";
        if (!DnsWireNameCodec.TryGetSafeAsciiQName(wire, out var display) || string.IsNullOrEmpty(display)
            || display.Length > 253) return false;
        // Hostname candidates must not contain presentation delimiters.
        foreach (char c in display)
            if (!(c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '.' or '-' or '_'))
                return false;
        name = display.ToLowerInvariant();
        return true;
    }
}
