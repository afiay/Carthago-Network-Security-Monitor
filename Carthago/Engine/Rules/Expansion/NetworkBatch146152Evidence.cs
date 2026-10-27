// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // R146-R152 rely on attributed transport; packet Info is a bounded
    // untrusted summary, never proof of a signed classification.
    internal static class NetworkBatch146152Evidence
    {
        internal static bool HandshakeFailure(TrafficRecord r)
        {
            var info = r.Info;
            if (string.IsNullOrWhiteSpace(info) || info.Length > 1024)
                return false;
            var value = info.ToLowerInvariant();
            return value.Contains("handshake failure", StringComparison.Ordinal)
                || value.Contains("handshake_failure", StringComparison.Ordinal)
                || value.Contains("tls alert", StringComparison.Ordinal)
                    && (value.Contains("bad certificate", StringComparison.Ordinal)
                        || value.Contains("unknown ca", StringComparison.Ordinal)
                        || value.Contains("protocol version", StringComparison.Ordinal));
        }

        internal static bool EchSummary(TrafficRecord r)
        {
            var info = r.Info;
            if (string.IsNullOrWhiteSpace(info) || info.Length > 1024)
                return false;
            var value = info.ToLowerInvariant();
            return value.Contains("encrypted client hello", StringComparison.Ordinal)
                || value.Contains("encrypted_client_hello", StringComparison.Ordinal)
                || value.Contains(" ech ", StringComparison.Ordinal);
        }

        internal static bool MalwareLabelSummary(TrafficRecord r)
        {
            var info = r.Info;
            if (string.IsNullOrWhiteSpace(info) || info.Length > 1024)
                return false;
            var value = info.ToLowerInvariant();
            return new[] { "malware ja3", "malware ja4", "cobalt strike ja3",
                "sliver ja3", "meterpreter ja3", "cobalt strike ja4", "sliver ja4" }
                .Any(value.Contains);
        }

        internal static string? Asn(TrafficRecord r)
        {
            var value = r.WhoisASN?.Trim().ToUpperInvariant();
            if (string.IsNullOrWhiteSpace(value) || value.Length > 12)
                return null;
            if (value.StartsWith("AS", StringComparison.Ordinal))
                value = value[2..];
            if (value.Length is < 1 or > 10
                || !value.All(static ch => ch >= '0' && ch <= '9')
                || !uint.TryParse(value, out var number) || number == 0)
                return null;
            return "AS" + number.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
    }

    // Bounded unique ASN observations, isolated by client source and TLS
    // fingerprint. Packet IDs are retained to prevent replay inflation.
    internal sealed class NetworkBatch146152AsnWindow
    {
        private sealed class Slot
        {
            internal readonly Dictionary<Guid, DateTime> Seen = new();
            internal readonly Dictionary<string, DateTime> Distinct = new(StringComparer.OrdinalIgnoreCase);
            internal DateTime Latest = DateTime.MinValue;
        }
        private readonly object _gate = new();
        private readonly Dictionary<string, Slot> _slots = new(StringComparer.OrdinalIgnoreCase);

        internal bool Observe(string key, Guid id, string asn, DateTime at, TimeSpan window, out int count)
        {
            lock (_gate)
            {
                foreach (var k in _slots.Where(v => at - v.Value.Latest > window)
                    .Select(v => v.Key).ToArray()) _slots.Remove(k);
                if (!_slots.TryGetValue(key, out var state))
                {
                    if (_slots.Count >= 1024)
                        _slots.Remove(_slots.OrderBy(v => v.Value.Latest).First().Key);
                    _slots[key] = state = new Slot();
                }
                foreach (var k in state.Seen.Where(v => at - v.Value > window)
                    .Select(v => v.Key).ToArray()) state.Seen.Remove(k);
                foreach (var k in state.Distinct.Where(v => at - v.Value > window)
                    .Select(v => v.Key).ToArray()) state.Distinct.Remove(k);
                count = state.Distinct.Count;
                if (at < state.Latest || state.Seen.ContainsKey(id))
                    return false;
                state.Latest = at;
                if (state.Seen.Count >= 256)
                    state.Seen.Remove(state.Seen.OrderBy(v => v.Value).First().Key);
                state.Seen[id] = at;
                if (state.Distinct.Count >= 256 && !state.Distinct.ContainsKey(asn))
                    state.Distinct.Remove(state.Distinct.OrderBy(v => v.Value).First().Key);
                state.Distinct[asn] = at;
                count = state.Distinct.Count;
                return true;
            }
        }
    }
}
