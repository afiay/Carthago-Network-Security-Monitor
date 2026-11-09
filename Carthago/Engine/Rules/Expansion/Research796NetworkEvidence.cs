// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; shared field hygiene and bounded state, not converged rule predicates.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    internal static class Research796NetworkEvidence
    {
        internal static bool PrivateSource(TrafficRecord r)
            => r != null && IPAddress.TryParse(r.Source, out var ip)
                && Research646Evidence.Private(ip);

        internal static bool Base32TxtSubdomain(TrafficRecord r, out string domain)
        {
            domain = string.Empty;
            if (!Research786NetworkEvidence.DnsQuestion(r) || !r.IsUdp
                || !string.Equals(r.DnsQtype, "TXT", StringComparison.OrdinalIgnoreCase))
                return false;
            var qname = r.DnsQname!.TrimEnd('.');
            var dot = qname.IndexOf('.');
            if (dot < 36 || dot > 63 || dot + 4 >= qname.Length) return false;
            var hasDigit = false;
            for (var i = 0; i < dot; i++)
            {
                var ch = char.ToUpperInvariant(qname[i]);
                if (ch is >= '2' and <= '7') hasDigit = true;
                else if (ch is < 'A' or > 'Z') return false;
            }
            if (!hasDigit) return false;
            domain = qname.Substring(dot + 1).ToLowerInvariant();
            return domain.Contains('.') && domain.Length <= 190;
        }

        internal static bool CoapMulticast(TrafficRecord r)
        {
            if (!Research786NetworkEvidence.UdpData(r) || !PrivateSource(r)
                || r.DestinationPort != 5683
                || !string.Equals(r.ApplicationProtocol, "coap.discovery", StringComparison.Ordinal)
                || r.DnsQname != null || r.HttpMethod != null || r.TlsVersion != null
                || !IPAddress.TryParse(r.Destination, out var dst)) return false;
            var first = dst.GetAddressBytes()[0];
            return first is >= 224 and <= 239;
        }
    }

    internal sealed class Research796DnsThenTlsCadenceWindow
    {
        private sealed class Slot
        {
            internal DateTime First, Last;
            internal int Count, LastLength;
            internal bool Active;
            internal readonly HashSet<Guid> Ids = new();
        }
        private readonly object _gate = new();
        private readonly Dictionary<string, Slot> _slots = new(StringComparer.Ordinal);

        internal bool Observe(string key, Guid id, DateTime at, bool query, int length)
        {
            if (string.IsNullOrWhiteSpace(key) || id == Guid.Empty
                || at.Kind != DateTimeKind.Utc) return false;
            lock (_gate)
            {
                if (!_slots.TryGetValue(key, out var slot))
                {
                    if (!query) return false;
                    if (_slots.Count >= 512)
                    {
                        foreach (var stale in _slots.Where(x => at >= x.Value.Last
                            && at - x.Value.Last > TimeSpan.FromMinutes(5))
                            .Select(x => x.Key).ToArray()) _slots.Remove(stale);
                        if (_slots.Count >= 512) return false;
                    }
                    slot = new Slot { Last = DateTime.MinValue };
                    _slots.Add(key, slot);
                }
                if (at <= slot.Last || slot.Ids.Contains(id)) return false;
                if (query)
                {
                    slot.Ids.Clear(); slot.Ids.Add(id);
                    slot.First = slot.Last = at;
                    slot.LastLength = 0; slot.Count = 0; slot.Active = true;
                    return false;
                }
                if (!slot.Active || length is < 128 or > 512
                    || at - slot.First > TimeSpan.FromSeconds(120)
                    || (at - slot.Last).TotalSeconds is < 12 or > 40
                    || (slot.Count > 0 && Math.Abs(length - slot.LastLength) > 48))
                {
                    slot.Active = false; slot.Last = at; slot.Ids.Add(id);
                    return false;
                }
                slot.Last = at;
                slot.LastLength = length;
                slot.Ids.Add(id);
                slot.Count++;
                if (slot.Count < 3) return false;
                slot.Active = false;
                return true;
            }
        }
    }
}
