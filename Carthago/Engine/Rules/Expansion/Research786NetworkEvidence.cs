// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Shared typed-field hygiene and bounded instance-owned state only.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    internal static class Research786NetworkEvidence
    {
        internal static bool Coherent(TrafficRecord? r)
        {
            if (r == null || r.Id == Guid.Empty || r.IpVersion != 4
                || r.IsTcp == r.IsUdp || r.IsQuic
                || r.SourcePort is null or <= 0 or > 65535
                || r.DestinationPort is null or <= 0 or > 65535
                || r.Length < (r.IsTcp ? 40 : 28)
                || !IPAddress.TryParse(r.Source, out var src)
                || !IPAddress.TryParse(r.Destination, out var dst)
                || src.AddressFamily != AddressFamily.InterNetwork
                || dst.AddressFamily != AddressFamily.InterNetwork) return false;

            return r.IsTcp
                ? string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                : string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
                    && r.TcpFlags == null;
        }

        internal static bool TcpData(TrafficRecord? r)
            => Coherent(r) && r!.IsTcp && r.TcpFlags == 0x18
                && r.L4Len is >= 1 and <= 8192 && r.Length >= r.L4Len!.Value + 40;

        internal static bool UdpData(TrafficRecord? r)
            => Coherent(r) && r!.IsUdp && r.L4Len is >= 1 and <= 8192
                && r.Length >= r.L4Len!.Value + 28;

        internal static bool DnsQuestion(TrafficRecord? r)
            => (TcpData(r) || UdpData(r))
                && r!.DestinationPort == 53
                && string.Equals(r.ApplicationProtocol, "DNS", StringComparison.OrdinalIgnoreCase)
                && !r.DnsIsResponse
                && !string.IsNullOrWhiteSpace(r.DnsQname) && r.DnsQname.Length <= 253
                && !string.IsNullOrWhiteSpace(r.DnsQtype)
                && r.HttpMethod == null && r.HttpUri == null
                && r.TlsVersion == null && r.Sni == null;

        internal static bool PrivatePublic(TrafficRecord r) => Research676Evidence.PrivateToPublic(r);
        internal static bool PublicPrivate(TrafficRecord r) => Research676Evidence.PublicToPrivate(r);
        internal static bool Internal(TrafficRecord r) => Research676Evidence.PrivatePair(r, out _, out _);

        internal static string Subnet24(string ip)
        {
            var bytes = IPAddress.Parse(ip).GetAddressBytes();
            return bytes[0] + "." + bytes[1] + "." + bytes[2];
        }
    }

    internal sealed class Research786TwoStageWindow
    {
        private sealed class Slot
        {
            internal DateTime First, Last;
            internal Guid InitialId;
            internal bool Started;
            internal readonly HashSet<Guid> Ids = new();
        }
        private readonly object _gate = new();
        private readonly Dictionary<string, Slot> _slots = new(StringComparer.Ordinal);
        internal bool Observe(string key, Guid id, DateTime at, bool initial, int seconds)
        {
            if (string.IsNullOrWhiteSpace(key) || id == Guid.Empty
                || at.Kind != DateTimeKind.Utc || seconds is < 5 or > 180) return false;
            lock (_gate)
            {
                if (!_slots.TryGetValue(key, out var slot))
                {
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
                if (slot.Ids.Count >= 64) { slot.Ids.Clear(); slot.Started = false; }
                if (initial)
                {
                    slot.First = slot.Last = at;
                    slot.InitialId = id;
                    slot.Ids.Add(id);
                    slot.Started = true;
                    return false;
                }
                if (!slot.Started || id == slot.InitialId
                    || at - slot.First > TimeSpan.FromSeconds(seconds))
                {
                    slot.Last = at;
                    slot.Started = false;
                    slot.Ids.Add(id);
                    return false;
                }
                slot.Last = at;
                slot.Ids.Add(id);
                slot.Started = false;
                return true;
            }
        }
    }

    internal sealed class Research786IssuerShiftWindow
    {
        private sealed class Slot
        {
            internal string Issuer = string.Empty;
            internal DateTime First, Last;
            internal readonly HashSet<Guid> Ids = new();
        }
        private readonly object _gate = new();
        private readonly Dictionary<string, Slot> _slots = new(StringComparer.Ordinal);
        internal bool Observe(string key, Guid id, string issuer, DateTime at)
        {
            if (string.IsNullOrWhiteSpace(key) || id == Guid.Empty
                || string.IsNullOrWhiteSpace(issuer) || issuer.Length > 512
                || at.Kind != DateTimeKind.Utc) return false;
            lock (_gate)
            {
                if (_slots.TryGetValue(key, out var slot))
                {
                    if (at <= slot.Last || slot.Ids.Contains(id)) return false;
                    if (at - slot.First <= TimeSpan.FromSeconds(180)
                        && !string.Equals(slot.Issuer, issuer, StringComparison.Ordinal))
                    {
                        _slots.Remove(key);
                        return true;
                    }
                    if (at - slot.First > TimeSpan.FromSeconds(180))
                    {
                        slot.First = at; slot.Issuer = issuer; slot.Ids.Clear();
                    }
                    slot.Last = at;
                    slot.Ids.Add(id);
                    return false;
                }
                if (_slots.Count >= 512)
                {
                    foreach (var stale in _slots.Where(x => at >= x.Value.Last
                        && at - x.Value.Last > TimeSpan.FromMinutes(5))
                        .Select(x => x.Key).ToArray()) _slots.Remove(stale);
                    if (_slots.Count >= 512) return false;
                }
                var created = new Slot { Issuer = issuer, First = at, Last = at };
                created.Ids.Add(id);
                _slots.Add(key, created);
                return false;
            }
        }
    }

    internal sealed class Research786BridgeWindow
    {
        private sealed class Slot
        {
            internal string OriginPrefix = string.Empty;
            internal Guid Id;
            internal DateTime At;
        }
        private readonly object _gate = new();
        private readonly Dictionary<string, Slot> _slots = new(StringComparer.Ordinal);
        internal bool Observe(string relay, string peer, Guid id, DateTime at, bool initial)
        {
            if (string.IsNullOrEmpty(relay) || string.IsNullOrEmpty(peer)
                || id == Guid.Empty || at.Kind != DateTimeKind.Utc) return false;
            lock (_gate)
            {
                if (initial)
                {
                    if (_slots.TryGetValue(relay, out var previous) && at <= previous.At)
                        return false;
                    if (_slots.Count >= 512 && !_slots.ContainsKey(relay))
                    {
                        foreach (var stale in _slots.Where(x => at >= x.Value.At
                            && at - x.Value.At > TimeSpan.FromMinutes(5))
                            .Select(x => x.Key).ToArray()) _slots.Remove(stale);
                        if (_slots.Count >= 512) return false;
                    }
                    _slots[relay] = new Slot { OriginPrefix = Research786NetworkEvidence.Subnet24(peer),
                        Id = id, At = at };
                    return false;
                }
                if (!_slots.TryGetValue(relay, out var start) || start.Id == id
                    || at <= start.At || at - start.At > TimeSpan.FromSeconds(60)
                    || Research786NetworkEvidence.Subnet24(peer) == start.OriginPrefix
                    || Research786NetworkEvidence.Subnet24(peer) == Research786NetworkEvidence.Subnet24(relay))
                    return false;
                _slots.Remove(relay);
                return true;
            }
        }
    }
}
