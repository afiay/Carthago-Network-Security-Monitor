// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Shared evidence hygiene/state only; no rule convergence.
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    internal static class Research706Evidence
    {
        internal static bool PublicToPrivate(TrafficRecord r)
            => Research646Evidence.Pair(r, true, out _, out _);

        internal static bool PrivateToPublic(TrafficRecord r)
            => Research646Evidence.Pair(r, false, out _, out _);

        internal static bool PrivatePair(TrafficRecord r)
            => Research676Evidence.PrivatePair(r, out _, out _);

        internal static bool Process(TrafficRecord r, params string[] names)
            => Research676Evidence.Process(r, names);

        internal static bool TcpSyn(TrafficRecord r)
            => r != null && r.Id != Guid.Empty && r.IpVersion == 4
               && r.IsTcp && !r.IsUdp && !r.IsQuic
               && string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
               && r.SourcePort is > 0 and <= 65535
               && r.DestinationPort is > 0 and <= 65535
               && r.TcpFlags == 0x02
               && r.L4Len is null or 0 && r.Length >= 40
               && r.HttpMethod == null && r.DnsQname == null && r.TlsVersion == null
               && r.ApplicationProtocol == null;

        internal static bool TcpPayload(TrafficRecord r)
            => r != null && r.Id != Guid.Empty && r.IpVersion == 4
               && r.IsTcp && !r.IsUdp && !r.IsQuic
               && string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
               && r.SourcePort is > 0 and <= 65535
               && r.DestinationPort is > 0 and <= 65535
               && r.TcpFlags != 0x02
               && r.L4Len is >= 32 and <= 4096 && r.Length >= 72
               && r.HttpMethod == null && r.DnsQname == null && r.TlsVersion == null
               && r.ApplicationProtocol == null;

        internal static bool Udp(TrafficRecord r)
            => r != null && r.Id != Guid.Empty && r.IpVersion == 4
               && !r.IsTcp && r.IsUdp && !r.IsQuic
               && string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
               && r.SourcePort is > 0 and <= 65535
               && r.DestinationPort is > 0 and <= 65535
               && r.TcpFlags == null
               && r.L4Len is >= 1 and <= 8192 && r.Length >= 28
               && r.HttpMethod == null && r.TlsVersion == null && r.Sni == null
               && r.DnsQname == null;

        internal static bool AdminPort(int? port)
            => port is 22 or 23 or 443 or 445 or 3389 or 5985 or 5986;

        internal static bool Netcat(TrafficRecord r)
            => r != null && (r.ProcessId > 0 && string.Equals(r.ProcessName?.Trim(), "nc", StringComparison.OrdinalIgnoreCase)
                || Process(r, "nc.exe", "ncat", "ncat.exe", "netcat", "netcat.exe",
                "nc.openbsd", "nc.traditional", "netcat.openbsd", "netcat.traditional"));

        internal static bool Plink(TrafficRecord r)
            => Process(r, "plink", "plink.exe", "putty", "putty.exe");

        internal static bool Socat(TrafficRecord r)
            => Process(r, "socat", "socat.exe");

        internal static bool OversizedManagementHttp(TrafficRecord r)
        {
            if (r == null || r.Id == Guid.Empty || r.IpVersion != 4
                || !r.IsTcp || r.IsUdp || r.IsQuic
                || !string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(r.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                || r.SourcePort is null or <= 0 or > 65535
                || r.DestinationPort is not (80 or 8000 or 8080 or 8081 or 8888)
                || r.L4Len is null or < 16 or > 8192 || r.Length < 40
                || r.TlsVersion != null || r.Sni != null || r.DnsQname != null || r.DnsIsResponse
                || r.HttpMethod is not ("GET" or "POST")
                || string.IsNullOrEmpty(r.HttpUri) || r.HttpUri.Length is <= 1024 or > 8192
                || r.HttpUri[0] != '/'
                || r.RedisRespConfigSetRequestObserved || r.RedisRespConfigSetReplyOkObserved
                || r.RedisRespConfigSetReplyErrorObserved || r.BacnetWritePropertyRequestObserved
                || r.LdapCleartextSimpleBindObserved
                || !PublicToPrivate(r))
                return false;

            foreach (var c in r.HttpUri)
                if (c <= 0x1f || c == 0x7f) return false;
            return true;
        }
    }

    internal sealed class Research706DistinctWindow
    {
        private sealed class Slot
        {
            internal DateTime First;
            internal DateTime Latest = DateTime.MinValue;
            internal readonly HashSet<Guid> Ids = new();
            internal readonly HashSet<string> Signals = new(StringComparer.Ordinal);
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, Slot> _slots = new(StringComparer.Ordinal);

        internal bool Observe(string key, string signal, Guid id, DateTime at, int threshold, int windowSeconds)
        {
            if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(signal)
                || id == Guid.Empty || at.Kind != DateTimeKind.Utc
                || threshold is < 2 or > 6 || windowSeconds is < 5 or > 300)
                return false;

            lock (_gate)
            {
                if (!_slots.TryGetValue(key, out var slot))
                {
                    if (_slots.Count >= 512)
                    {
                        foreach (var stale in _slots
                            .Where(x => at >= x.Value.Latest && at - x.Value.Latest > TimeSpan.FromMinutes(10))
                            .Select(x => x.Key).ToArray())
                            _slots.Remove(stale);
                        if (_slots.Count >= 512) return false;
                    }
                    slot = new Slot { First = at };
                    _slots.Add(key, slot);
                }

                if (at <= slot.Latest || slot.Ids.Contains(id)) return false;
                if (at - slot.First > TimeSpan.FromSeconds(windowSeconds))
                {
                    slot.First = at;
                    slot.Ids.Clear();
                    slot.Signals.Clear();
                }

                if (slot.Ids.Count >= 64) return false;
                slot.Ids.Add(id);
                slot.Signals.Add(signal);
                slot.Latest = at;

                if (slot.Signals.Count < threshold) return false;
                slot.First = at;
                slot.Ids.Clear();
                slot.Signals.Clear();
                return true;
            }
        }
    }

    internal sealed class Research706KnockWindow
    {
        private sealed class Slot
        {
            internal DateTime First;
            internal DateTime Latest = DateTime.MinValue;
            internal readonly HashSet<Guid> Ids = new();
            internal readonly HashSet<int> Ports = new();
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, Slot> _slots = new(StringComparer.Ordinal);

        internal bool Observe(string key, int port, Guid id, DateTime at, bool final)
        {
            if (string.IsNullOrWhiteSpace(key) || port is <= 0 or > 65535
                || id == Guid.Empty || at.Kind != DateTimeKind.Utc)
                return false;

            lock (_gate)
            {
                if (final)
                {
                    if (!_slots.TryGetValue(key, out var existing)
                        || existing.Ids.Contains(id) || at <= existing.Latest
                        || at - existing.First > TimeSpan.FromSeconds(60)
                        || existing.Ports.Count != 3)
                        return false;
                    _slots.Remove(key);
                    return true;
                }

                if (!_slots.TryGetValue(key, out var slot))
                {
                    if (_slots.Count >= 512)
                    {
                        foreach (var stale in _slots
                            .Where(x => at >= x.Value.Latest && at - x.Value.Latest > TimeSpan.FromMinutes(2))
                            .Select(x => x.Key).ToArray())
                            _slots.Remove(stale);
                        if (_slots.Count >= 512) return false;
                    }
                    slot = new Slot { First = at };
                    _slots.Add(key, slot);
                }

                if (slot.Ids.Contains(id) || at <= slot.Latest) return false;
                if (at - slot.First > TimeSpan.FromSeconds(60))
                {
                    slot.First = at;
                    slot.Ids.Clear();
                    slot.Ports.Clear();
                }

                slot.Ids.Add(id);
                slot.Latest = at;
                slot.Ports.Add(port);
                if (slot.Ports.Count <= 3) return false;

                slot.First = at;
                slot.Ids.Clear();
                slot.Ports.Clear();
                slot.Ids.Add(id);
                slot.Ports.Add(port);
                return false;
            }
        }
    }

    internal sealed class Research706TftpWindow
    {
        private sealed class Start
        {
            internal Guid Id;
            internal int ClientPort;
            internal DateTime At;
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, Start> _starts = new(StringComparer.Ordinal);

        internal bool Observe(string key, bool request, int clientPort, Guid id, DateTime at)
        {
            if (string.IsNullOrWhiteSpace(key) || clientPort is <= 1024 or > 65535
                || id == Guid.Empty || at.Kind != DateTimeKind.Utc)
                return false;

            lock (_gate)
            {
                if (request)
                {
                    if (_starts.Count >= 512)
                    {
                        foreach (var stale in _starts
                            .Where(x => at >= x.Value.At && at - x.Value.At > TimeSpan.FromMinutes(2))
                            .Select(x => x.Key).ToArray())
                            _starts.Remove(stale);
                        if (_starts.Count >= 512) return false;
                    }

                    if (_starts.TryGetValue(key, out var prior) && at <= prior.At) return false;
                    _starts[key] = new Start { Id = id, ClientPort = clientPort, At = at };
                    return false;
                }

                if (!_starts.TryGetValue(key, out var start)
                    || start.Id == id || start.ClientPort != clientPort
                    || at <= start.At || at - start.At > TimeSpan.FromSeconds(30))
                    return false;

                _starts.Remove(key);
                return true;
            }
        }
    }
}
