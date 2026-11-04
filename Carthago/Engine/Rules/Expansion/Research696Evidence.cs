// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Evidence hygiene and bounded pair state only.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    internal static class Research696Evidence
    {
        internal static bool OfficeSuspiciousGet(TrafficRecord r)
        {
            if (!Research686Evidence.Process(r, "winword.exe", "excel.exe", "powerpnt.exe", "msoxmled.exe")
                || !Research686Evidence.PrivateToPublic(r)
                || !WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || method != "GET")
                return false;
            return Research686Evidence.SuspiciousFilePath(uri);
        }

        internal static bool OtProtocolMismatch(TrafficRecord r)
        {
            if (r == null || r.Id == Guid.Empty || r.IpVersion != 4
                || !r.IsTcp || r.IsUdp || r.IsQuic
                || !string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || r.SourcePort is null or <= 0 or > 65535
                || r.DestinationPort is null
                || r.Length < 40 || r.L4Len is null or < 4 or > 4096
                || string.IsNullOrWhiteSpace(r.ApplicationProtocol)
                || r.DnsQname != null)
                return false;

            var boundary = Research646Evidence.Pair(r, true, out _, out _)
                || Research676Evidence.PrivatePair(r, out _, out _);
            if (!boundary) return false;

            var protocol = r.ApplicationProtocol!;
            return r.DestinationPort switch
            {
                102 => !protocol.Equals("s7comm", StringComparison.OrdinalIgnoreCase),
                44818 => !protocol.StartsWith("ethernetip.", StringComparison.OrdinalIgnoreCase),
                4840 => !protocol.StartsWith("opcua", StringComparison.OrdinalIgnoreCase),
                _ => false
            };
        }

        internal static bool RawPublicUdp(TrafficRecord r, params string[] processes)
        {
            if (!Research686Evidence.Process(r, processes)
                || !Research646Evidence.Pair(r, false, out _, out _)
                || r.IsTcp || !r.IsUdp || r.IsQuic
                || !string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
                || r.SourcePort is null or <= 0 or > 65535
                || r.DestinationPort is null or <= 1024 or > 65535
                || r.DestinationPort is 1900 or 3478 or 4500 or 5353
                || r.DnsQname != null || r.HttpMethod != null || r.TlsVersion != null
                || r.ApplicationProtocol != null || r.ApplicationService != null
                || r.L4Len is null or < 80 or > 1200 || r.Length < r.L4Len.Value + 20)
                return false;
            return true;
        }
    }

    internal sealed class Research696RelayWindow
    {
        private sealed class Start
        {
            internal Guid Id;
            internal string Peer = "";
            internal DateTime At;
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, Start> _pending = new(StringComparer.Ordinal);

        internal bool Observe(string key, string peer, Guid id, DateTime at, bool first)
        {
            if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(peer)
                || id == Guid.Empty || at.Kind != DateTimeKind.Utc)
                return false;

            lock (_gate)
            {
                if (first)
                {
                    if (_pending.Count >= 512)
                    {
                        foreach (var stale in _pending
                            .Where(x => at >= x.Value.At && at - x.Value.At > TimeSpan.FromMinutes(2))
                            .Select(x => x.Key).ToArray())
                            _pending.Remove(stale);
                        if (_pending.Count >= 512) return false;
                    }
                    if (_pending.TryGetValue(key, out var previous) && at <= previous.At)
                        return false;
                    _pending[key] = new Start { Id = id, Peer = peer, At = at };
                    return false;
                }

                if (!_pending.TryGetValue(key, out var start)
                    || start.Id == id || at <= start.At
                    || at - start.At > TimeSpan.FromSeconds(30)
                    || start.Peer.Equals(peer, StringComparison.Ordinal))
                    return false;

                _pending.Remove(key);
                return true;
            }
        }
    }
}
