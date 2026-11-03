// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed.
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // Shared state and exact network boundaries for R580-R584. This helper does
    // not trust freeform Info, imported event labels, port numbers or payloads.
    internal static class CrossBoundaryRequestEvidence
    {
        internal static bool TryPair(TrafficRecord record, bool publicToPrivate,
            out string source, out string targetSubnet)
        {
            source = string.Empty;
            targetSubnet = string.Empty;
            if (record.IpVersion != 4 || record.Id == Guid.Empty)
                return false;
            if (publicToPrivate)
                return TryPublic24(record.Source, out source, out _)
                    && TryPrivate24(record.Destination, out _, out targetSubnet);
            return TryPrivate24(record.Source, out source, out _)
                && TryPublic24(record.Destination, out _, out targetSubnet);
        }

        internal static bool Tcp(TrafficRecord record, int minLength, int maxLength)
            => record.Id != Guid.Empty && record.IpVersion == 4
                && record.IsTcp && !record.IsUdp && !record.IsQuic
                && string.Equals(record.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                && record.SourcePort is >= 1024 and <= 65535
                && record.L4Len is not null
                && record.L4Len >= minLength && record.L4Len <= maxLength
                && record.Length >= record.L4Len.Value + 40
                && record.TlsVersion == null && record.Sni == null && record.Alpn == null
                && record.DnsQname == null && record.DnsQtype == null
                && record.DnsRcode == null && record.DnsAnswers == null;

        internal static bool Udp(TrafficRecord record, int minLength, int maxLength)
            => record.Id != Guid.Empty && record.IpVersion == 4
                && record.IsUdp && !record.IsTcp && !record.IsQuic
                && string.Equals(record.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
                && record.L4Len is not null
                && record.L4Len >= minLength && record.L4Len <= maxLength
                && record.Length >= record.L4Len.Value + 28
                && record.TlsVersion == null && record.Sni == null && record.Alpn == null
                && record.DnsQname == null && record.DnsQtype == null
                && record.DnsRcode == null && record.DnsAnswers == null
                && record.HttpMethod == null && record.HttpUri == null
                && record.HttpHost == null && record.HttpRequestHeaders == null;

        internal static bool NoHttpOrConflictingParserFlags(TrafficRecord record)
            => record.HttpMethod == null && record.HttpUri == null
                && record.HttpHost == null && record.HttpRequestHeaders == null
                && !record.HttpBasicDefaultCredentialObserved
                && !record.HttpGitHubTokenPatternObserved
                && !record.HttpGitLabTokenPatternObserved
                && !record.RedisRespConfigSetReplyOkObserved
                && !record.RedisRespConfigSetReplyErrorObserved;

        internal static bool NoRedisParserFlags(TrafficRecord record)
            => !record.RedisRespConfigSetRequestObserved
                && !record.RedisRespConfigSetReplyOkObserved
                && !record.RedisRespConfigSetReplyErrorObserved;

        private static bool TryPrivate24(string? raw, out string address, out string subnet)
        {
            address = subnet = string.Empty;
            if (!IPAddress.TryParse(raw, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            var b = ip.GetAddressBytes();
            if (!(b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31)
                || (b[0] == 192 && b[1] == 168)))
                return false;
            address = ip.ToString();
            subnet = b[0] + "." + b[1] + "." + b[2] + ".0/24";
            return true;
        }

        private static bool TryPublic24(string? raw, out string address, out string subnet)
        {
            address = subnet = string.Empty;
            if (!NetworkBatch226230Evidence.Public(raw)
                || !IPAddress.TryParse(raw, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            var b = ip.GetAddressBytes();
            if (b[0] is 0 or 10 or 127 or >= 224
                || (b[0] == 100 && b[1] is >= 64 and <= 127)
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 172 && b[1] is >= 16 and <= 31)
                || (b[0] == 192 && (b[1] == 0 || b[1] == 168
                    || b[1] == 88 && b[2] == 99))
                || (b[0] == 198 && (b[1] is 18 or 19
                    || b[1] == 51 && b[2] == 100))
                || (b[0] == 203 && b[1] == 0 && b[2] == 113))
                return false;
            address = ip.ToString();
            subnet = b[0] + "." + b[1] + "." + b[2] + ".0/24";
            return true;
        }
    }

    internal enum FanoutObservation { None, Match, Suppressed }

    // A per-rule instance: no shared cross-rule counters or global mutable state.
    internal sealed class CrossBoundaryRequestFanoutWindow
    {
        private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
        private const int MaxSources = 1024;
        private const int MaxSubnets = 32;
        private const int MaxIds = 128;

        private sealed class SourceState
        {
            internal readonly Dictionary<string, DateTime> Subnets = new(StringComparer.Ordinal);
            internal readonly Dictionary<Guid, DateTime> Seen = new();
            internal DateTime LastAt;
            internal DateTime? LastEmission;
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, SourceState> _sources = new(StringComparer.Ordinal);

        internal FanoutObservation Observe(string source, string subnet, Guid id, DateTime now)
        {
            if (id == Guid.Empty || string.IsNullOrEmpty(source) || string.IsNullOrEmpty(subnet))
                return FanoutObservation.None;
            lock (_gate)
            {
                if (!_sources.TryGetValue(source, out var state))
                {
                    if (_sources.Count >= MaxSources)
                    {
                        var staleSources = new List<string>();
                        foreach (var pair in _sources)
                            if (now >= pair.Value.LastAt && now - pair.Value.LastAt > Cooldown)
                                staleSources.Add(pair.Key);
                        foreach (var stale in staleSources)
                            _sources.Remove(stale);
                        if (_sources.Count >= MaxSources)
                            return FanoutObservation.None;
                    }
                    state = new SourceState();
                    _sources.Add(source, state);
                }
                if (now <= state.LastAt || state.Seen.ContainsKey(id))
                    return FanoutObservation.None;

                var staleIds = new List<Guid>();
                foreach (var pair in state.Seen)
                    if (now >= pair.Value && now - pair.Value > Window)
                        staleIds.Add(pair.Key);
                foreach (var stale in staleIds) state.Seen.Remove(stale);

                var staleSubnets = new List<string>();
                foreach (var pair in state.Subnets)
                    if (now >= pair.Value && now - pair.Value > Window)
                        staleSubnets.Add(pair.Key);
                foreach (var stale in staleSubnets) state.Subnets.Remove(stale);

                if (state.Seen.Count >= MaxIds
                    || (state.Subnets.Count >= MaxSubnets && !state.Subnets.ContainsKey(subnet)))
                    return FanoutObservation.None;
                state.Seen.Add(id, now);
                state.LastAt = now;
                if (!state.Subnets.ContainsKey(subnet))
                    state.Subnets.Add(subnet, now);
                if (state.Subnets.Count < 3)
                    return FanoutObservation.None;

                // Require three *fresh* distinct destination subnets for the next
                // observation. Never count a fourth packet as a second campaign.
                state.Subnets.Clear();
                if (state.LastEmission.HasValue && now >= state.LastEmission.Value
                    && now - state.LastEmission.Value < Cooldown)
                    return FanoutObservation.Suppressed;
                state.LastEmission = now;
                return FanoutObservation.Match;
            }
        }
    }
}
