// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Source-only; no runtime/test evidence.
using System;
using System.Collections.Generic;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // Shared evidence hygiene only. Each rule retains its own independent predicate.
    internal static class WebSignatureRequestEvidence
    {
        internal static bool TryGet(TrafficRecord record, out string method, out string uri, bool allowPut = false)
        {
            method = uri = string.Empty;
            if (record == null || record.Id == Guid.Empty
                || !record.IsTcp || record.IsUdp || record.IsQuic
                || !string.Equals(record.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(record.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                || record.SourcePort is null or <= 0 or > 65535
                || record.DestinationPort is null or <= 0 or > 65535
                || record.L4Len is null or < 16 or > 8192 || record.Length < 40
                || record.TlsVersion != null || record.Sni != null
                || record.DnsQname != null || record.DnsIsResponse
                || record.RedisRespConfigSetRequestObserved || record.RedisRespConfigSetReplyOkObserved
                || record.RedisRespConfigSetReplyErrorObserved
                || record.BacnetWritePropertyRequestObserved || record.LdapCleartextSimpleBindObserved
                || record.HttpUri == null || record.HttpUri.Length < 3 || record.HttpUri.Length > 1024
                || record.HttpUri[0] != '/'
                || (record.HttpMethod != "GET" && record.HttpMethod != "POST"
                    && !(allowPut && record.HttpMethod == "PUT")))
                return false;
            if (!IPAddress.TryParse(record.Source, out var source)
                || !IPAddress.TryParse(record.Destination, out var destination)
                || source.AddressFamily != destination.AddressFamily)
                return false;
            foreach (var c in record.HttpUri)
                if (c <= 0x1f || c == 0x7f) return false;
            method = record.HttpMethod;
            uri = record.HttpUri;
            return true;
        }
    }

    internal enum WebSignatureObservation { None, Match, Suppressed }

    // Per-rule, instance-owned cooldown; no cross-rule shared windows or convergence.
    internal sealed class WebSignatureCooldown
    {
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
        private const int MaxKeys = 1024;
        private readonly object _gate = new();
        private readonly Dictionary<string, (Guid Id, DateTime At)> _last = new(StringComparer.Ordinal);

        internal WebSignatureObservation Observe(string source, string destination, Guid id, DateTime at)
        {
            if (at.Kind != DateTimeKind.Utc || id == Guid.Empty)
                return WebSignatureObservation.None;
            var key = source + "|" + destination;
            lock (_gate)
            {
                if (_last.TryGetValue(key, out var prev))
                {
                    if (prev.Id == id || at <= prev.At) return WebSignatureObservation.None;
                    if (at - prev.At < Cooldown) return WebSignatureObservation.Suppressed;
                }
                else if (_last.Count >= MaxKeys)
                {
                    var expired = new List<string>();
                    foreach (var item in _last)
                        if (at >= item.Value.At && at - item.Value.At >= Cooldown)
                            expired.Add(item.Key);
                    foreach (var stale in expired) _last.Remove(stale);
                    if (_last.Count >= MaxKeys) return WebSignatureObservation.None;
                }
                _last[key] = (id, at);
                return WebSignatureObservation.Match;
            }
        }
    }
}
