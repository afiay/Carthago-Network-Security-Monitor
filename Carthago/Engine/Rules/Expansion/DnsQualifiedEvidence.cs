// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    internal static class DnsQualifiedEvidence
    {
        internal static bool Message(TrafficRecord r)
            => r.DnsValidatedTransactionId.HasValue && r.DnsValidatedAQuestion
                && r.DnsQtype == "A" && r.ApplicationProtocol == "DNS"
                && !string.IsNullOrWhiteSpace(r.DnsQname) && r.DnsQname.Length <= 253
                && string.Equals(r.DnsQname.TrimEnd('.'), r.DnsValidatedQuestionName, StringComparison.OrdinalIgnoreCase)
                && r.HttpMethod == null && r.HttpUri == null && r.TlsVersion == null && r.Sni == null;
        internal static string Key(TrafficRecord r, bool query)
            => (query ? r.Source! + "|" + r.Destination! + "|" + r.SourcePort
                : r.Destination! + "|" + r.Source! + "|" + r.DestinationPort)
                + "|" + r.DnsValidatedTransactionId!.Value
                + "|" + r.DnsValidatedQuestionName!.ToLowerInvariant();
    }

    // Instance-owned exact transaction-to-PID association; one consumed response per query.
    internal sealed class DnsQualifiedQueryWindow
    {
        private readonly object _gate = new();
        private readonly Dictionary<string, Pending> _pending = new(StringComparer.Ordinal);
        private readonly record struct Pending(Guid Id, int Pid, DateTime At);
        private const int MaxPending = 1024;
        private static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(45);

        internal void Observe(string key, Guid id, int pid, DateTime at)
        {
            if (id == Guid.Empty || pid <= 0 || at.Kind != DateTimeKind.Utc) return;
            lock (_gate)
            {
                if (_pending.TryGetValue(key, out var previous))
                {
                    if (at <= previous.At || previous.Id == id) return;
                    if (at - previous.At <= Lifetime)
                    {
                        // Retransmit does not extend lifetime; a conflicting PID is ambiguous.
                        if (previous.Pid != pid) _pending.Remove(key);
                        return;
                    }
                    _pending.Remove(key);
                }
                if (_pending.Count >= MaxPending)
                {
                    var stale = new List<string>();
                    foreach (var item in _pending)
                        if (at >= item.Value.At && at - item.Value.At > Lifetime) stale.Add(item.Key);
                    foreach (var k in stale) _pending.Remove(k);
                    if (_pending.Count >= MaxPending) return;
                }
                _pending.Add(key, new Pending(id, pid, at));
            }
        }
        internal bool TryConsume(string key, Guid id, DateTime at, out int pid)
        {
            pid = 0;
            if (id == Guid.Empty || at.Kind != DateTimeKind.Utc) return false;
            lock (_gate)
            {
                if (!_pending.TryGetValue(key, out var prior) || at <= prior.At || id == prior.Id)
                    return false;
                if (at - prior.At > Lifetime) { _pending.Remove(key); return false; }
                _pending.Remove(key);
                pid = prior.Pid;
                return true;
            }
        }
    }
}
