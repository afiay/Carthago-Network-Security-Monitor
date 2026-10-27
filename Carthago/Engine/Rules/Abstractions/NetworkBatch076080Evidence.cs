// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules.AssetInventory;
using Carthago.Models;

namespace Carthago.Engine.Rules
{
    // Trust only explicitly parsed L7 classifications, never human-readable packet Info.
    // Classification must be populated by an audited capture adapter; otherwise fail closed.
    internal static class NetworkBatch076080Evidence
    {
        internal static bool InternalTcp(RuleEvaluationContext c, int port,
            out string source, out string target)
        {
            source = target = "";
            var r = c.Record;
            if (!ValidTime(c) || r.Id == Guid.Empty || (r.IpVersion.HasValue && r.IpVersion != 4)
                || !AssetNetworkEvidence.Private(r.Source, out source)
                || !AssetNetworkEvidence.Private(r.Destination, out target) || source == target
                || !string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || !r.IsTcp || r.IsUdp || r.IsQuic || r.IcmpTypeCode.HasValue
                || r.DnsIsResponse || r.DnsQname != null || r.HttpMethod != null
                || r.DestinationPort != port || r.SourcePort is not int sp || sp is < 1 or > 65535)
                return false;
            // A SYN, FIN or RST is not evidence of an L7 request.
            if (r.TcpFlags is ushort flags &&
                ((flags & 0x07) != 0 || (flags & 0x18) == 0)) return false;
            return true;
        }

        internal static bool InternalKerberos(RuleEvaluationContext c,
            out string source, out string target)
        {
            source = target = "";
            var r = c.Record;
            if (!ValidTime(c) || r.Id == Guid.Empty || (r.IpVersion.HasValue && r.IpVersion != 4)
                || !AssetNetworkEvidence.Private(r.Source, out source)
                || !AssetNetworkEvidence.Private(r.Destination, out target) || source == target
                || r.DestinationPort != 88 || r.SourcePort is not int sp || sp is < 1 or > 65535
                || r.IsQuic || r.IcmpTypeCode.HasValue || r.DnsIsResponse
                || r.DnsQname != null || r.HttpMethod != null) return false;
            if (string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase))
                return r.IsTcp && !r.IsUdp && (!r.TcpFlags.HasValue ||
                    ((r.TcpFlags.Value & 0x07) == 0 && (r.TcpFlags.Value & 0x18) != 0));
            return string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
                   && r.IsUdp && !r.IsTcp && !r.TcpFlags.HasValue;
        }

        internal static bool Classification(TrafficRecord r, string protocol, string service)
            => string.Equals(r.ApplicationProtocol?.Trim(), protocol, StringComparison.OrdinalIgnoreCase)
               && string.Equals(r.ApplicationService?.Trim(), service, StringComparison.OrdinalIgnoreCase);

        internal static bool ValidTime(RuleEvaluationContext c)
            => c.TimestampUtc.Kind == DateTimeKind.Utc
               && c.TimestampUtc <= DateTime.UtcNow.AddMinutes(1);

        internal static RuleEvaluationResult Result(RuleDescriptor d, RuleEvaluationContext c, string summary)
            => RuleEvaluationResult.Match(d.RuleId, NetworkBatch071075Evidence.Alert(d, c, summary));
    }

    // Corroborate two different classified actions, in order, on the same internal flow.
    // Per-instance state does not imply persistent authorization or a verified process identity.
    internal sealed class NetworkBatch076080Sequence
    {
        private sealed class Entry
        {
            internal DateTime Last;
            internal DateTime ShareAt;
            internal Guid LastRecord;
            internal bool Reported;
        }
        private readonly Dictionary<string, Entry> _flows = new(StringComparer.Ordinal);
        private readonly object _gate = new();
        internal bool Observe(string flow, bool share, Guid recordId, DateTime now, TimeSpan window)
        {
            lock (_gate)
            {
                foreach (var expired in _flows.Where(x => now - x.Value.Last > window)
                    .Select(x => x.Key).ToArray()) _flows.Remove(expired);
                if (!_flows.TryGetValue(flow, out var e))
                {
                    if (_flows.Count >= 2048)
                        _flows.Remove(_flows.OrderBy(x => x.Value.Last).First().Key);
                    _flows[flow] = e = new Entry();
                }
                if (now <= e.Last || recordId == e.LastRecord) return false;
                e.Last = now;
                e.LastRecord = recordId;
                if (share)
                {
                    if (e.ShareAt == default || now - e.ShareAt > window)
                    {
                        e.ShareAt = now;
                        e.Reported = false;
                    }
                    return false;
                }
                if (e.ShareAt == default || now - e.ShareAt > window || e.Reported) return false;
                e.Reported = true;
                return true;
            }
        }
    }
}
