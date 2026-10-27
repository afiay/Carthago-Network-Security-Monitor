// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // R141-R145 require network-observed, typed TLS. Neither packet Info,
    // HTTPS port numbers nor untrusted HTTP/DNS hostnames establish an SNI.
    internal static class NetworkBatch141145Evidence
    {
        internal static bool TlsSession(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch076080Evidence.ValidTime(context)
                || !NetworkBatch136140Evidence.TlsSession(r)
                || r.DestinationPort is not int port || port is < 1 or > 65535
                || !IPAddress.TryParse(r.Source, out var source)
                || !IPAddress.TryParse(r.Destination, out var destination)
                || source.Equals(destination) || source.AddressFamily != destination.AddressFamily
                || r.IpVersion is not (null or 4 or 6)
                || r.IpVersion == 4 && source.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
                || r.IpVersion == 6 && source.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                return false;

            if (!string.IsNullOrWhiteSpace(r.Sni) && !string.IsNullOrWhiteSpace(r.TlsSni)
                && !string.Equals(r.Sni.Trim().TrimEnd('.'), r.TlsSni.Trim().TrimEnd('.'),
                    StringComparison.OrdinalIgnoreCase))
                return false;
            return true;
        }

        internal static string? Sni(TrafficRecord record)
        {
            var raw = string.IsNullOrWhiteSpace(record.TlsSni) ? record.Sni : record.TlsSni;
            if (string.IsNullOrWhiteSpace(raw) || raw.Length > 253)
                return null;
            var host = raw.Trim().TrimEnd('.').ToLowerInvariant();
            if (host.Length < 4 || !host.Contains('.')
                || IPAddress.TryParse(host, out _))
                return null;
            var labels = host.Split('.');
            if (labels.Any(static label => label.Length is < 1 or > 63
                || label[0] == '-' || label[^1] == '-'
                || label.Any(static ch => !char.IsAsciiLetterOrDigit(ch) && ch != '-')))
                return null;
            return host;
        }

        internal static string? Fingerprint(TrafficRecord record)
        {
            var raw = string.IsNullOrWhiteSpace(record.Ja4) ? record.Ja3 : record.Ja4;
            if (string.IsNullOrWhiteSpace(raw))
                return null;
            var fingerprint = raw.Trim();
            if (fingerprint.Length is < 6 or > 256
                || fingerprint.Any(static ch => !char.IsAsciiLetterOrDigit(ch)
                    && ch is not ('_' or '-' or '.' or ':' or ',')))
                return null;
            return fingerprint;
        }

        internal static bool CertificateSubject(TrafficRecord record)
            => !string.IsNullOrWhiteSpace(record.CertSubject)
                && record.CertSubject.Length <= 512
                && !record.CertSubject.Any(char.IsControl);

        internal static bool CertificateLifetime(TrafficRecord record, out double days)
        {
            days = 0;
            if (!record.CertValidFrom.HasValue || !record.CertValidTo.HasValue)
                return false;
            days = (record.CertValidTo.Value - record.CertValidFrom.Value).TotalDays;
            return days > 0 && days <= 36500;
        }
    }

    // Per-rule-instance bounded observations. A duplicate packet ID, another
    // source, a late timestamp or a changed certificate cannot fill a burst.
    internal sealed class NetworkBatch141145Window
    {
        private sealed class Slot
        {
            internal readonly Dictionary<Guid, DateTime> Records = new();
            internal DateTime Last = DateTime.MinValue;
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, Slot> _slots = new(StringComparer.OrdinalIgnoreCase);

        internal bool Observe(string key, Guid id, DateTime timestampUtc, TimeSpan window, out int count)
        {
            lock (_gate)
            {
                foreach (var expired in _slots.Where(item =>
                    timestampUtc - item.Value.Last > window).Select(item => item.Key).ToArray())
                    _slots.Remove(expired);
                if (!_slots.TryGetValue(key, out var slot))
                {
                    if (_slots.Count >= 1024)
                        _slots.Remove(_slots.OrderBy(item => item.Value.Last).First().Key);
                    _slots[key] = slot = new Slot();
                }

                foreach (var expired in slot.Records.Where(item =>
                    timestampUtc - item.Value > window).Select(item => item.Key).ToArray())
                    slot.Records.Remove(expired);
                count = slot.Records.Count;
                if (timestampUtc < slot.Last || slot.Records.ContainsKey(id))
                    return false;
                slot.Last = timestampUtc;
                if (slot.Records.Count >= 256)
                    slot.Records.Remove(slot.Records.OrderBy(item => item.Value).First().Key);
                slot.Records[id] = timestampUtc;
                count = slot.Records.Count;
                return true;
            }
        }
    }
}
