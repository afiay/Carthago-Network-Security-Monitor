// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.AssetInventory
{
    // Only corroborated, local-link ARP is-at claims can seed these inventory signals.
    // A generic Ethernet source MAC on routed IP traffic belongs to a next hop,
    // not necessarily the source IP. Do not infer host identity from that pairing.
    internal readonly record struct AssetArpClaim(string Ip, string Mac, string Oui, bool GloballyAdministered);

    internal static class AssetInventoryClaimEvidence
    {
        private static readonly Regex ClaimPattern = new(
            @"\b(?<ip>\d{1,3}(?:\.\d{1,3}){3})\s+is-at\s+(?<mac>(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        private static readonly Regex MacPattern = new(
            @"\A(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\z",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        public static bool TryRead(RuleEvaluationContext context, out AssetArpClaim claim)
        {
            claim = default;
            var record = context.Record;
            if (context.TimestampUtc.Kind != DateTimeKind.Utc
                || !string.Equals(record.Protocol, "ARP", StringComparison.OrdinalIgnoreCase)
                || string.IsNullOrWhiteSpace(record.Info) || record.Info.Length > 512
                || string.IsNullOrWhiteSpace(record.MacSource) || !MacPattern.IsMatch(record.MacSource)
                || !IPAddress.TryParse(record.Source, out var source)
                || source.AddressFamily != AddressFamily.InterNetwork)
                return false;

            var bytes = source.GetAddressBytes();
            // RFC1918 only: no public, loopback, multicast, link-local or unspecified addresses.
            if (!(bytes[0] == 10 || bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31
                || bytes[0] == 192 && bytes[1] == 168))
                return false;

            var match = ClaimPattern.Match(record.Info);
            if (!match.Success || !IPAddress.TryParse(match.Groups["ip"].Value, out var claimedIp)
                || !source.Equals(claimedIp))
                return false;
            var sourceMac = record.MacSource.Replace('-', ':').ToUpperInvariant();
            var claimedMac = match.Groups["mac"].Value.Replace('-', ':').ToUpperInvariant();
            if (!string.Equals(sourceMac, claimedMac, StringComparison.Ordinal))
                return false;

            if (!byte.TryParse(sourceMac.Substring(0, 2), NumberStyles.HexNumber,
                    CultureInfo.InvariantCulture, out var first)
                || (first & 1) != 0 || sourceMac == "00:00:00:00:00:00")
                return false;

            claim = new AssetArpClaim(source.ToString(), sourceMac,
                sourceMac.Substring(0, 8), (first & 2) == 0);
            return true;
        }

        public static DetectionEvent Event(RuleDescriptor descriptor, RuleEvaluationContext context,
            string ip, string summary) => new()
        {
            RuleId = descriptor.RuleId,
            RuleName = descriptor.Name,
            TimestampUtc = context.TimestampUtc,
            Severity = descriptor.DefaultSeverity,
            SourceIp = ip,
            DestinationIp = "local-segment",
            Protocol = "ARP",
            Count = 2,
            Summary = summary,
            Description = summary,
            Evidence = "Two temporally distinct corroborated local ARP claims; MAC values redacted."
        };
    }

    internal sealed class AssetNoveltyTracker
    {
        private sealed class Entry
        {
            public DateTime First;
            public DateTime Last;
            public bool Reported;
            public bool SilentBaseline;
        }
        private readonly object _sync = new();
        private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
        private bool _hasBaseline;
        private static readonly TimeSpan Confirmation = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan Retention = TimeSpan.FromMinutes(30);

        public bool Observe(string key, DateTime now, bool silentFirst)
        {
            lock (_sync)
            {
                if (_entries.Count > 2048)
                {
                    foreach (var stale in _entries.Where(x => now - x.Value.Last > Retention)
                                 .Select(x => x.Key).ToArray()) _entries.Remove(stale);
                    while (_entries.Count > 2048)
                        _entries.Remove(_entries.OrderBy(x => x.Value.Last).First().Key);
                }
                if (!_entries.TryGetValue(key, out var entry))
                {
                    entry = new Entry { First = now, Last = now, SilentBaseline = silentFirst && !_hasBaseline };
                    _entries[key] = entry;
                    _hasBaseline = true;
                    return false;
                }
                if (now <= entry.Last) return false;
                if (now - entry.Last > Retention)
                {
                    entry.First = entry.Last = now;
                    entry.Reported = false;
                    return false;
                }
                if (!entry.Reported && !entry.SilentBaseline && now - entry.First > Confirmation)
                {
                    // An old first sighting cannot corroborate a new observation.
                    // Restart the two-minute confirmation window rather than
                    // leaving the candidate permanently unconfirmable.
                    entry.First = entry.Last = now;
                    return false;
                }
                entry.Last = now;
                if (entry.Reported || entry.SilentBaseline) return false;
                entry.Reported = true;
                return true;
            }
        }
    }

    internal sealed class AssetConflictTracker
    {
        private sealed class Entry
        {
            public string Known = string.Empty;
            public string? Candidate;
            public DateTime CandidateAt;
            public DateTime Last;
        }
        private readonly object _sync = new();
        private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
        private static readonly TimeSpan Confirmation = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan Retention = TimeSpan.FromMinutes(30);

        public bool Observe(string key, string value, DateTime now)
        {
            lock (_sync)
            {
                if (_entries.Count > 2048)
                {
                    foreach (var stale in _entries.Where(x => now - x.Value.Last > Retention)
                                 .Select(x => x.Key).ToArray()) _entries.Remove(stale);
                    while (_entries.Count > 2048)
                        _entries.Remove(_entries.OrderBy(x => x.Value.Last).First().Key);
                }
                if (!_entries.TryGetValue(key, out var entry))
                {
                    _entries[key] = new Entry { Known = value, Last = now };
                    return false;
                }
                if (now <= entry.Last) return false;
                if (now - entry.Last > Retention)
                {
                    entry.Known = value;
                    entry.Candidate = null;
                    entry.Last = now;
                    return false;
                }
                entry.Last = now;
                if (value == entry.Known)
                {
                    entry.Candidate = null;
                    return false;
                }
                if (entry.Candidate == value && now - entry.CandidateAt <= Confirmation)
                {
                    entry.Known = value;
                    entry.Candidate = null;
                    return true;
                }
                entry.Candidate = value;
                entry.CandidateAt = now;
                return false;
            }
        }
    }
}
