// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Services;

internal sealed record ExternalCommunicationRow(string InterfaceScope, string LocalIp, string Destination,
    long Observations, DateTimeOffset FirstSeenUtc, DateTimeOffset LastSeenUtc,
    string[] Asns, string[] Countries, string[] Processes);
internal sealed record CommunicationHistoryRow(Guid SessionId, DateTimeOffset StartedUtc, ExternalCommunicationRow Row);

// Only outbound observations from a proven local endpoint. TCP SYN is an attempt,
// not an established connection; UDP is a datagram, not proof of a response.
internal sealed class ExternalCommunicationRegistry
{
    internal const int Capacity = 2048;
    private const int MetadataLimit = 8;
    private readonly object _gate = new();
    private bool _sealed;
    private readonly Dictionary<Key, Entry> _entries = new();
    private readonly record struct Key(string Scope, string Local, string Destination);
    private sealed class Entry
    {
        internal long Count;
        internal DateTimeOffset First, Last;
        internal readonly HashSet<string> Asns = new(StringComparer.Ordinal);
        internal readonly HashSet<string> Countries = new(StringComparer.Ordinal);
        internal readonly HashSet<string> Processes = new(StringComparer.Ordinal);
    }
    internal void Seal() { lock (_gate) _sealed = true; }
    private static bool TryKey(TrafficRecord r, out Key key)
    {
        key = default;
        if (r.SrcIsLocalHost != true || r.DstIsLocalHost != false
            || r.CaptureInterfaceEvidence != "WindowsInterfaceGuid" || !Guid.TryParse(r.CaptureInterfaceId, out var scope)
            || r.SourcePort is not (> 0 and <= 65535) || r.DestinationPort is not (> 0 and <= 65535)
            || !(r.IsTcp && r.TcpFlags is ushort flags && (flags & 0x17) == 2 || r.IsUdp && !r.IsTcp)
            || ObservedAssetRegistry.NormalizeAddress(r.Source) is not string local
            || !IPAddress.TryParse(r.Destination, out var destination)
            || EndpointIpEnrichment.Classify(r.Destination) != "Public") return false;
        key = new(scope.ToString("D"), local, EndpointIpEnrichment.Normalize(destination).ToString());
        return true;
    }

    internal void Observe(TrafficRecord r, DateTimeOffset now)
    {
        if (!TryKey(r, out var key)) return;
        lock (_gate)
        {
            if (_sealed) return;
            if (!_entries.TryGetValue(key, out var entry))
            {
                if (_entries.Count >= Capacity) return;
                _entries[key] = entry = new Entry { First = now, Last = now };
            }
            if (entry.Count < long.MaxValue) entry.Count++;
            if (now < entry.First) entry.First = now;
            if (now > entry.Last) entry.Last = now;
        }
    }

    internal void AddMetadata(TrafficRecord r)
    {
        if (!TryKey(r, out var key)) return;
        lock (_gate)
        {
            if (_sealed || !_entries.TryGetValue(key, out var e)) return;
            if (r.DstAsn is > 0 and <= uint.MaxValue && e.Asns.Count < MetadataLimit)
                e.Asns.Add(r.DstAsn.Value.ToString(CultureInfo.InvariantCulture));
            var country = r.DstCountryIso2?.ToUpperInvariant();
            if (ValidCountry(country) && e.Countries.Count < MetadataLimit) e.Countries.Add(country!);
            // UDP binding is not proof of remote tuple ownership.
            if (r.IsTcp && r.ProcessId > 0 && r.ProcessAttribution is "CaptureProvided" or "TcpSocketTable"
                && NormalizeProcess(r.ProcessName) is string process && e.Processes.Count < MetadataLimit)
                e.Processes.Add(process);
        }
    }

    internal IReadOnlyList<ExternalCommunicationRow> Snapshot()
    {
        lock (_gate)
            return _entries.OrderByDescending(x => x.Value.Last).ThenBy(x => x.Key.Destination, StringComparer.Ordinal)
                .Select(x => new ExternalCommunicationRow(x.Key.Scope, x.Key.Local, x.Key.Destination, x.Value.Count,
                    x.Value.First, x.Value.Last, Sorted(x.Value.Asns), Sorted(x.Value.Countries), Sorted(x.Value.Processes))).ToArray();
    }
    private static string[] Sorted(HashSet<string> set) => set.OrderBy(x => x, StringComparer.Ordinal).ToArray();
    private static bool ValidCountry(string? s) => s is { Length: 2 } && s.All(c => c is >= 'A' and <= 'Z');
    private static string? NormalizeProcess(string? s)
    {
        if (string.IsNullOrWhiteSpace(s) || s.Length > 128 || s.Any(c => char.IsControl(c) || c is '/' or '\\' or ';')
            || string.Equals(s.Trim(), "Unknown", StringComparison.OrdinalIgnoreCase)) return null;
        return s.Trim().ToLowerInvariant();
    }
    internal static bool Valid(ExternalCommunicationRow? r)
        => r is not null && Guid.TryParseExact(r.InterfaceScope, "D", out _)
            && !string.IsNullOrWhiteSpace(r.LocalIp) && ObservedAssetRegistry.NormalizeAddress(r.LocalIp) == r.LocalIp
            && EndpointIpEnrichment.Classify(r.Destination) == "Public"
            && IPAddress.TryParse(r.Destination, out var address) && EndpointIpEnrichment.Normalize(address).ToString() == r.Destination
            && r.LocalIp != r.Destination && r.Observations > 0 && r.FirstSeenUtc != default && r.FirstSeenUtc <= r.LastSeenUtc
            && r.Asns is { Length: <= MetadataLimit } && r.Asns.All(a => uint.TryParse(a, NumberStyles.None, CultureInfo.InvariantCulture, out uint n) && n > 0)
            && r.Countries is { Length: <= MetadataLimit } && r.Countries.All(ValidCountry)
            && r.Processes is { Length: <= MetadataLimit } && r.Processes.All(p => NormalizeProcess(p) == p && p is not null);
}
