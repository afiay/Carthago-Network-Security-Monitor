// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;

namespace Carthago.Services;

internal sealed record CommunicationComparisonRow(string InterfaceScope, string LocalIp, string Destination,
    string Status, long Observations, string Asns, string Countries, string Processes,
    string NewAsns, string NewCountries, string NewProcesses);
internal sealed record CommunicationComparisonSnapshot(IReadOnlyList<CommunicationComparisonRow> Rows, string Summary);

internal static class ExternalCommunicationComparison
{
    private readonly record struct Host(string Scope, string Local);
    private sealed class Prior
    {
        internal readonly HashSet<string> Destinations = new(StringComparer.Ordinal);
        internal readonly HashSet<string> Asns = new(StringComparer.Ordinal);
        internal readonly HashSet<string> Countries = new(StringComparer.Ordinal);
        internal readonly Dictionary<string, HashSet<string>> Processes = new(StringComparer.Ordinal);
    }
    internal static CommunicationComparisonSnapshot Compare(ObservedAssetSessionSnapshot current, AssetHistorySnapshot history)
    {
        var rows = (current.Communications ?? Array.Empty<ExternalCommunicationRow>()).Where(ExternalCommunicationRegistry.Valid).ToArray();
        var saved = history.Communications ?? Array.Empty<CommunicationHistoryRow>();
        bool incomplete = history.Error is not null;
        var excluded = new HashSet<Guid>();
        foreach (var r in saved)
        {
            if (r.SessionId == current.SessionId) { excluded.Add(r.SessionId); continue; }
            if (r.SessionId == Guid.Empty || r.StartedUtc == default || !ExternalCommunicationRegistry.Valid(r.Row) || r.Row.FirstSeenUtc < r.StartedUtc)
            { incomplete = true; excluded.Add(r.SessionId); continue; }
            if (r.StartedUtc >= current.StartedUtc || r.Row.LastSeenUtc >= current.StartedUtc)
                excluded.Add(r.SessionId);
        }
        // Asset timestamps use second precision; any overlapping asset row also
        // excludes the entire checkpoint, even if its communication ended earlier.
        var cutoff = current.StartedUtc.UtcDateTime.AddTicks(-(current.StartedUtc.UtcDateTime.Ticks % TimeSpan.TicksPerSecond));
        foreach (var r in history.Rows)
            if (Guid.TryParse(r.SessionId, out var id) &&
                DateTimeOffset.TryParseExact(r.Asset.LastSeenUtc, "u", System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal, out var last) && last.UtcDateTime >= cutoff)
                excluded.Add(id);
        var prior = rows.Select(r => new Host(r.InterfaceScope, r.LocalIp)).Distinct().ToDictionary(h => h, _ => new Prior());
        foreach (var r in saved)
        {
            if (excluded.Contains(r.SessionId) || !prior.TryGetValue(new(r.Row.InterfaceScope, r.Row.LocalIp), out var p)) continue;
            p.Destinations.Add(r.Row.Destination);
            p.Asns.UnionWith(r.Row.Asns);
            p.Countries.UnionWith(r.Row.Countries);
            if (r.Row.Processes.Length > 0)
            {
                if (!p.Processes.TryGetValue(r.Row.Destination, out var names)) p.Processes[r.Row.Destination] = names = new(StringComparer.Ordinal);
                names.UnionWith(r.Row.Processes);
            }
        }
        var result = new List<CommunicationComparisonRow>();
        string Join(IEnumerable<string> values) => string.Join("; ", values);
        foreach (var r in rows)
        {
            var p = prior[new(r.InterfaceScope, r.LocalIp)];
            bool comparable = p.Destinations.Count > 0 && !incomplete;
            string status = incomplete ? "History incomplete; novelty withheld" : !comparable ? "No comparable prior communication"
                : p.Destinations.Contains(r.Destination) ? "Previously observed destination" : "Destination not in retained history";
            var asns = comparable && p.Asns.Count > 0 ? r.Asns.Where(a => !p.Asns.Contains(a)) : Array.Empty<string>();
            var countries = comparable && p.Countries.Count > 0 ? r.Countries.Where(a => !p.Countries.Contains(a)) : Array.Empty<string>();
            var names = comparable && p.Processes.TryGetValue(r.Destination, out var known)
                ? r.Processes.Where(a => !known.Contains(a)) : Array.Empty<string>();
            result.Add(new(r.InterfaceScope, r.LocalIp, r.Destination, status, r.Observations,
                Join(r.Asns), Join(r.Countries), Join(r.Processes), Join(asns), Join(countries), Join(names)));
        }
        return new(result, $"{result.Count} outbound destination rows. TCP SYN attempts / UDP datagrams, not confirmed connections. " +
            "Only earlier checkpoints with communication data for the same interface and local IP are compared. " +
            "Metadata absence is not proof of novelty; blank comparison fields may mean missing prior metadata. " +
            "Process names are not executable identities. " + (incomplete ? "History incomplete: novelty withheld." : ""));
    }
}
