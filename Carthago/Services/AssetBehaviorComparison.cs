// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Carthago.Services;

internal sealed record ObservedAssetSessionSnapshot(Guid SessionId, DateTimeOffset StartedUtc,
    IReadOnlyList<ObservedAssetRow> Rows, IReadOnlyList<ExternalCommunicationRow>? Communications = null);
internal sealed record AssetBehaviorRow(string Identity, string InterfaceScope, string Status, int PriorSessions,
    string NewAddresses, string NewServices, string HistoricalMacClaims, string SessionMacClaims);
internal sealed record AssetBehaviorSnapshot(IReadOnlyList<AssetBehaviorRow> Rows, string Summary);

// Retained evidence comparison, not a detection rule or a device reconciliation engine.
// An interface GUID scopes observations but does not prove the same network was attached.
internal static class AssetBehaviorComparison
{
    private readonly record struct IdentityKey(string Scope, string Evidence, string Value);
    private readonly record struct AddressKey(string Scope, string Address);
    private readonly record struct ScopeKey(string Scope, string Evidence);
    private sealed record Identity(IdentityKey Key, string[] Addresses, int[] Ports);
    private sealed class Prior
    {
        internal readonly HashSet<string> Addresses = new(StringComparer.Ordinal);
        internal readonly HashSet<int> Ports = new();
        internal bool Seen;
    }
    private sealed class Claim
    {
        internal string? First, Other;
        internal void Add(string mac)
        {
            if (First is null) First = mac;
            else if (First != mac && Other is null) Other = mac;
        }
        internal string? DifferentFrom(string mac) => First != mac ? First : Other;
    }

    internal static AssetBehaviorSnapshot Compare(ObservedAssetSessionSnapshot current, AssetHistorySnapshot history)
    {
        var currentRows = current.Rows.Take(2048).Select(Parse).OfType<Identity>().ToArray();
        var currentByKey = currentRows.GroupBy(r => r.Key).ToDictionary(g => g.Key, g => g.First());
        var prior = currentByKey.Keys.ToDictionary(k => k, _ => new Prior());
        var scopedSessions = new Dictionary<ScopeKey, HashSet<string>>();
        var currentClaims = new Dictionary<AddressKey, Claim>();
        var earlierClaims = new Dictionary<AddressKey, Claim>();
        foreach (var row in currentRows.Where(r => r.Key.Evidence == "ARP sender claim"))
            foreach (var address in row.Addresses)
            {
                var key = new AddressKey(row.Key.Scope, address);
                if (!currentClaims.TryGetValue(key, out var claim)) currentClaims[key] = claim = new Claim();
                claim.Add(row.Key.Value);
                earlierClaims.TryAdd(key, new Claim());
            }

        // Stored timestamps have second precision. Exclude same-second and
        // overlapping sessions instead of guessing their temporal ordering.
        var cutoff = new DateTimeOffset(current.StartedUtc.UtcDateTime.AddTicks(
            -(current.StartedUtc.UtcDateTime.Ticks % TimeSpan.TicksPerSecond)), TimeSpan.Zero);
        var excludedSessions = new HashSet<Guid>();
        bool incomplete = history.Error is not null;
        foreach (var saved in history.Rows)
        {
            if (!Guid.TryParse(saved.SessionId, out var session)) { incomplete = true; continue; }
            if (session == current.SessionId) { excludedSessions.Add(session); continue; }
            if (!Time(saved.SessionStartedUtc, out var started) || !Time(saved.Asset.LastSeenUtc, out var last) || last < started)
            { incomplete = true; excludedSessions.Add(session); continue; }
            if (started >= cutoff || last >= cutoff) excludedSessions.Add(session);
        }
        foreach (var saved in history.Rows)
        {
            if (!Guid.TryParse(saved.SessionId, out var session) || excludedSessions.Contains(session)) continue;
            // Unknown-interface rows cannot establish same-interface coverage.
            if (!Guid.TryParse(saved.Asset.InterfaceScope, out _)) continue;
            if (Parse(saved.Asset) is not Identity identity) { incomplete = true; continue; }
            var scope = new ScopeKey(identity.Key.Scope, identity.Key.Evidence);
            if (!scopedSessions.TryGetValue(scope, out var sessions)) scopedSessions[scope] = sessions = new(StringComparer.Ordinal);
            sessions.Add(session.ToString("N"));

            if (prior.TryGetValue(identity.Key, out var known))
            {
                known.Seen = true;
                // Track only intersections with current values; no unbounded
                // accumulation of the historical address/service union.
                var target = currentByKey[identity.Key];
                foreach (var address in identity.Addresses)
                    if (target.Addresses.Contains(address, StringComparer.Ordinal)) known.Addresses.Add(address);
                foreach (var port in identity.Ports)
                    if (target.Ports.Contains(port)) known.Ports.Add(port);
            }
            if (identity.Key.Evidence == "ARP sender claim")
                foreach (var address in identity.Addresses)
                    if (earlierClaims.TryGetValue(new AddressKey(identity.Key.Scope, address), out var claim))
                        claim.Add(identity.Key.Value);
        }

        var result = new List<AssetBehaviorRow>();
        foreach (var row in currentRows)
        {
            var k = row.Key;
            int count = scopedSessions.TryGetValue(new ScopeKey(k.Scope, k.Evidence), out var sessions) ? sessions.Count : 0;
            var known = prior[k];
            bool comparable = count > 0 && !incomplete;
            string status = incomplete ? "History incomplete; novelty withheld" : count == 0 ? "No comparable prior observations"
                : !known.Seen ? "Identity not in retained history" : "Previously observed identity";
            var newAddresses = comparable && known.Seen && k.Evidence == "ARP sender claim"
                ? row.Addresses.Where(a => !known.Addresses.Contains(a)) : Array.Empty<string>();
            var newPorts = comparable && known.Seen && k.Evidence == "Local host IP"
                ? row.Ports.Where(p => !known.Ports.Contains(p)) : Array.Empty<int>();
            string Claims(Dictionary<AddressKey, Claim> source) => k.Evidence != "ARP sender claim" ? "" :
                string.Join("; ", row.Addresses.Select(a =>
                {
                    var other = source.TryGetValue(new AddressKey(k.Scope, a), out var claim) ? claim.DifferentFrom(k.Value) : null;
                    return other is null ? null : $"{a} → {other}";
                }).OfType<string>());
            result.Add(new(k.Evidence + " · " + k.Value, k.Scope, status, count,
                string.Join("; ", newAddresses), string.Join("; ", newPorts), Claims(earlierClaims), Claims(currentClaims)));
        }
        int skipped = current.Rows.Count - currentRows.Length;
        string summary = $"{result.Count} scoped identities compared; {skipped} unscoped or invalid rows excluded. " +
            "Only earlier retained observations on the same interface and evidence type are used; current checkpoints are excluded. " +
            "Different MAC claims may be sequential, not simultaneous. Interface identity does not establish the same LAN or trust.";
        if (incomplete) summary += " History is incomplete: absence-based changes are withheld.";
        return new(result, summary);
    }

    private static Identity? Parse(ObservedAssetRow row)
    {
        if (!Guid.TryParse(row.InterfaceScope, out var scope) || row.Observations <= 0
            || string.IsNullOrWhiteSpace(row.Addresses) || row.Addresses.Length > 4096
            || row.Services is null || row.Services.Length > 512) return null;
        var addresses = row.Addresses.Split("; ", StringSplitOptions.RemoveEmptyEntries)
            .Select(ObservedAssetRegistry.NormalizeAddress).OfType<string>().Distinct(StringComparer.Ordinal).ToArray();
        if (addresses.Length is < 1 or > 32) return null;
        if (row.Evidence == "ARP sender claim")
        {
            if (ObservedAssetRegistry.NormalizeMac(row.Mac) is not string mac
                || addresses.Any(a => !System.Net.IPAddress.TryParse(a, out var ip) || !LocalLanDiscovery.IsLocalHostAddress(ip)))
                return null;
            return new(new(scope.ToString("D"), row.Evidence, mac), addresses, Array.Empty<int>());
        }
        if (row.Evidence != "Local host IP" || addresses.Length != 1 || row.Mac is not null) return null;
        var ports = row.Services.Split("; ", StringSplitOptions.RemoveEmptyEntries)
            .Select(p => int.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out int n) && n is > 0 and <= 65535 ? n : 0)
            .Where(p => p != 0).Distinct().OrderBy(p => p).ToArray();
        if (ports.Length > 64) return null;
        return new(new(scope.ToString("D"), row.Evidence, addresses[0]), addresses, ports);
    }

    private static bool Time(string value, out DateTimeOffset time)
        => DateTimeOffset.TryParseExact(value, "u", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal, out time);
}
