// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Carthago.Analytics.Models;
using Carthago.Engine;
using Carthago.Services.Sensors;

namespace Carthago.Analytics.Services;

// A contextual search, not correlation or attachment to an Incident.
// Never mutate incident membership, attack story, risk or passive event IDs.
internal sealed record ActiveIncidentScope(string IncidentId, IReadOnlyList<string> Targets,
    DateTimeOffset FromUtc, DateTimeOffset ThroughUtc);
internal sealed record ActiveIncidentContextResult(IReadOnlyList<ActiveFindingRow> Rows, string? Error);

internal static class ActiveIncidentContext
{
    internal const int MaxResults = 50;
    internal static ActiveIncidentScope? CreateScope(Incident incident)
    {
        ArgumentNullException.ThrowIfNull(incident);
        if (string.IsNullOrWhiteSpace(incident.Id) ||
            incident.Tags.Any(t => string.Equals(t, "demo", StringComparison.OrdinalIgnoreCase) ||
                t.StartsWith("demo:", StringComparison.OrdinalIgnoreCase)))
            return null;
        // UTC-named model fields must have established time-zone provenance.
        // Never substitute UpdatedUtc (analyst edits) or the current time.
        if (incident.FirstSeenUtc == default || incident.LastSeenUtc == default ||
            incident.FirstSeenUtc.Kind == DateTimeKind.Unspecified || incident.LastSeenUtc.Kind == DateTimeKind.Unspecified)
            return null;
        var first = new DateTimeOffset(incident.FirstSeenUtc).ToUniversalTime();
        var last = new DateTimeOffset(incident.LastSeenUtc).ToUniversalTime();
        if (last < first) return null;
        var targets = new[] { incident.PrimarySourceIp, incident.PrimaryDestinationIp }
            .Where(s => IPAddress.TryParse(s, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork &&
                ip.ToString() == s && Carthago.Services.LocalLanDiscovery.IsLocalHostAddress(ip))
            .Select(s => s!).Distinct(StringComparer.Ordinal).ToArray();
        if (targets.Length == 0) return null;
        return new(incident.Id, Array.AsReadOnly(targets), first, last);
    }

    internal static ActiveIncidentContextResult Read(ActiveIncidentScope scope, ActiveEvidenceStore store)
    {
        // Time/endpoint filters precede the per-target cap. Results are local
        // contextual candidates; no adapter or asset equivalence is inferred.
        var results = new List<ActiveFindingRow>();
        foreach (var target in scope.Targets)
        {
            var read = store.ReadFindings(target: target, limit: MaxResults,
                fromUtc: scope.FromUtc, throughUtc: scope.ThroughUtc);
            if (read.Error is not null)
                return new(Array.Empty<ActiveFindingRow>(), read.Error);
            results.AddRange(read.Rows);
        }
        return new(results.OrderByDescending(r => r.ObservedTicks).ThenBy(r => r.Id, StringComparer.Ordinal)
            .Take(MaxResults).ToArray(), null);
    }
}
