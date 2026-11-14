// SPDX-License-Identifier: MIT
using System.Collections.Generic;
using System.Globalization;
using Carthago.Services.Geo;

namespace Carthago.Services;

internal sealed record EnrichmentProviderDisplay(string Provider, long Success, long Unavailable, long Failed,
    long TimedOut, long Cancelled, long CacheHits, string SuccessShare, string Latency);
internal sealed record EnrichmentHealthDisplay(string Summary, IReadOnlyList<EnrichmentProviderDisplay> Providers);

internal static class EnrichmentHealthPresentation
{
    internal static EnrichmentHealthDisplay Build(TrafficCaptureService.StatsSnapshot? stats)
    {
        var providers = new List<EnrichmentProviderDisplay>();
        if (stats is null) return new("No enrichment snapshot available.", providers);
        foreach (string name in new[] { "whois", "reputation", "vpn-proxy" })
        {
            if (!stats.EnrichmentProviders.TryGetValue(name, out var p)) p = new(0,0,0,0,0,0,0,0);
            long total = p.Success + p.Unavailable + p.Failed + p.TimedOut + p.Cancelled;
            string share = total > 0 ? ((double)p.Success / total).ToString("P1", CultureInfo.InvariantCulture) : "—";
            string latency = total > 0
                ? ((double)p.TotalElapsedMs / total).ToString("0.0", CultureInfo.InvariantCulture) + " / " + p.MaxElapsedMs.ToString(CultureInfo.InvariantCulture)
                : "—";
            providers.Add(new(name, p.Success, p.Unavailable, p.Failed, p.TimedOut, p.Cancelled, p.CacheHits, share, latency));
        }
        return new("Provider outcomes: capture-service lifetime; success share includes cancelled outcomes. " +
            "Cache hits are lookup-path events, not additional outcomes. No attempts means no rate. " +
            $"Enrichment queue depth: {stats.EnrichmentQueueDepth?.ToString(CultureInfo.InvariantCulture) ?? "unknown"}; " +
            $"fallback records (lifetime): {stats.EnrichmentFallbacks:N0}. " +
            "Provider success is not proof of detection accuracy or endpoint trust. " +
            WorkerSummary(stats.EnrichmentWorkers) + " " + CoverageSummary(stats.EnrichmentCoverage) + " " + StorageSummary(stats.EnrichmentStorage) + " " + GeoSummary(stats) + " " + NativeProcessSummary(stats.NativeProcessLookups) + " " + ProcessMetadataCacheSummary(stats.ProcessMetadataCache) + " " + ProcessMetadataCacheCapacitySummary(stats.ProcessMetadataCacheCapacity), providers);
    }

    internal static string ProcessMetadataCacheSummary(WindowsProcessResolver.MetadataCacheMetrics.Snapshot? snapshot)
    {
        if (snapshot is not { } h) return "TCP metadata-cache metrics unavailable.";
        string reuse = h.Completed == 0 ? "—" : ((double)h.Reused / h.Completed).ToString("P1", CultureInfo.InvariantCulture);
        return $"TCP metadata-cache probes (process lifetime): {h.Completed} completed, {h.Absent} absent, {h.Expired} expired, " +
            $"{h.OwnerMismatch} owner mismatch, {h.IdentityMismatch} identity mismatch, {h.Reused} reused (reuse share {reuse}). " +
            "Probes are not packets or avoided native ownership scans; fresh ownership remains required.";
    }

    internal static string ProcessMetadataCacheCapacitySummary((int Count, long Evictions)? snapshot)
    {
        if (snapshot is not { } h) return "TCP metadata-cache capacity metrics unavailable.";
        return $"TCP metadata-cache retained entries: {h.Count}/{WindowsProcessResolver.MaxCacheEntries}; capacity evictions (process lifetime): {h.Evictions}. " +
            "Retained entries may be expired; capacity evictions exclude explicit clear and invalidation.";
    }

    internal static string NativeProcessSummary(WindowsProcessResolver.ProcessLookupMetrics.Snapshot[]? snapshots)
    {
        if (snapshots is not { Length: 4 }) return "Native process lookup metrics unavailable.";
        var labels = new[] { "TCP/IPv4", "TCP/IPv6", "UDP/IPv4", "UDP/IPv6" };
        var rows = new List<string>();
        for (int i = 0; i < labels.Length; i++)
        {
            var h = snapshots[i];
            string mean = h.Completed == 0 ? "—" :
                (1000.0 * h.ElapsedTicks / System.Diagnostics.Stopwatch.Frequency / h.Completed)
                    .ToString("0.0", CultureInfo.InvariantCulture);
            rows.Add($"{labels[i]}: {h.Completed} completed, {h.Resolved} resolved, {h.Unresolved} unresolved, mean ms {mean}, {h.Active} active, {h.PeakActive} peak active");
        }
        return "Native process candidate lookups (process lifetime): " + string.Join("; ", rows)
            + ". Active and peak are overlapping candidate operations per bucket, not threads; bucket peaks must not be summed. Candidate scans are not packets, individual native API calls or verified application identities.";
    }

    internal static string GeoSummary(TrafficCaptureService.StatsSnapshot stats)
    {
        return $"GeoIP databases (reader startup): City {stats.GeoCityDatabaseStatus?.ToString() ?? "unknown"}; " +
            $"ASN {stats.GeoAsnDatabaseStatus?.ToString() ?? "unknown"}. " +
            "Ready means reader opened with a supported declared edition, not a successful lookup. " +
            "GeoIP completed database attempts (service lifetime): " +
            GeoLookupSummary("City", stats.GeoCityLookupHealth) + "; " +
            GeoLookupSummary("ASN", stats.GeoAsnLookupHealth) + ". Records found do not imply usable field coverage. " + GeoCacheSummary(stats.GeoCacheHealth);
    }

    private static string GeoCacheSummary(GeoIpService.CacheHealthSnapshot? snapshot)
    {
        if (snapshot is not { } h) return "GeoIP cache metrics unavailable.";
        string rate = h.Requests == 0 ? "—" : ((double)(h.PositiveHits + h.NegativeHits) / h.Requests).ToString("P1", CultureInfo.InvariantCulture);
        return $"GeoIP cache (service lifetime): {h.Requests} eligible requests, {h.PositiveHits} positive hits, {h.NegativeHits} negative hits, {h.Misses} misses (hit share {rate}); " +
            $"expired on access: {h.Expired}, capacity-evicted entries: {h.Evicted}, retained entries: {h.Occupancy}/{h.Capacity}. Cache requests are not database attempts.";
    }

    private static string GeoLookupSummary(string name, GeoIpService.LookupHealthSnapshot? snapshot)
    {
        if (snapshot is not { } h) return name + " unknown";
        string rate = h.Attempts == 0 ? "—" : ((double)h.Failed / h.Attempts).ToString("P1", CultureInfo.InvariantCulture);
        return $"{name}: {h.Attempts} attempts, {h.Found} found, {h.NotFound} not found, {h.Failed} failed (failure share {rate})";
    }

    internal static string StorageSummary(EnrichmentStorageSnapshot? s)
    {
        if (s is null) return "Storage diagnostics unavailable.";
        return $"Current/last session assets: {s.Assets.Count}/{s.Assets.Limit}, capacity-rejected observations: {s.Assets.Rejected}; " +
            $"external destinations: {s.Destinations.Count}/{s.Destinations.Limit}, capacity-rejected observations: {s.Destinations.Rejected}. " +
            $"Checkpoint writes: {s.Checkpoints.Writes}, failures: {s.Checkpoints.Failures}; " +
            (s.Checkpoints.LastError is not null ? "Last save error: " + s.Checkpoints.LastError : "No save error reported.") +
            " Retained history may be incomplete; rejection counts are observations, not unique identities.";
    }

    internal static string CoverageSummary(EnrichmentCoverageSnapshot? c)
    {
        if (c is null) return "Evidence coverage unavailable.";
        return $"Published records (lifetime): {c.Published:N0}; both endpoint membership flags known: {c.LocalKnown:N0}/{c.Published:N0}; " +
            $"verified interface: {c.InterfaceKnown:N0}/{c.Published:N0}; DNS correlated: {c.DnsCorrelated:N0}/{c.Published:N0}; " +
            $"TLS correlated: {c.TlsCorrelated:N0}/{c.Published:N0}. " +
            $"Local TCP/UDP records sampled after process stage: {c.ProcessEligible:N0}; TCP socket ownership: {c.ProcessStrong:N0}; " +
            $"UDP binding only: {c.ProcessUdpBinding:N0}. Coverage is observed evidence availability, not protocol recall; UDP binding is not remote tuple proof.";
    }

    internal static string WorkerSummary(EnrichmentWorkerSnapshot? w)
    {
        if (w is null) return "Worker metrics unavailable.";
        string Mean(long sum, long count) => count == 0 ? "—" : ((double)sum / count).ToString("0.0", CultureInfo.InvariantCulture);
        return $"Workers (lifetime): {w.Started:N0} started, {w.Returned:N0} returned, {w.Cancelled:N0} cancelled, {w.Faulted:N0} faulted; " +
            $"{w.Skipped:N0} cancelled before processing. Queue wait mean/max ms: {Mean(w.WaitTotalMs, w.Started)} / {w.WaitMaxMs}; " +
            $"worker elapsed mean/max ms: {Mean(w.ElapsedTotalMs, w.Returned + w.Cancelled + w.Faulted)} / {w.ElapsedMaxMs}. " +
            "Returned does not imply provider success; worker elapsed includes rule evaluation.";
    }
}
