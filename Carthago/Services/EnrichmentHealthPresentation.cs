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
    // Explicit aggregate-only export; never serialize the entire StatsSnapshot.
    internal static string ExportCounters(TrafficCaptureService.StatsSnapshot stats,
        System.DateTimeOffset sampledUtc, int processId, System.DateTimeOffset processStartedUtc)
    {
        var storage = stats.EnrichmentStorage;
        var providers = new Dictionary<string, EnrichmentProviderSnapshot>();
        foreach (var name in new[] { "whois", "reputation", "vpn-proxy" })
            if (stats.EnrichmentProviders.TryGetValue(name, out var value)) providers[name] = value;
        return System.Text.Json.JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            sampledUtc = sampledUtc.ToUniversalTime(),
            processId,
            processStartedUtc = processStartedUtc.ToUniversalTime(),
            scope = "service lifetime except queue depth and current/last session registry gauges",
            queueDepth = stats.EnrichmentQueueDepth,
            fallbacks = stats.EnrichmentFallbacks,
            coverage = stats.EnrichmentCoverage,
            workers = stats.EnrichmentWorkers,
            providers,
            geoCity = stats.GeoCityLookupHealth,
            geoAsn = stats.GeoAsnLookupHealth,
            geoCache = stats.GeoCacheHealth,
            storage = storage is null ? null : new
            {
                registrySessionId = stats.RegistrySessionId,
                registryRunPresent = stats.RegistryRunPresent,
                assets = storage.Assets,
                destinations = storage.Destinations,
                checkpointWrites = storage.Checkpoints.Writes,
                checkpointFailures = storage.Checkpoints.Failures,
                checkpointDiagnosticPresent = storage.Checkpoints.LastError is not null
            }
        }, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
    }

    internal static EnrichmentHealthDisplay Build(TrafficCaptureService.StatsSnapshot? stats)
    {
        var providers = new List<EnrichmentProviderDisplay>();
        if (stats is null) return new("No enrichment snapshot available.", providers);
        foreach (string name in new[] { "whois", "reputation", "vpn-proxy" })
        {
            if (!stats.EnrichmentProviders.TryGetValue(name, out var p)) p = new(0,0,0,0,0,0,0,0);
            // Use a widened denominator: lifetime counters may sum beyond Int64 even when each is valid.
            decimal total = (decimal)p.Success + p.Unavailable + p.Failed + p.TimedOut + p.Cancelled;
            string share = total > 0 && p.Success >= 0 && p.Unavailable >= 0 && p.Failed >= 0 && p.TimedOut >= 0 && p.Cancelled >= 0
                ? ((decimal)p.Success / total).ToString("P1", CultureInfo.InvariantCulture) : "—";
            // Cache hits are path events, not completed provider outcomes.
            // Keep the denominator visible so a mean is not mistaken for
            // latency per published packet or per cache access.
            string latency = total > 0 && p.Success >= 0 && p.Unavailable >= 0 &&
                p.Failed >= 0 && p.TimedOut >= 0 && p.Cancelled >= 0 &&
                p.TotalElapsedMs >= 0 && p.MaxElapsedMs >= 0 && p.MaxElapsedMs <= p.TotalElapsedMs
                ? ((decimal)p.TotalElapsedMs / total).ToString("0.0", CultureInfo.InvariantCulture) + " / " + p.MaxElapsedMs.ToString(CultureInfo.InvariantCulture) + " ms (" + total.ToString(CultureInfo.InvariantCulture) + " outcomes)"
                : "—";
            providers.Add(new(name, p.Success, p.Unavailable, p.Failed, p.TimedOut, p.Cancelled, p.CacheHits, share, latency));
        }
        // Cache-path events are not outcomes; invalid counters must be visible.
        bool invalidProviderCounters = false;
        foreach (string name in new[] { "whois", "reputation", "vpn-proxy" })
        {
            if (!stats.EnrichmentProviders.TryGetValue(name, out var p)) continue;
            invalidProviderCounters |= p.Success < 0 || p.Unavailable < 0 || p.Failed < 0 ||
                p.TimedOut < 0 || p.Cancelled < 0 || p.CacheHits < 0 ||
                p.TotalElapsedMs < 0 || p.MaxElapsedMs < 0 ||
                (p.Success + (decimal)p.Unavailable + p.Failed + p.TimedOut + p.Cancelled == 0 &&
                 (p.TotalElapsedMs != 0 || p.MaxElapsedMs != 0)) ||
                (p.TotalElapsedMs >= 0 && p.MaxElapsedMs > p.TotalElapsedMs);
        }
        return new("Provider outcomes: capture-service lifetime; success share includes cancelled outcomes. " +
            "Cache hits are lookup-path events, not additional outcomes. No attempts means no rate. " +
            $"Enrichment queue depth: {stats.EnrichmentQueueDepth?.ToString(CultureInfo.InvariantCulture) ?? "unknown"}; " +
            $"fallback records (lifetime): {stats.EnrichmentFallbacks:N0}. " +
            "Provider success is not proof of detection accuracy or endpoint trust. " +
            (invalidProviderCounters ? "WARNING: invalid provider outcome, cache-path or latency counters; investigate provider accounting. " : string.Empty) +
            WorkerSummary(stats.EnrichmentWorkers) + " " + CoverageSummary(stats.EnrichmentCoverage) + " " + StorageSummary(stats.EnrichmentStorage) + " " + GeoSummary(stats) + " " + NativeProcessSummary(stats.NativeProcessLookups) + " " + ProcessMetadataCacheSummary(stats.ProcessMetadataCache) + " " + ProcessMetadataCacheCapacitySummary(stats.ProcessMetadataCacheCapacity) + " " + TlsCapacitySummary(stats.TlsCapacity), providers);
    }

    internal static string ProcessMetadataCacheSummary(WindowsProcessResolver.MetadataCacheMetrics.Snapshot? snapshot)
    {
        if (snapshot is not { } h) return "TCP metadata-cache metrics unavailable.";
        // Snapshot.Completed is an Int64 sum and can overflow even when every
        // individual outcome is nonnegative. Use exact widened arithmetic.
        decimal completed = (decimal)h.Absent + h.Expired + h.OwnerMismatch + h.IdentityMismatch + h.Reused;
        bool invalid = h.Absent < 0 || h.Expired < 0 || h.OwnerMismatch < 0 ||
            h.IdentityMismatch < 0 || h.Reused < 0 || completed > long.MaxValue;
        string reuse = completed <= 0 || invalid ? "—" :
            ((decimal)h.Reused / completed).ToString("P1", CultureInfo.InvariantCulture);
        return (invalid ? "WARNING: TCP metadata-cache outcome counters invalid or exceed Int64; inspect probe accounting. " : string.Empty) +
            $"TCP metadata-cache probes (process lifetime): {completed.ToString(CultureInfo.InvariantCulture)} completed, {h.Absent} absent, {h.Expired} expired, " +
            $"{h.OwnerMismatch} owner mismatch, {h.IdentityMismatch} identity mismatch, {h.Reused} reused (reuse share {reuse}). " +
            "Probes are not packets or avoided native ownership scans; fresh ownership remains required.";
    }

    internal static string TlsCapacitySummary((int Retained, int Closed, long CapacityRejections)? snapshot)
    {
        if (snapshot is not { } s) return "TLS capacity metrics unavailable (no capture session).";
        bool invalid = s.Retained < 0 || s.Closed < 0 || s.Closed > s.Retained ||
            s.Retained > TlsConnectionEnrichment.Capacity || s.CapacityRejections < 0;
        string open = invalid ? "—" : (s.Retained - s.Closed).ToString("N0", CultureInfo.InvariantCulture);
        return (invalid ? "WARNING: TLS retained, closed or capacity rejection counters inconsistent; inspect session accounting. " : string.Empty) +
            $"TLS retained states: {s.Retained:N0}/{TlsConnectionEnrichment.Capacity:N0}; open: {open}; closed: {s.Closed:N0}; capacity-rejected SYN attempts (session lifetime): {s.CapacityRejections:N0}. Retained states may await expiry pruning; not a count of live connections.";
    }

    internal static string ProcessMetadataCacheCapacitySummary((int Count, long Evictions)? snapshot)
    {
        if (snapshot is not { } h) return "TCP metadata-cache capacity metrics unavailable.";
        bool invalid = h.Count < 0 || h.Count > WindowsProcessResolver.MaxCacheEntries || h.Evictions < 0;
        return (invalid ? "WARNING: TCP metadata-cache capacity counters inconsistent; inspect cache accounting. " : string.Empty) +
            $"TCP metadata-cache retained entries: {h.Count}/{WindowsProcessResolver.MaxCacheEntries}; capacity evictions (process lifetime): {h.Evictions}. " +
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
            // Candidate outcomes must reconcile before publishing a latency mean.
            // Active operations are independent of completed outcomes and may be
            // nonzero even when no candidate has completed yet.
            bool invalid = h.Completed < 0 || h.Resolved < 0 || h.Unresolved < 0 ||
                h.ElapsedTicks < 0 || h.Active < 0 || h.PeakActive < 0 ||
                h.Active > h.PeakActive ||
                (decimal)h.Resolved + h.Unresolved != h.Completed ||
                (h.Completed == 0 && h.ElapsedTicks != 0);
            string mean = invalid || h.Completed == 0 ? "—" :
                ((decimal)1000 * h.ElapsedTicks / System.Diagnostics.Stopwatch.Frequency / h.Completed)
                    .ToString("0.0", CultureInfo.InvariantCulture);
            rows.Add((invalid ? "WARNING: native process candidate lookup accounting inconsistent; " : string.Empty) +
                $"{labels[i]}: {h.Completed} completed, {h.Resolved} resolved, {h.Unresolved} unresolved, mean ms {mean}, {h.Active} active, {h.PeakActive} peak active");
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
        decimal accountedRequests = (decimal)h.PositiveHits + h.NegativeHits + h.Misses;
        string rate = accountedRequests <= 0 || h.PositiveHits < 0 || h.NegativeHits < 0 || h.Misses < 0
            ? "—"
            : (((decimal)h.PositiveHits + h.NegativeHits) / accountedRequests).ToString("P1", CultureInfo.InvariantCulture);
        // Each eligible request follows exactly one cache path: positive hit,
        // negative hit or miss. Requests is a derived Int64 sum that can overflow;
        // expiry/eviction are separate events.
        bool invalid = h.Requests < 0 || h.PositiveHits < 0 || h.NegativeHits < 0 ||
            h.Misses < 0 || h.Expired < 0 || h.Evicted < 0 ||
            h.Occupancy < 0 || h.Capacity < 0 || h.Occupancy > h.Capacity ||
            accountedRequests > long.MaxValue || accountedRequests < 0 || (decimal)h.Requests != accountedRequests;
        return (invalid ? "WARNING: GeoIP cache request-path or capacity counters inconsistent; inspect cache accounting. " : string.Empty) +
            $"GeoIP cache (service lifetime): {accountedRequests.ToString(CultureInfo.InvariantCulture)} accounted eligible requests (reported Int64 total {h.Requests}), {h.PositiveHits} positive hits, {h.NegativeHits} negative hits, {h.Misses} misses (hit share {rate} of {accountedRequests.ToString(CultureInfo.InvariantCulture)} accounted eligible requests); " +
            $"expired on access: {h.Expired}, capacity-evicted entries: {h.Evicted}, retained entries: {h.Occupancy}/{h.Capacity}. Cache requests are not database attempts.";
    }

    private static string GeoLookupSummary(string name, GeoIpService.LookupHealthSnapshot? snapshot)
    {
        if (snapshot is not { } h) return name + " unknown";
        decimal attempts = h.AttemptsExact;
        bool invalid = h.Found < 0 || h.NotFound < 0 || h.Failed < 0 || h.AttemptsOverflowed;
        string rate = attempts <= 0 || h.Failed < 0 || h.Found < 0 || h.NotFound < 0
            ? "—" : ((decimal)h.Failed / attempts).ToString("P1", CultureInfo.InvariantCulture);
        return (invalid ? "WARNING: GeoIP lookup outcome counters invalid or exceed Int64; inspect lookup accounting. " : string.Empty) +
            $"{name}: {attempts.ToString(CultureInfo.InvariantCulture)} attempts, {h.Found} found, {h.NotFound} not found, {h.Failed} failed (failure share {rate})";
    }

    internal static string StorageSummary(EnrichmentStorageSnapshot? s)
    {
        if (s is null) return "Storage diagnostics unavailable.";
        bool invalid = s.Assets.Count < 0 || s.Assets.Limit < 0 || s.Assets.Count > s.Assets.Limit ||
            s.Assets.Rejected < 0 || s.Destinations.Count < 0 || s.Destinations.Limit < 0 ||
            s.Destinations.Count > s.Destinations.Limit || s.Destinations.Rejected < 0 ||
            s.Checkpoints.Writes < 0 || s.Checkpoints.Failures < 0;
        return (invalid ? "WARNING: enrichment registry capacity or checkpoint counters inconsistent; inspect storage accounting. " : string.Empty) +
            $"Current/last session assets: {s.Assets.Count}/{s.Assets.Limit}, capacity-rejected observations: {s.Assets.Rejected}; " +
            $"external destinations: {s.Destinations.Count}/{s.Destinations.Limit}, capacity-rejected observations: {s.Destinations.Rejected}. " +
            $"Checkpoint writes: {s.Checkpoints.Writes}, failures: {s.Checkpoints.Failures}; " +
            (s.Checkpoints.LastError is not null ? "Checkpoint diagnostic present (details withheld; inspect restricted local logs)." : "No checkpoint diagnostic reported.") +
            " Retained history may be incomplete; rejection counts are observations, not unique identities.";
    }

    internal static string CoverageSummary(EnrichmentCoverageSnapshot? c)
    {
        if (c is null) return "Evidence coverage unavailable.";
        return $"Published records (lifetime): {c.Published:N0}; both endpoint membership flags known: {c.LocalKnown:N0}/{c.Published:N0}; " +
            $"verified interface: {c.InterfaceKnown:N0}/{c.Published:N0}; DNS correlated: {c.DnsCorrelated:N0}/{c.Published:N0}; " +
            $"TLS correlated: {c.TlsCorrelated:N0}/{c.Published:N0}. " +
            $"Local TCP/UDP records sampled after process stage: {c.ProcessEligible:N0}; TCP socket ownership: {c.ProcessStrong:N0}/{c.ProcessEligible:N0} eligible; " +
            $"UDP binding only: {c.ProcessUdpBinding:N0}/{c.ProcessEligible:N0} eligible. Process-eligible records are a subset of published records, not a second publication count. " +
            "Coverage is observed evidence availability, not protocol recall; UDP binding is not remote tuple proof. " +
            (c.LocalKnown > c.Published || c.InterfaceKnown > c.Published || c.DnsCorrelated > c.Published || c.TlsCorrelated > c.Published || c.EtwPublished > c.Published || c.ProcessEligible > c.Published || c.ProcessStrong > c.ProcessEligible || c.ProcessUdpBinding > c.ProcessEligible ||
             c.Published < 0 || c.LocalKnown < 0 || c.InterfaceKnown < 0 || c.DnsCorrelated < 0 ||
             c.TlsCorrelated < 0 || c.ProcessEligible < 0 || c.ProcessStrong < 0 ||
             c.ProcessUdpBinding < 0 || c.EtwPublished < 0
                ? "WARNING: evidence coverage counters are negative or exceed their eligible publication or process-stage population; investigate snapshot accounting. "
                : string.Empty) +
            $"ETW published records (lifetime): {c.EtwPublished:N0}/{c.Published:N0}. ETW kernel records do not supply packet payload or verified capture-interface identity; missing DNS/TLS evidence is not a negative protocol observation.";
    }

    internal static string WorkerSummary(EnrichmentWorkerSnapshot? w)
    {
        if (w is null) return "Worker metrics unavailable.";
        string Mean(long sum, decimal count, long maximum) => count <= 0 || sum < 0 || maximum < 0 || maximum > sum
            ? "—" : ((decimal)sum / count).ToString("0.0", CultureInfo.InvariantCulture);
        // Lifetime outcome counters can collectively exceed Int64 without any individual
        // counter overflowing. Keep lifecycle reconciliation in a widened domain.
        decimal completed = (decimal)w.Returned + w.Cancelled + w.Faulted;
        bool invalidLifecycle = w.Started < 0 || w.Returned < 0 || w.Cancelled < 0 || w.Faulted < 0 || completed > w.Started;
        // Do not silently clamp impossible lifecycle populations to zero in flight.
        string inFlight = invalidLifecycle ? "—" : (w.Started - completed).ToString("N0", CultureInfo.InvariantCulture);
        string accounting = completed > w.Started
            ? $" WARNING: completed outcomes exceed started workers by {completed - w.Started:N0}; inspect worker lifecycle accounting."
            : string.Empty;
        if (w.Started < 0 || w.Returned < 0 || w.Cancelled < 0 || w.Faulted < 0 || w.Skipped < 0 ||
            w.WaitTotalMs < 0 || w.WaitMaxMs < 0 || w.ElapsedTotalMs < 0 || w.ElapsedMaxMs < 0 ||
            w.WaitMaxMs > w.WaitTotalMs || w.ElapsedMaxMs > w.ElapsedTotalMs ||
            (w.Started == 0 && (w.WaitTotalMs != 0 || w.WaitMaxMs != 0)) ||
            (completed == 0 && (w.ElapsedTotalMs != 0 || w.ElapsedMaxMs != 0)))
            accounting += " WARNING: invalid worker counters or duration accounting; inspect worker lifecycle accounting.";
        return $"Workers (lifetime): {w.Started:N0} started, {w.Returned:N0} returned, {w.Cancelled:N0} cancelled, {w.Faulted:N0} faulted; " +
            $"in flight at snapshot: {inFlight}; " +
            $"{w.Skipped:N0} cancelled before processing. Queue wait mean/max ms (started workers: {w.Started:N0}): {Mean(w.WaitTotalMs, invalidLifecycle ? 0 : w.Started, w.WaitMaxMs)} / {w.WaitMaxMs}; " +
            $"worker elapsed mean/max ms (completed workers: {completed:N0}): {Mean(w.ElapsedTotalMs, invalidLifecycle ? 0 : completed, w.ElapsedMaxMs)} / {w.ElapsedMaxMs}. " +
            "Returned does not imply provider success; worker elapsed includes rule evaluation." + accounting;
    }
}
