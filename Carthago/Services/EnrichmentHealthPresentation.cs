// SPDX-License-Identifier: MIT
using System.Collections.Generic;
using System.Globalization;

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
            WorkerSummary(stats.EnrichmentWorkers) + " " + CoverageSummary(stats.EnrichmentCoverage) + " " + StorageSummary(stats.EnrichmentStorage) + " " + GeoSummary(stats), providers);
    }

    internal static string GeoSummary(TrafficCaptureService.StatsSnapshot stats)
    {
        return $"GeoIP databases (reader startup): City {stats.GeoCityDatabaseStatus?.ToString() ?? "unknown"}; " +
            $"ASN {stats.GeoAsnDatabaseStatus?.ToString() ?? "unknown"}. " +
            "Ready means reader opened, not a successful lookup or verified database edition.";
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
            $"Local TCP/UDP records sampled after process stage: {c.ProcessEligible:N0}; capture/TCP attribution: {c.ProcessStrong:N0}; " +
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
