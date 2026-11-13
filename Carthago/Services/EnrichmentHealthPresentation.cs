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
            WorkerSummary(stats.EnrichmentWorkers), providers);
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
