// SPDX-License-Identifier: MIT
using System.Text.Json.Serialization;

namespace Carthago.Contracts;

// Process-lifetime counters and instantaneous observations. No packet payloads.
public sealed record PipelineTelemetry([property: JsonRequired] bool NativeStarted, [property: JsonRequired] DateTimeOffset? LastPacketUtc,
    [property: JsonRequired] int? QueueDepth, [property: JsonRequired] int QueueCapacity, [property: JsonRequired] int WorkersAlive, [property: JsonRequired] int WorkersConfigured,
    [property: JsonRequired] long WorkerFaults, [property: JsonRequired] long EnrichmentFallbacks, [property: JsonRequired] long Evaluations, [property: JsonRequired] long JournalWriteFailures,
    [property: JsonRequired] long PersistedDetections, [property: JsonRequired] long RuleFailures);
public sealed record PipelineAssessment(string State, string Activity, string Journal,
    string[] Reasons, string DetectionValidation = "not_assessed");

public static class PipelineHealth
{
    public static readonly TimeSpan MaxAge = TimeSpan.FromSeconds(120);
    public static readonly TimeSpan IdleAfter = TimeSpan.FromSeconds(30);

    public static void Validate(PipelineTelemetry p)
    {
        if (p.QueueCapacity <= 0 || p.QueueDepth is < 0 ||
            (p.QueueDepth is int depth && depth > p.QueueCapacity) ||
            p.WorkersConfigured <= 0 || p.WorkersAlive < 0 || p.WorkersAlive > p.WorkersConfigured ||
            p.WorkerFaults < 0 || p.EnrichmentFallbacks < 0 || p.Evaluations < 0 ||
            p.JournalWriteFailures < 0 || p.PersistedDetections < 0 || p.RuleFailures < 0 ||
            (p.LastPacketUtc is { } last && (last == default || last.Offset != TimeSpan.Zero)))
            throw new InvalidDataException("Invalid pipeline telemetry.");
    }

    public static PipelineAssessment Assess(ForegroundMonitorCounters? counters, DateTimeOffset? sampledUtc,
        DateTimeOffset now, bool monitoring)
    {
        if (!monitoring) return new("unknown", "not_monitoring", "not_assessed", ["monitor_not_running"]);
        if (counters?.Pipeline is not { } p || sampledUtc is null)
            return new("unknown", "unknown", "not_assessed", ["telemetry_unavailable"]);
        Validate(p);
        if (counters.Captured < 0 || counters.Parsed < 0 || counters.ParseErrors < 0 || counters.Detections < 0)
            throw new InvalidDataException("Invalid capture counters.");
        if (sampledUtc.Value.Offset != TimeSpan.Zero || sampledUtc.Value > now || now - sampledUtc.Value > MaxAge ||
            (p.LastPacketUtc is { } packet && packet > sampledUtc.Value))
            return new("unknown", "unknown", "not_assessed", ["stale_or_inconsistent_telemetry"]);
        string activity = p.LastPacketUtc is { } recent && now - recent <= IdleAfter ? "recent_packets" : "no_recent_packets";
        string journal = p.JournalWriteFailures > 0 ? "write_failure_observed" :
            p.PersistedDetections > 0 ? "persistence_observed" : "not_exercised";
        var reasons = new List<string>();
        if (!p.NativeStarted) reasons.Add("native_capture_not_started");
        if (p.WorkersAlive == 0) reasons.Add("no_live_enrichment_workers");
        if (p.JournalWriteFailures > 0) reasons.Add("journal_write_failure_observed");
        if (reasons.Count > 0) return new("failed", activity, journal, reasons.ToArray());

        if (p.WorkersAlive < p.WorkersConfigured) reasons.Add("enrichment_worker_exit");
        if (p.WorkerFaults > 0) reasons.Add("enrichment_worker_fault_observed");
        if (p.EnrichmentFallbacks > 0) reasons.Add("enrichment_fallback_observed");
        if (p.RuleFailures > 0) reasons.Add("rule_failure_observed");
        if (p.QueueDepth is int q && (long)q * 100 >= (long)p.QueueCapacity * 80) reasons.Add("enrichment_queue_pressure");
        // Cumulative error ratio, not an interval rate. Minimum 20 parsed/error observations.
        double attempted = (double)counters.Parsed + counters.ParseErrors;
        if (attempted >= 20 && counters.ParseErrors / attempted >= 0.10) reasons.Add("parse_error_ratio_high");
        if (reasons.Count > 0) return new("degraded", activity, journal, reasons.ToArray());
        if (p.QueueDepth is null) return new("unknown", activity, journal, ["queue_depth_unavailable"]);
        if (activity == "no_recent_packets") return new("idle", activity, journal, ["packet_absence_not_failure_proof"]);
        if (p.Evaluations == 0) return new("unknown", activity, journal, ["evaluation_not_observed"]);
        return new("healthy", activity, journal, ["observed_pipeline_no_measured_degradation"]);
    }
}
