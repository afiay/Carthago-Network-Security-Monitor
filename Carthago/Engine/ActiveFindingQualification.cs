// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Carthago.Models;
using Carthago.Services.Sensors;

namespace Carthago.Engine;

// Active findings are not packet-rule matches. Persist only the bounded projected
// evidence and expose a DetectionEvent contract for the separate active inbox.
internal sealed class ActiveFindingRow
{
    public string Id { get; set; } = "";
    public string RuleId { get; set; } = "";
    public string Sensor { get; set; } = "";
    public string AdapterId { get; set; } = "";
    public string Source { get; set; } = "";
    public string Target { get; set; } = "";
    public string ProbeKey { get; set; } = "";
    public Guid BaselineId { get; set; }
    public Guid FirstObservationId { get; set; }
    public Guid ConfirmingObservationId { get; set; }
    public long ObservedTicks { get; set; }
    public string Kind { get; set; } = "";
    public string Field { get; set; } = "";
    public string Before { get; set; } = "";
    public string After { get; set; } = "";
    public string Severity { get; set; } = "";
}

internal static class ActiveFindingQualification
{
    internal static readonly TimeSpan MinimumSeparation = TimeSpan.FromMinutes(1);
    internal static readonly TimeSpan MaximumSeparation = TimeSpan.FromHours(24);
    internal const int MaxFindings = 1000;
    // Dedicated identifiers, not R-series packet rules. Conservative severity
    // reflects investigation priority, not probability of an attack.
    private static readonly Dictionary<string, (string Id, SeverityLevel Severity)> Catalog = new(StringComparer.Ordinal)
    {
        ["PortOpened"] = ("ASD001", SeverityLevel.Medium),
        ["PortRefused"] = ("ASD002", SeverityLevel.Low),
        ["DnsAnswerChanged"] = ("ASD003", SeverityLevel.Low),
        ["CertificateChanged"] = ("ASD004", SeverityLevel.Low),
        ["CertificateValidityChanged"] = ("ASD005", SeverityLevel.Low),
        ["CertificatePolicyChanged"] = ("ASD006", SeverityLevel.Medium),
        ["HttpStatusChanged"] = ("ASD007", SeverityLevel.Info),
        ["HttpHeaderChanged"] = ("ASD008", SeverityLevel.Low),
        ["GatewayMacChanged"] = ("ASD009", SeverityLevel.Medium),
        ["GatewayCompetingClaims"] = ("ASD010", SeverityLevel.Medium),
        ["SnmpInventoryChanged"] = ("ASD011", SeverityLevel.Low)
    };

    internal static IReadOnlyList<ActiveFindingRow> Qualify(ActiveEvidenceRow baseline,
        ActiveEvidenceRow first, ActiveEvidenceRow current, long approvedTicks, DateTimeOffset now)
    {
        if (!ActiveChangeDetector.SameScope(baseline, first) || !ActiveChangeDetector.SameScope(baseline, current) ||
            baseline.Id == first.Id || baseline.Id == current.Id || first.Id == current.Id ||
            baseline.ObservedTicks >= first.ObservedTicks || first.ObservedTicks < approvedTicks ||
            current.ObservedTicks > now.UtcDateTime.Ticks ||
            first.ObservedTicks < (now - MaximumSeparation).UtcDateTime.Ticks ||
            current.ObservedTicks - first.ObservedTicks < MinimumSeparation.Ticks ||
            current.ObservedTicks - first.ObservedTicks > MaximumSeparation.Ticks ||
            baseline.ObservedTicks < (now - ActiveEvidenceStore.Retention).UtcDateTime.Ticks)
            return Array.Empty<ActiveFindingRow>();
        var previous = ActiveChangeDetector.Compare(baseline, first);
        var latest = ActiveChangeDetector.Compare(baseline, current);
        if (previous.Status != "Changed" || latest.Status != "Changed") return Array.Empty<ActiveFindingRow>();
        var result = new List<ActiveFindingRow>();
        foreach (var change in latest.Changes)
        {
            if (!previous.Changes.Contains(change) || !Catalog.TryGetValue(change.Kind, out var rule)) continue;
            var key = JsonSerializer.Serialize(new[] { baseline.Id.ToString("N"), current.Sensor, current.AdapterId,
                current.Source, current.Target, current.ProbeKey, change.Kind, change.Field, change.Before, change.After });
            result.Add(new ActiveFindingRow
            {
                Id = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key))).ToLowerInvariant(),
                RuleId = rule.Id, Severity = rule.Severity.ToString(), Sensor = current.Sensor,
                AdapterId = current.AdapterId, Source = current.Source, Target = current.Target, ProbeKey = current.ProbeKey,
                BaselineId = baseline.Id, FirstObservationId = first.Id, ConfirmingObservationId = current.Id,
                ObservedTicks = current.ObservedTicks, Kind = change.Kind, Field = change.Field,
                Before = change.Before, After = change.After
            });
        }
        return result.AsReadOnly();
    }

    internal static DetectionEvent ToDetection(ActiveFindingRow finding)
    {
        if (!Catalog.TryGetValue(finding.Kind, out var rule) || finding.RuleId != rule.Id)
            throw new ArgumentException("Unknown active finding.");
        return new DetectionEvent
        {
            EventId = finding.Id, RuleId = rule.Id, RuleName = finding.Kind,
            TimestampUtc = new DateTime(finding.ObservedTicks, DateTimeKind.Utc),
            Severity = rule.Severity, SourceIp = finding.Source, DestinationIp = finding.Target,
            CaptureInterface = finding.AdapterId, Count = 2,
            Description = $"Active probe: {finding.Field} changed in two observations. Not proof of attack.",
            ConfidenceLabel = DetectionConfidenceLabel.Medium,
            RuleMaturityAtDetection = "ActiveSourceCandidate", RuleRevisionAtDetection = 1,
            DeliveryStatus = DetectionDeliveryStatus.Persisted,
            StructuredEvidence = new DetectionEvidenceSet(new[]
            {
                new DetectionEvidenceItem("Origin", "ActiveProbe", "ActiveEvidenceStore"),
                new DetectionEvidenceItem("Sensor", finding.Sensor, "ActiveEvidenceStore"),
                new DetectionEvidenceItem("ProbeKey", finding.ProbeKey, "ActiveEvidenceStore", true),
                new DetectionEvidenceItem("BaselineId", finding.BaselineId.ToString("N"), "ActiveEvidenceStore"),
                new DetectionEvidenceItem("FirstObservationId", finding.FirstObservationId.ToString("N"), "ActiveEvidenceStore"),
                new DetectionEvidenceItem("ConfirmingObservationId", finding.ConfirmingObservationId.ToString("N"), "ActiveEvidenceStore"),
                new DetectionEvidenceItem("Before", finding.Before, "ActiveEvidenceStore", true),
                new DetectionEvidenceItem("After", finding.After, "ActiveEvidenceStore", true)
            }, "Repeated active configuration observation; no passive packet or attack attribution.")
        };
    }
}
