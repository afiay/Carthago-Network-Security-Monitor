// File: Models/DetectionEvent.cs
using System;

namespace Carthago.Models
{
    public enum SeverityLevel { Info, Low, Medium, High, Critical }

    public enum DetectionDeliveryStatus
    {
        Pending,
        Persisted,
        Delivered,
        Failed,
        FailedToPersist
    }

    public enum DetectionSuppressionStatus
    {
        None,
        Suppressed,
        EmittedAfterSuppressionWindow,
        Shadowed
    }

    public enum DetectionConfidenceLabel
    {
        Unknown,
        Low,
        Medium,
        High
    }

    public sealed record DetectionEvidenceItem(
        string Key,
        string Value,
        string Source,
        bool IsSensitive = false);

    public sealed record DetectionEvidenceSet(
        System.Collections.Generic.IReadOnlyList<DetectionEvidenceItem> Items,
        string Summary);

    public enum ExternalSinkDeliveryStatus
    {
        NotQueued,
        Pending,
        Delivered,
        Failed
    }

    public class DetectionEvent
    {
        public string EventId { get; set; } = Guid.NewGuid().ToString("N");

        public DateTime Timestamp { get; set; }
        public DateTime TimestampUtc
        {
            get => Timestamp;
            set => Timestamp = value.Kind == DateTimeKind.Utc ? value : value.ToUniversalTime();
        }

        public string RuleId { get; set; } = string.Empty;
        public string RuleName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Summary
        {
            get => Description;
            set => Description = value ?? string.Empty;
        }

        public string? SourceIp { get; set; }
        public int? SourcePort { get; set; }
        public string? DestinationIp { get; set; }
        public string? DestinationHost { get; set; }
        public int? DestinationPort { get; set; }
        public string? Protocol { get; set; }
        public string? ProcessName { get; set; }
        public string? Country { get; set; }
        public string? Asn { get; set; }
        public string? Ja4 { get; set; }
        public string? Hassh { get; set; }
        public string? QuicAlpn { get; set; }
        public string? QuicConnectionIdHash { get; set; }

        public string? PacketId { get; set; }
        public string? FlowId { get; set; }
        public string? CorrelationId { get; set; }
        public string? Evidence { get; set; }
        public DetectionEvidenceSet? StructuredEvidence { get; set; }
        public double ConfidenceScore { get; set; }
        public DetectionConfidenceLabel ConfidenceLabel { get; set; } = DetectionConfidenceLabel.Unknown;
        public double EvidenceScore { get; set; }
        public double BaselineScore { get; set; }
        public double ThreatIntelScore { get; set; }
        public double CorrelationScore { get; set; }
        public string? RuleMaturityAtDetection { get; set; }
        public int RuleRevisionAtDetection { get; set; }
        public string? JournalPath { get; set; }
        public DateTime? PersistedAtUtc { get; set; }
        public string? PersistenceError { get; set; }
        public DetectionDeliveryStatus DeliveryStatus { get; set; } = DetectionDeliveryStatus.Pending;
        public DetectionSuppressionStatus SuppressionStatus { get; set; } = DetectionSuppressionStatus.None;

        // Local journal status is intentionally separate from external sink state.
        // A sink may fail while the detection remains durable in the local journal.
        public ExternalSinkDeliveryStatus ExternalDeliveryStatus { get; set; } = ExternalSinkDeliveryStatus.NotQueued;
        public string? LastSinkName { get; set; }
        public string? LastSinkError { get; set; }
        public DateTime? LastSinkAttemptUtc { get; set; }
        public int SinkSuccessCount { get; set; }
        public int SinkFailureCount { get; set; }

        // Sensor/fleet context. Defaults are supplied by SensorIdentity when available.
        public string? SensorId { get; set; }
        public string? SiteId { get; set; }
        public string? TenantId { get; set; }
        public string? CaptureInterface { get; set; }
        public string? SensorVersion { get; set; }
        public double? SensorClockSkewMs { get; set; }
        public DateTime? IngestionTimestampUtc { get; set; }

        public SeverityLevel Severity { get; set; } = SeverityLevel.Low;
        public int Count { get; set; }
        public int WindowSeconds { get; set; }

        // Needed by RuleEngine for logging/correlation
        public Sensitivity SensitivityAtTrigger { get; set; } = Sensitivity.Balanced;
    }
}
