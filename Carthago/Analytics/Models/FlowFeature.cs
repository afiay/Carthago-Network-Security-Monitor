// SPDX-License-Identifier: MIT
using System;
using Carthago.Models;

namespace Carthago.Analytics.Models
{
    public sealed class FlowFeature
    {
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
        public string SourceIp { get; set; } = "";
        public string? DestinationIp { get; set; }
        public int? DestinationPort { get; set; }
        public string Protocol { get; set; } = "";
        public long Bytes { get; set; }
        public int PacketCount { get; set; } = 1;
        public string? ProcessName { get; set; }
        public string? Country { get; set; }
        public string? Asn { get; set; }
        public string? Domain { get; set; }
        public string? Sni { get; set; }
        public string? Ja4 { get; set; }
        public string? Hassh { get; set; }
        public string? RuleId { get; set; }
        public string? RuleName { get; set; }
        public string? RuleSeverity { get; set; }
        public bool IsInternalSource { get; set; }
        public bool IsInternalDestination { get; set; }
        public string Direction { get; set; } = "unknown";
        public int HourOfDay { get; set; }
        public DayOfWeek DayOfWeek { get; set; }
        public bool IsDns { get; set; }
        public bool IsThreatFeedHit { get; set; }
        public SeverityLevel? DetectionSeverity { get; set; }
    }
}
