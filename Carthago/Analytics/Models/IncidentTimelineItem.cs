// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;

namespace Carthago.Analytics.Models
{
    public sealed class IncidentTimelineItem
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
        public string Type { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Severity { get; set; } = "info";
        public int? RiskScoreAfter { get; set; }
        public string? SourceIp { get; set; }
        public string? DestinationIp { get; set; }
        public string? DestinationHost { get; set; }
        public string? Category { get; set; }
        public string[] Tags { get; set; } = Array.Empty<string>();
        public Dictionary<string, string> Details { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
