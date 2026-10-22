// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Analytics.Models
{
    public sealed class IncidentFeedback
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string IncidentId { get; set; } = string.Empty;
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
        public string FeedbackType { get; set; } = string.Empty;
        public string? SourceIp { get; set; }
        public string? DestinationIp { get; set; }
        public string? DestinationHost { get; set; }
        public string? DestinationPort { get; set; }
        public string? ProcessName { get; set; }
        public string? Category { get; set; }
        public string? AnalystNote { get; set; }
        public DateTime? SuppressUntilUtc { get; set; }
        public string[] Tags { get; set; } = Array.Empty<string>();
    }
}
