// SPDX-License-Identifier: MIT
// File: Analytics/Models/FlowRecord.cs
using System;

namespace Carthago.Analytics.Models
{
    /// <summary>
    /// A minimal normalized network flow summary extracted from DetectionEvent.
    /// </summary>
    public sealed class FlowRecord
    {
        public DateTime TimestampUtc { get; set; }
        public string Source { get; set; } = "";       // IP or user
        public string Destination { get; set; } = "";  // IP or service
        public string Protocol { get; set; } = "";
        public int? SourcePort { get; set; }
        public int? DestinationPort { get; set; }
        public long? Bytes { get; set; }
        public string? RuleId { get; set; }
        public int? Severity { get; set; }
    }
}
