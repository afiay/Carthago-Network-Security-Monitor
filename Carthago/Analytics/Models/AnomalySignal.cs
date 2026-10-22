// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;

namespace Carthago.Analytics.Models
{
    public sealed class AnomalySignal
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedUtc { get; set; } = DateTime.UtcNow;

        public string SourceIp { get; set; } = "";
        public string? DestinationIp { get; set; }
        public string? DestinationHost { get; set; }
        public string? DestinationPort { get; set; }
        public string? Protocol { get; set; }

        public string Category { get; set; } = "";
        public string Title { get; set; } = "";
        public string Description { get; set; } = "";

        public double Score { get; set; }
        public string Severity { get; set; } = "medium";

        public List<string> Reasons { get; set; } = new();
        public List<string> RelatedRuleIds { get; set; } = new();
        public List<string> Tags { get; set; } = new();

        public Dictionary<string, string> Features { get; set; } = new();
    }
}
