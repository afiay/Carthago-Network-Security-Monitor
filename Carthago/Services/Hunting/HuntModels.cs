// SPDX-License-Identifier: MIT
// File: Services/Hunting/HuntModels.cs
using System;
using System.Collections.Generic;
using Carthago.Analytics.Models;
using Carthago.Models;

namespace Carthago.Services.Hunting
{
    public sealed class HuntQuery
    {
        public string? RuleId { get; set; }
        public string? EntityContains { get; set; }
        public string? SourceIp { get; set; }
        public string? DestinationIp { get; set; }
        public double? MinConfidence { get; set; }
        public DetectionSuppressionStatus? SuppressionStatus { get; set; }
        public ExternalSinkDeliveryStatus? ExternalSinkStatus { get; set; }
        public AttackStoryType? StoryType { get; set; }
        public int? MinRiskScore { get; set; }
    }

    public sealed class HuntQueryResult
    {
        public List<DetectionEvent> Detections { get; set; } = new();
        public List<Incident> Incidents { get; set; } = new();
        public List<string> SourceIds { get; set; } = new();
    }

    public sealed class SavedHunt
    {
        public string HuntId { get; set; } = Guid.NewGuid().ToString("N");
        public string? PackId { get; set; }
        public string Name { get; set; } = string.Empty;
        public HuntQuery Query { get; set; } = new();
    }
}
