// SPDX-License-Identifier: MIT
// File: Services/EntityGraph/EntityRiskReason.cs
using System;

namespace Carthago.Services.EntityGraph
{
    public sealed class EntityRiskReason
    {
        public string EntityId { get; set; } = string.Empty;
        public int ScoreDelta { get; set; }
        public string Reason { get; set; } = string.Empty;
        public string? EvidenceEventId { get; set; }
        public string? RuleId { get; set; }
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    }
}
