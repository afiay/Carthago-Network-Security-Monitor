// SPDX-License-Identifier: MIT
// File: Services/EntityGraph/EntityObservation.cs
using System;
using System.Collections.Generic;

namespace Carthago.Services.EntityGraph
{
    public sealed class EntityObservation
    {
        public string ObservationId { get; set; } = Guid.NewGuid().ToString("N");
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
        public string Source { get; set; } = "detection";
        public string? EventId { get; set; }
        public string? RuleId { get; set; }
        public List<string> EntityIds { get; set; } = new();
    }
}
