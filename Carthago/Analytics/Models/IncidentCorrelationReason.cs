// SPDX-License-Identifier: MIT
// File: Analytics/Models/IncidentCorrelationReason.cs
using System;
using System.Collections.Generic;
using System.Linq;

namespace Carthago.Analytics.Models
{
    public sealed class IncidentCorrelationReason
    {
        public string Code { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public double Weight { get; set; }
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
        public string? EventId { get; set; }
        public string? RuleId { get; set; }
        public string? Category { get; set; }
        public string? SourceNodeId { get; set; }
        public string? TargetNodeId { get; set; }
        public List<string> EvidenceKeys { get; set; } = new();

        public static IncidentCorrelationReason Create(
            string code,
            string description,
            double weight,
            DateTime timestampUtc,
            string? eventId = null,
            string? ruleId = null,
            string? category = null,
            string? sourceNodeId = null,
            string? targetNodeId = null,
            IEnumerable<string>? evidenceKeys = null)
        {
            return new IncidentCorrelationReason
            {
                Code = string.IsNullOrWhiteSpace(code) ? "CORRELATION_REASON" : code.Trim(),
                Description = description ?? string.Empty,
                Weight = Math.Clamp(weight, 0, 1),
                TimestampUtc = timestampUtc.Kind == DateTimeKind.Utc ? timestampUtc : timestampUtc.ToUniversalTime(),
                EventId = string.IsNullOrWhiteSpace(eventId) ? null : eventId.Trim(),
                RuleId = string.IsNullOrWhiteSpace(ruleId) ? null : ruleId.Trim(),
                Category = string.IsNullOrWhiteSpace(category) ? null : category.Trim(),
                SourceNodeId = string.IsNullOrWhiteSpace(sourceNodeId) ? null : sourceNodeId.Trim(),
                TargetNodeId = string.IsNullOrWhiteSpace(targetNodeId) ? null : targetNodeId.Trim(),
                EvidenceKeys = evidenceKeys?.Where(k => !string.IsNullOrWhiteSpace(k)).Select(k => k.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList() ?? new List<string>()
            };
        }
    }
}
