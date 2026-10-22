// SPDX-License-Identifier: MIT
// File: Analytics/Models/IncidentReasonGraph.cs
using System;
using System.Collections.Generic;
using System.Linq;

namespace Carthago.Analytics.Models
{
    public sealed class IncidentReasonGraph
    {
        public List<IncidentReasonNode> Nodes { get; set; } = new();
        public List<IncidentReasonEdge> Edges { get; set; } = new();
        public DateTime UpdatedUtc { get; set; } = DateTime.UtcNow;

        public IncidentReasonNode GetOrAddNode(string id, string type, string label, double weight = 0)
        {
            id = NormalizeId(id);
            var existing = Nodes.FirstOrDefault(n => string.Equals(n.Id, id, StringComparison.OrdinalIgnoreCase));
            if (existing != null)
            {
                existing.Weight = Math.Max(existing.Weight, Math.Clamp(weight, 0, 1));
                existing.LastSeenUtc = DateTime.UtcNow;
                if (!string.IsNullOrWhiteSpace(label))
                    existing.Label = label;
                return existing;
            }

            var node = new IncidentReasonNode
            {
                Id = id,
                Type = string.IsNullOrWhiteSpace(type) ? "Unknown" : type.Trim(),
                Label = string.IsNullOrWhiteSpace(label) ? id : label.Trim(),
                Weight = Math.Clamp(weight, 0, 1),
                FirstSeenUtc = DateTime.UtcNow,
                LastSeenUtc = DateTime.UtcNow
            };
            Nodes.Add(node);
            return node;
        }

        public void AddEdge(string sourceId, string targetId, string relationship, double weight = 0, string? evidenceId = null)
        {
            sourceId = NormalizeId(sourceId);
            targetId = NormalizeId(targetId);
            relationship = string.IsNullOrWhiteSpace(relationship) ? "related_to" : relationship.Trim();

            var existing = Edges.FirstOrDefault(e =>
                string.Equals(e.SourceId, sourceId, StringComparison.OrdinalIgnoreCase)
                && string.Equals(e.TargetId, targetId, StringComparison.OrdinalIgnoreCase)
                && string.Equals(e.Relationship, relationship, StringComparison.OrdinalIgnoreCase));
            if (existing != null)
            {
                existing.Weight = Math.Max(existing.Weight, Math.Clamp(weight, 0, 1));
                existing.LastSeenUtc = DateTime.UtcNow;
                if (!string.IsNullOrWhiteSpace(evidenceId) && !existing.EvidenceIds.Contains(evidenceId, StringComparer.OrdinalIgnoreCase))
                    existing.EvidenceIds.Add(evidenceId);
                return;
            }

            var edge = new IncidentReasonEdge
            {
                SourceId = sourceId,
                TargetId = targetId,
                Relationship = relationship,
                Weight = Math.Clamp(weight, 0, 1),
                FirstSeenUtc = DateTime.UtcNow,
                LastSeenUtc = DateTime.UtcNow
            };
            if (!string.IsNullOrWhiteSpace(evidenceId))
                edge.EvidenceIds.Add(evidenceId.Trim());
            Edges.Add(edge);
            UpdatedUtc = DateTime.UtcNow;
        }

        public IReadOnlyList<IncidentReasonNode> ImportantNodes(int limit = 12)
            => Nodes.OrderByDescending(n => n.Weight).ThenBy(n => n.Type).Take(Math.Max(1, limit)).ToArray();

        private static string NormalizeId(string value)
            => string.IsNullOrWhiteSpace(value) ? "unknown" : value.Trim().ToLowerInvariant();
    }

    public sealed class IncidentReasonNode
    {
        public string Id { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string Label { get; set; } = string.Empty;
        public double Weight { get; set; }
        public DateTime FirstSeenUtc { get; set; } = DateTime.UtcNow;
        public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
    }

    public sealed class IncidentReasonEdge
    {
        public string SourceId { get; set; } = string.Empty;
        public string TargetId { get; set; } = string.Empty;
        public string Relationship { get; set; } = string.Empty;
        public double Weight { get; set; }
        public List<string> EvidenceIds { get; set; } = new();
        public DateTime FirstSeenUtc { get; set; } = DateTime.UtcNow;
        public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
    }
}
