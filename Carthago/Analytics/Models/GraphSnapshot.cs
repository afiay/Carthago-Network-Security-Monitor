// SPDX-License-Identifier: MIT
// File: Analytics/Models/GraphSnapshot.cs
using System.Collections.Generic;
using Carthago.Analytics.Services;

namespace Carthago.Analytics.Models
{
    /// <summary>
    /// Lightweight directed edge between two node IDs (e.g., IPs).
    /// </summary>
    public sealed class GraphEdge
    {
        public string Source { get; }
        public string Target { get; }

        public GraphEdge(string source, string target)
        {
            Source = source;
            Target = target;
        }
    }

    /// <summary>
    /// Snapshot used by the scorer. Features come from Analytics.Services.NodeFeatures.
    /// </summary>
    public sealed class GraphSnapshot
    {
        /// <summary>Per-node features keyed by node ID.</summary>
        public Dictionary<string, NodeFeatures> Features { get; } = new();

        /// <summary>Directed graph edges.</summary>
        public List<GraphEdge> Graph { get; } = new();
    }
}
