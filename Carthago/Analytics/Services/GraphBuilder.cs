// SPDX-License-Identifier: MIT
// File: Analytics/Services/GraphBuilder.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;

namespace Carthago.Analytics.Services
{
    public sealed class GraphBuilder
    {
        public GraphSnapshot BuildSnapshot(IEnumerable<DetectionEvent> events)
        {
            var edges = new List<GraphEdge>();
            var features = new Dictionary<string, NodeFeatures>(StringComparer.Ordinal);

            foreach (var e in events)
            {
                var src = e.SourceIp ?? "unknown-src";
                var dst = e.DestinationIp ?? "unknown-dst";
                edges.Add(new GraphEdge(src, dst));

                if (!features.TryGetValue(src, out var fs))
                    features[src] = fs = new NodeFeatures(src);
                if (!features.TryGetValue(dst, out var fd))
                    features[dst] = fd = new NodeFeatures(dst);

                fs.DegreeOut++;
                fd.DegreeIn++;
                fs.TotalEvents++;
                fd.TotalEvents++;
            }

            return new GraphSnapshot(edges, features);
        }
    }

    // ===== POCOs =====
    public sealed record GraphEdge(string Source, string Target);

    public sealed class NodeFeatures
    {
        public NodeFeatures(string id) { Id = id; }
        public string Id { get; }
        public int DegreeIn { get; set; }
        public int DegreeOut { get; set; }
        public long TotalEvents { get; set; }

        // Present to satisfy other components that expect them; we keep 0.
        public long TotalBytesIn { get; set; }
        public long TotalBytesOut { get; set; }
        public double PageRank { get; set; }
    }

    public sealed class GraphSnapshot
    {
        public GraphSnapshot(List<GraphEdge> edges, Dictionary<string, NodeFeatures> features)
        {
            Graph = edges;
            Features = features;
        }

        public List<GraphEdge> Graph { get; }
        public Dictionary<string, NodeFeatures> Features { get; }
    }
}
