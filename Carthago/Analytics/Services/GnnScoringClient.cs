// SPDX-License-Identifier: MIT
// File: Analytics/Services/GnnScoringClient.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using Carthago.Analytics.Models;

namespace Carthago.Analytics.Services
{
    /// <summary>
    /// Graph anomaly scoring with two modes:
    /// - LocalHeuristic: pure C# (no native deps) using normalized features + sigmoid
    /// - RemotePyG: POST to a local Python service that runs a real GNN (optional)
    /// </summary>
    public sealed class GnnScoringClient
    {
        public enum Mode { LocalHeuristic, RemotePyG }

        private readonly Mode _mode;
        private readonly HttpClient _http = new();

        public GnnScoringClient(Mode mode, string? remoteBaseUrl = "http://127.0.0.1:5009")
        {
            _mode = mode;
            if (_mode == Mode.RemotePyG)
                _http.BaseAddress = new Uri(remoteBaseUrl!);
        }

        public IEnumerable<ScoredNode> ScoreNodes(GraphSnapshot snap)
            => _mode == Mode.RemotePyG ? ScoreRemote(snap) : ScoreLocal(snap);

        private IEnumerable<ScoredNode> ScoreLocal(GraphSnapshot snap)
        {
            if (snap.Features.Count == 0)
                yield break;

            // Global maxima for normalization
            int maxIn = Math.Max(1, snap.Features.Values.Max(f => f.DegreeIn));
            int maxOut = Math.Max(1, snap.Features.Values.Max(f => f.DegreeOut));
            long maxBin = Math.Max(1, snap.Features.Values.Max(f => f.TotalBytesIn));
            long maxBout = Math.Max(1, snap.Features.Values.Max(f => f.TotalBytesOut));
            double maxPr = Math.Max(1e-9, snap.Features.Values.Max(f => f.PageRank));

            // Weights and bias (tune as needed)
            const double wIn = 0.30, wOut = 0.30, wPr = 0.25, wBout = 0.10, wBin = 0.05;
            const double bias = 1.2;

            foreach (var f in snap.Features.Values)
            {
                double nin = (double)f.DegreeIn / maxIn;
                double nout = (double)f.DegreeOut / maxOut;
                double npr = f.PageRank / maxPr;
                double nbin = (double)f.TotalBytesIn / maxBin;
                double nbout = (double)f.TotalBytesOut / maxBout;

                double raw = (wIn * nin) + (wOut * nout) + (wPr * npr) + (wBout * nbout) + (wBin * nbin) - bias;
                double score = 1.0 / (1.0 + Math.Exp(-raw)); // sigmoid
                if (score < 0) score = 0; else if (score > 1) score = 1;

                yield return new ScoredNode { NodeId = f.Id, Features = f, Score = score };
            }
        }

        private IEnumerable<ScoredNode> ScoreRemote(GraphSnapshot snap)
        {
            // Edges are a List<GraphEdge>; do not use ".Edges"
            var payload = new
            {
                nodes = snap.Features.Values.Select(n => new
                {
                    id = n.Id,
                    f = new[] { n.DegreeIn, n.DegreeOut, n.PageRank, (double)n.TotalBytesIn, (double)n.TotalBytesOut }
                }),
                edges = snap.Graph.Select(e => new[] { e.Source, e.Target })
            };

            var req = new StringContent(JsonSerializer.Serialize(payload));
            req.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

            var resp = _http.PostAsync("/score", req).GetAwaiter().GetResult();
            resp.EnsureSuccessStatusCode();

            var json = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            var dict = JsonSerializer.Deserialize<Dictionary<string, double>>(json) ?? new();

            foreach (var f in snap.Features.Values)
            {
                dict.TryGetValue(f.Id, out var s);
                var v = double.IsFinite(s) ? s : 0;
                if (v < 0) v = 0; else if (v > 1) v = 1;

                yield return new ScoredNode { NodeId = f.Id, Features = f, Score = v };
            }
        }
    }
}
