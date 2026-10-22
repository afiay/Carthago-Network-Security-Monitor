// SPDX-License-Identifier: MIT
// File: Analytics/Models/ScoredNode.cs
using Carthago.Analytics.Services;

namespace Carthago.Analytics.Models
{
    public sealed class ScoredNode
    {
        public string NodeId { get; set; } = "";
        public NodeFeatures Features { get; set; } = new NodeFeatures("unknown");
        public double Score { get; set; }
    }
}
