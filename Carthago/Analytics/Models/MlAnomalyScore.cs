// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;

namespace Carthago.Analytics.Models
{
    public sealed class MlAnomalyScore
    {
        public string SourceIp { get; set; } = string.Empty;
        public DateTime WindowStartUtc { get; set; }
        public DateTime WindowEndUtc { get; set; }
        public DateTime ScoredAtUtc { get; set; } = DateTime.UtcNow;
        public double Score { get; set; }
        public double Confidence { get; set; }
        public bool IsAnomalous { get; set; }
        public string ModelName { get; set; } = "mlnet-timeseries-v1";
        public string ModelVersion { get; set; } = "1.0";
        public string[] Reasons { get; set; } = Array.Empty<string>();
        public Dictionary<string, double> FeatureContributions { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
