// SPDX-License-Identifier: MIT
// File: Services/Benchmarking/TuningBenchmarkDeploymentState.cs
using System;
using System.Collections.Generic;

namespace Carthago.Services.Benchmarking
{
    public static class TuningBenchmarkDeploymentStates
    {
        public const string ColdUnconfigured = "ColdUnconfigured";
        public const string CalibratedConfigured = "CalibratedConfigured";

        public static IReadOnlyList<string> All { get; } =
            new[] { ColdUnconfigured, CalibratedConfigured };

        public static IReadOnlyDictionary<string, TuningBenchmarkProfileSampleSummary> ProfilesFor(
            TuningBenchmarkSampleResult sample,
            string? deploymentState)
        {
            if (sample == null) throw new ArgumentNullException(nameof(sample));
            if (string.IsNullOrWhiteSpace(deploymentState)
                || string.Equals(deploymentState, ColdUnconfigured, StringComparison.OrdinalIgnoreCase))
                return sample.Profiles;

            if (sample.DeploymentStateProfiles.TryGetValue(deploymentState, out var profiles))
                return profiles;

            return new Dictionary<string, TuningBenchmarkProfileSampleSummary>(StringComparer.OrdinalIgnoreCase);
        }
    }

    public sealed class TuningBenchmarkDeploymentStateResult
    {
        public string StateName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public bool SimulatedBaselineReady { get; set; }
        public bool SimulatedBaselineLearningMode { get; set; }
        public string EnvironmentConfigurationSource { get; set; } = string.Empty;
        public Dictionary<string, TuningBenchmarkProfileSummary> ProfileResults { get; set; }
            = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, DetectionQualityMetrics> SampleLevelQualityByProfile { get; set; }
            = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, TuningBenchmarkDetectionFunnel> DetectionFunnelByProfile { get; set; }
            = new(StringComparer.OrdinalIgnoreCase);
        public List<TuningBenchmarkRecallGap> RecallGaps { get; set; } = new();
    }
}
