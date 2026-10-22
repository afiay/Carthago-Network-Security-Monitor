// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackReplaySampleReference.cs
using System.Collections.Generic;
using Carthago.Services.Benchmarking;

namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackReplaySampleReference
    {
        public string SampleId { get; set; } = string.Empty;
        public string RelativePath { get; set; } = string.Empty;
        public ReplaySampleClassification Classification { get; set; }
        public List<string> ExpectedRuleIds { get; set; } = new();
        public string Purpose { get; set; } = string.Empty;
        public string? ProfileName { get; set; }
    }

    public sealed class ContentPackBenchmarkExpectation
    {
        public string ProfileName { get; set; } = string.Empty;
        public double MinimumPositivePassRate { get; set; }
        public int MaximumCriticalFalsePositives { get; set; }
        public bool RequireBenchmarkBeforeAlertPromotion { get; set; } = true;
    }
}
