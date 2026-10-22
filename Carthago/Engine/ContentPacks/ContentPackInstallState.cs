// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackInstallState.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Services.Response;

namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackBenchmarkResultSummary
    {
        public string PackId { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public List<string> EnabledProfiles { get; set; } = new();
        public int RulesCovered { get; set; }
        public List<string> RulesWithoutSamples { get; set; } = new();
        public double PositivePassRate { get; set; }
        public int BenignFalsePositiveCount { get; set; }
        public int CriticalFalsePositiveCount { get; set; }
        public double AverageConfidence { get; set; }
        public RuleMode RecommendedDefaultMode { get; set; } = RuleMode.Shadow;
        public List<string> RecommendedProfileChanges { get; set; } = new();
        public List<string> TelemetryGaps { get; set; } = new();
        public bool PassedExpectations { get; set; }
        public List<string> FailedExpectations { get; set; } = new();
        public string JsonPath { get; set; } = string.Empty;
        public string MarkdownPath { get; set; } = string.Empty;
    }

    public sealed class InstalledContentPackState
    {
        public string PackId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public bool Enabled { get; set; }
        public DateTime InstalledAtUtc { get; set; }
        public DateTime? LastEnabledAtUtc { get; set; }
        public ContentPackValidationResult ValidationResult { get; set; } = new();
        public ContentPackBenchmarkResultSummary? LastBenchmarkResult { get; set; }
        public List<string> InstalledRuleIds { get; set; } = new();
        public List<string> ActivatedProfileChanges { get; set; } = new();
        public List<string> AppliedTuningChanges { get; set; } = new();
        public List<ContentPackInstallPlan> DryRunPlanHistory { get; set; } = new();
        public List<string> Changelog { get; set; } = new();
        public List<string> HistoricalWarnings { get; set; } = new();
        public string ManifestPath { get; set; } = string.Empty;
    }

    public sealed class ContentPackInstallState
    {
        public string SchemaVersion { get; set; } = "1";
        public List<InstalledContentPackState> InstalledPacks { get; set; } = new();
        public List<ContentPackInstallPlan> DryRunPlanHistory { get; set; } = new();
    }
}
