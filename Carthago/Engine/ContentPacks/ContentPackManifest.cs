// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackManifest.cs
using System.Collections.Generic;
using Carthago.Engine.Rules;

namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackSignatureMetadata
    {
        public string? Algorithm { get; set; }
        public string? Signature { get; set; }
        public string? PublicKeyId { get; set; }
    }

    public sealed class ContentPackManifest
    {
        public string PackId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Version { get; set; } = "1.0.0";
        public string Description { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Author { get; set; } = string.Empty;
        public string MinimumCarthagoVersion { get; set; } = "1.0.0";
        public List<ContentPackRule> Rules { get; set; } = new();
        public List<ContentPackTuningDefaults> ExistingRuleOverrides { get; set; } = new();
        public List<ContentPackProfileDefaults> Profiles { get; set; } = new();
        public List<ContentPackTuningDefaults> TuningDefaults { get; set; } = new();
        public List<string> RequiredTelemetry { get; set; } = new();
        public List<string> RequiredApprovedAssets { get; set; } = new();
        public List<ContentPackReplaySampleReference> ReplaySamples { get; set; } = new();
        public List<ContentPackBenchmarkExpectation> Benchmarks { get; set; } = new();
        public List<ContentPackHuntReference> HuntingQueries { get; set; } = new();
        public List<ContentPackResponseRecommendation> ResponseRecommendations { get; set; } = new();
        public List<ContentPackDashboardPreset> DashboardPresets { get; set; } = new();
        public List<RuleReference> References { get; set; } = new();
        public List<string> Changelog { get; set; } = new();
        public List<string> SafetyNotes { get; set; } = new();
        public string License { get; set; } = string.Empty;
        public ContentPackSignatureMetadata Signature { get; set; } = new();
        public bool DisableMandatoryJournaling { get; set; }
        public List<string> InstallOperations { get; set; } = new();
    }

    public sealed class ContentPackValidationResult
    {
        public bool IsValid => Errors.Count == 0;
        public List<string> Errors { get; set; } = new();
        public List<string> Warnings { get; set; } = new();
    }
}
