// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackInstallPlan.cs
using System.Collections.Generic;

namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackInstallPlan
    {
        public string PackId { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public bool DryRun { get; set; } = true;
        public bool EnableAfterInstall { get; set; }
        public ContentPackValidationResult Validation { get; set; } = new();
        public List<string> PlannedChanges { get; set; } = new();
        public List<string> NewRuleIds { get; set; } = new();
        public List<string> ProfileChanges { get; set; } = new();
        public List<string> TuningChanges { get; set; } = new();
        public List<string> ReplaySamples { get; set; } = new();
        public List<string> ResponseRecommendations { get; set; } = new();
        public List<string> SafetyWarnings { get; set; } = new();
        public List<string> Errors { get; set; } = new();
    }
}
