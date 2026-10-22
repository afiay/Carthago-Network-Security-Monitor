// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackUpgradePlan.cs
using System.Collections.Generic;

namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackUpgradePlan
    {
        public string PackId { get; set; } = string.Empty;
        public string CurrentVersion { get; set; } = string.Empty;
        public string TargetVersion { get; set; } = string.Empty;
        public bool IsDowngrade { get; set; }
        public List<string> AddedRuleIds { get; set; } = new();
        public List<string> DeprecatedRuleIds { get; set; } = new();
        public List<string> RemovedRuleIds { get; set; } = new();
        public List<string> PreservedUserOverrideNotes { get; set; } = new();
        public List<string> Warnings { get; set; } = new();
        public List<string> Errors { get; set; } = new();
    }
}
