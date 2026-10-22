// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackRule.cs
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackRule
    {
        public string RuleId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public SeverityLevel DefaultSeverity { get; set; } = SeverityLevel.Medium;
        public ContentPackRuleSource Source { get; set; } = new();
        public bool Deprecated { get; set; }
        public List<RuleReference> References { get; set; } = new();
        public List<RuleFalsePositiveNote> KnownFalsePositives { get; set; } = new();
        public List<RuleTelemetryRequirement> TelemetryRequirements { get; set; } = new();
    }
}
