// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackTuningDefaults.cs
using System.Collections.Generic;
using Carthago.Engine.Rules;

namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackTuningDefaults
    {
        public string RuleId { get; set; } = string.Empty;
        public RuleMode? RecommendedMode { get; set; }
        public int? Threshold { get; set; }
        public int? WindowSeconds { get; set; }
        public double? ConfidenceFloor { get; set; }
        public Dictionary<string, string> FieldOverrides { get; set; } = new(System.StringComparer.OrdinalIgnoreCase);
        public string Notes { get; set; } = string.Empty;
    }
}
