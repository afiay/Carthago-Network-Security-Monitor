// SPDX-License-Identifier: MIT
// File: Analytics/Models/IncidentCorrelationSummary.cs
using System;
using System.Collections.Generic;

namespace Carthago.Analytics.Models
{
    public sealed class IncidentCorrelationSummary
    {
        public string IncidentId { get; set; } = string.Empty;
        public string StoryType { get; set; } = "None";
        public double StrengthScore { get; set; }
        public double ConfidenceScore { get; set; }
        public int RelatedEventCount { get; set; }
        public int RelatedRuleCount { get; set; }
        public int RelatedEntityCount { get; set; }
        public int ReasonCount { get; set; }
        public IReadOnlyList<string> TopReasons { get; set; } = Array.Empty<string>();
        public IReadOnlyList<string> ImportantEntities { get; set; } = Array.Empty<string>();
    }
}
