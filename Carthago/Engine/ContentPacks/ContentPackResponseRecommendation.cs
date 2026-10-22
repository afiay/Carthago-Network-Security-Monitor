// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackResponseRecommendation.cs
using System.Collections.Generic;
using Carthago.Services.Response;

namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackResponseRecommendation
    {
        public string RecommendationId { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public ResponseActionType ActionType { get; set; } = ResponseActionType.MarkForReview;
        public ResponseActionSafety Safety { get; set; } = ResponseActionSafety.RecommendationOnly;
        public bool Automatic { get; set; }
        public bool RequiresApproval { get; set; } = true;
        public string SafetyWarning { get; set; } = string.Empty;
        public List<string> AppliesToRuleIds { get; set; } = new();
        public List<string> Steps { get; set; } = new();
    }
}
