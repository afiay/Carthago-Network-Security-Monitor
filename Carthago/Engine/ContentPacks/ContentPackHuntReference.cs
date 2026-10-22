// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackHuntReference.cs
namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackHuntReference
    {
        public string HuntId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string PrimaryRuleId { get; set; } = string.Empty;
        public double? MinConfidence { get; set; }
    }
}
