// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackRuleSource.cs
namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackRuleSource
    {
        public string Kind { get; set; } = "CoreRuleAlias";
        public string CoreRuleId { get; set; } = string.Empty;
        public string? Notes { get; set; }
    }
}
