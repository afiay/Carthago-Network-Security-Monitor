// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackRuleRegistration.cs
using System.Text.Json.Serialization;

namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackRuleRegistration
    {
        public string PackId { get; set; } = string.Empty;
        public string PackVersion { get; set; } = string.Empty;
        public ContentPackRule Rule { get; set; } = new();

        [JsonIgnore]
        public IContentPackRule? CompiledRule { get; set; }
    }
}
