// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackDashboardPreset.cs
using System.Collections.Generic;

namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackDashboardPreset
    {
        public string PresetId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string? ProfileName { get; set; }
        public Dictionary<string, string> Filters { get; set; } = new(System.StringComparer.OrdinalIgnoreCase);
    }
}
