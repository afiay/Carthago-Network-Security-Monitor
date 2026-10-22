// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackUpgradeResult.cs
using System.Collections.Generic;

namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackUpgradeResult
    {
        public bool Succeeded => Errors.Count == 0;
        public string PackId { get; set; } = string.Empty;
        public ContentPackUpgradePlan Plan { get; set; } = new();
        public InstalledContentPackState? InstalledPack { get; set; }
        public List<string> Errors { get; set; } = new();
        public List<string> Warnings { get; set; } = new();
    }
}
