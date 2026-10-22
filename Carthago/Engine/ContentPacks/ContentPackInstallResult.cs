// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackInstallResult.cs
using System.Collections.Generic;

namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackInstallResult
    {
        public bool Succeeded => Errors.Count == 0;
        public string PackId { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public ContentPackInstallPlan Plan { get; set; } = new();
        public InstalledContentPackState? InstalledPack { get; set; }
        public List<string> Errors { get; set; } = new();
        public List<string> Warnings { get; set; } = new();
    }
}
