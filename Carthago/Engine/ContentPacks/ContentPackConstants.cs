// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackConstants.cs
using System;
using System.Collections.Generic;
using System.IO;

namespace Carthago.Engine.ContentPacks
{
    public static class ContentPackConstants
    {
        public static readonly Version CurrentCarthagoVersion = new(1, 0, 0);

        public static string DefaultRootDirectory => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Carthago",
            "content-packs");

        public static IReadOnlyCollection<string> ImmutableOverrideFields { get; } = new[]
        {
            "RuleId",
            "EventId",
            "JournalPath",
            "PersistedAtUtc"
        };

        public static IReadOnlyCollection<string> DangerousInstallOperationKeywords { get; } = new[]
        {
            "delete",
            "purge",
            "erase",
            "wipe",
            "drop",
            "truncate"
        };
    }
}
