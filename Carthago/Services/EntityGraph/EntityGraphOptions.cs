// SPDX-License-Identifier: MIT
// File: Services/EntityGraph/EntityGraphOptions.cs
using System;
using System.IO;

namespace Carthago.Services.EntityGraph
{
    public sealed class EntityGraphOptions
    {
        public string DirectoryPath { get; set; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Carthago", "entity-graph");

        public string FileName { get; set; } = "entity-graph.json";
        public bool FlushAfterEveryWrite { get; set; } = true;
    }
}
