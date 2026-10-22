// SPDX-License-Identifier: MIT
// File: Services/Journaling/DetectionJournalOptions.cs
using System;
using System.IO;

namespace Carthago.Services
{
    public sealed class DetectionJournalOptions
    {
        public string DirectoryPath { get; init; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Carthago", "detections");
        public bool FlushAfterEveryWrite { get; init; } = true;
        public bool CreateDirectoryIfMissing { get; init; } = true;
    }
}
