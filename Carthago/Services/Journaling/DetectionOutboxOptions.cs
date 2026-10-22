// SPDX-License-Identifier: MIT
// File: Services/Journaling/DetectionOutboxOptions.cs
using System;
using System.IO;

namespace Carthago.Services
{
    public sealed class DetectionOutboxOptions
    {
        public string DirectoryPath { get; init; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Carthago",
            "detections",
            "outbox");

        public bool FlushAfterEveryWrite { get; init; } = true;
        public bool CreateDirectoryIfMissing { get; init; } = true;
    }
}
