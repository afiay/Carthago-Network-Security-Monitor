// SPDX-License-Identifier: MIT
// File: Services/Journaling/DetectionJournalWriteResult.cs
using System;

namespace Carthago.Services
{
    public sealed record DetectionJournalWriteResult(bool Succeeded, string? JournalPath, DateTime? PersistedAtUtc, string? ErrorMessage)
    {
        public static DetectionJournalWriteResult Success(string path, DateTime persistedAtUtc) => new(true, path, persistedAtUtc, null);
        public static DetectionJournalWriteResult Failure(string error, string? path = null) => new(false, path, null, error);
    }
}
