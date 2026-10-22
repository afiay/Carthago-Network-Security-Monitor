// SPDX-License-Identifier: MIT
// File: Services/Journaling/DetectionOutboxWriteResult.cs
using System;

namespace Carthago.Services
{
    public sealed record DetectionOutboxWriteResult(
        bool Succeeded,
        string? OutboxPath,
        DateTime? WrittenAtUtc,
        string? ErrorMessage)
    {
        public static DetectionOutboxWriteResult Success(string path, DateTime writtenAtUtc) =>
            new(true, path, writtenAtUtc, null);

        public static DetectionOutboxWriteResult Failure(string error, string? path = null) =>
            new(false, path, null, error);
    }
}
