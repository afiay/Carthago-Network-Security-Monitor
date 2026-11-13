// SPDX-License-Identifier: MIT
using System;
using System.Linq;

namespace Carthago.Services;

internal static class AssetHistoryCoveragePresentation
{
    internal static string Describe(AssetHistorySnapshot history)
    {
        var coverage = history.Coverage ?? Array.Empty<CheckpointCoverage>();
        var communicationSessions = (history.Communications ?? Array.Empty<CommunicationHistoryRow>())
            .Select(r => r.SessionId).Distinct().Count();
        int capable = coverage.Count;
        int legacy = Math.Max(0, history.SessionCount - capable);
        string Capacity(string label, Func<CheckpointCoverage, long?> select)
        {
            int unknown = coverage.Count(c => select(c) is null);
            int zero = coverage.Count(c => select(c) == 0);
            int rejected = coverage.Count(c => select(c) > 0);
            return $"{label} capacity (communication-capable sessions): {zero} zero rejections, {rejected} with rejections, {unknown} unknown.";
        }
        return $"Retained coverage: {legacy} legacy asset-only, {capable} communication-capable, " +
            $"{communicationSessions} with destination rows. " +
            Capacity("Destination", c => c.DestinationRejected) + " " +
            Capacity("Asset", c => c.AssetRejected) + " " +
            "These are retained-file counts, not eligible comparison sessions. Zero capacity rejections do not establish complete capture." +
            (history.Error is null ? "" : " Some history could not be read.");
    }
}
