// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.Diagnostics
{
    /// <summary>
    /// Pure rate comparison for trusted, cumulative parser counters. This does not
    /// authenticate a producer or emit a rule alert; callers must establish counter
    /// ownership, epoch continuity and exclusion of replay/maintenance periods.
    /// </summary>
    internal static class ParserFailureRateWindow
    {
        internal readonly record struct Sample(
            string ParserId, string EpochId, DateTime TimestampUtc,
            long AttemptedRecords, long FailedRecords);

        internal readonly record struct RateComparison(
            long Attempts, long Failures, double FailureRate, double BaselineRate);

        internal static bool TryDetect(
            Sample baselineStart, Sample baselineEnd,
            Sample currentStart, Sample currentEnd,
            long minimumCurrentAttempts, long minimumCurrentFailures,
            double minimumAbsoluteIncrease, double minimumRateMultiplier,
            out RateComparison comparison)
        {
            comparison = default;
            if (minimumCurrentAttempts <= 0 || minimumCurrentFailures <= 0 ||
                !double.IsFinite(minimumAbsoluteIncrease) || minimumAbsoluteIncrease < 0 ||
                !double.IsFinite(minimumRateMultiplier) || minimumRateMultiplier < 1 ||
                !ValidWindow(baselineStart, baselineEnd) ||
                !ValidWindow(currentStart, currentEnd) ||
                !string.Equals(baselineStart.ParserId, currentStart.ParserId, StringComparison.Ordinal) ||
                !string.Equals(baselineStart.EpochId, currentStart.EpochId, StringComparison.Ordinal) ||
                baselineEnd.TimestampUtc > currentStart.TimestampUtc)
                return false;

            long baseAttempts = baselineEnd.AttemptedRecords - baselineStart.AttemptedRecords;
            long baseFailures = baselineEnd.FailedRecords - baselineStart.FailedRecords;
            long attempts = currentEnd.AttemptedRecords - currentStart.AttemptedRecords;
            long failures = currentEnd.FailedRecords - currentStart.FailedRecords;
            if (baseAttempts == 0 || attempts < minimumCurrentAttempts ||
                failures < minimumCurrentFailures)
                return false;

            double baselineRate = (double)baseFailures / baseAttempts;
            double currentRate = (double)failures / attempts;
            if (currentRate - baselineRate < minimumAbsoluteIncrease ||
                currentRate < baselineRate * minimumRateMultiplier)
                return false;

            comparison = new RateComparison(attempts, failures, currentRate, baselineRate);
            return true;
        }

        private static bool ValidWindow(Sample start, Sample end)
            => !string.IsNullOrWhiteSpace(start.ParserId) &&
               !string.IsNullOrWhiteSpace(start.EpochId) &&
               string.Equals(start.ParserId, end.ParserId, StringComparison.Ordinal) &&
               string.Equals(start.EpochId, end.EpochId, StringComparison.Ordinal) &&
               start.TimestampUtc.Kind == DateTimeKind.Utc &&
               end.TimestampUtc.Kind == DateTimeKind.Utc &&
               start.TimestampUtc < end.TimestampUtc &&
               start.AttemptedRecords >= 0 && start.FailedRecords >= 0 &&
               end.AttemptedRecords >= start.AttemptedRecords &&
               end.FailedRecords >= start.FailedRecords &&
               start.FailedRecords <= start.AttemptedRecords &&
               end.FailedRecords <= end.AttemptedRecords &&
               end.FailedRecords - start.FailedRecords <=
                   end.AttemptedRecords - start.AttemptedRecords;
    }
}
