// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Health;

namespace Carthago.Services;

// Measures local runtime reach among rules in alert mode, not detection accuracy,
// qualified positive/negative tests, or whole-fleet coverage.
internal readonly record struct DetectionCoverageKpiSnapshot(string Value, string Caption);

internal static class DetectionCoverageKpiProjection
{
    internal static DetectionCoverageKpiSnapshot FromSnapshots(IReadOnlyList<RuleHealthSnapshot> snapshots)
    {
        ArgumentNullException.ThrowIfNull(snapshots);
        return FromCounts(
            snapshots.Count,
            snapshots.Count(s => s.CurrentMode == RuleMode.Alert),
            snapshots.Count(s => s.CurrentMode == RuleMode.Alert && s.RuntimeStats.Evaluations > 0),
            snapshots.Count(s => s.HasValidationErrors));
    }

    internal static DetectionCoverageKpiSnapshot FromCounts(int registered, int alertMode,
        int evaluatedInProcess, int catalogErrors)
    {
        if (registered < 0 || alertMode < 0 || evaluatedInProcess < 0 || catalogErrors < 0 ||
            alertMode > registered || evaluatedInProcess > alertMode || catalogErrors > registered)
            throw new ArgumentOutOfRangeException(nameof(registered), "Invalid detection coverage counters.");

        if (registered == 0)
            return new DetectionCoverageKpiSnapshot("—", "No rule catalog loaded · coverage unknown");

        if (alertMode == 0)
        {
            var noDenominator = $"No alert-mode rules · {registered} registered";
            if (catalogErrors > 0)
                noDenominator += $" · {catalogErrors} catalog errors";
            return new DetectionCoverageKpiSnapshot("—", noDenominator);
        }

        var value = evaluatedInProcess.ToString(CultureInfo.InvariantCulture) + "/" +
                    alertMode.ToString(CultureInfo.InvariantCulture);
        var caption = $"Alert-mode rules evaluated in process · {registered} registered";
        if (catalogErrors > 0)
            caption += $" · {catalogErrors} catalog errors";
        return new DetectionCoverageKpiSnapshot(value, caption);
    }

    internal static DetectionCoverageKpiSnapshot Unavailable()
        => new("—", "Runtime coverage unavailable · no inferred zero");
}
