// SPDX-License-Identifier: MIT
using System;
using System.Globalization;

namespace Carthago.Services.Sensors;

// Presentation-only projection: neither saved profiles nor a single in-flight
// probe establish machine-wide active sensor health.
internal readonly record struct ActiveSensorKpiSnapshot(string Value, string Caption);

internal static class ActiveSensorKpiProjection
{
    internal static ActiveSensorKpiSnapshot FromGuiScheduler(int approved, int blocked)
    {
        if (approved < 0 || blocked < 0 || blocked > approved)
            throw new ArgumentOutOfRangeException(nameof(blocked), "Invalid scheduler snapshot.");

        var scheduled = approved - blocked;
        var caption = blocked == 0
            ? $"GUI scheduler · {scheduled} scheduled"
            : $"GUI scheduler · {scheduled} scheduled · {blocked} blocked";
        return new ActiveSensorKpiSnapshot(scheduled.ToString(CultureInfo.InvariantCulture), caption);
    }

    internal static ActiveSensorKpiSnapshot FromStoredProfiles(int saved, string? error)
    {
        if (!string.IsNullOrWhiteSpace(error) || saved < 0)
            return new ActiveSensorKpiSnapshot("—", "Sensor inventory unavailable · live count unknown");

        // Saved profiles may be unapproved, expired or running in another process.
        // An unobserved runtime must not be reported as zero or as saved.Count.
        return new ActiveSensorKpiSnapshot("—",
            $"{saved.ToString(CultureInfo.InvariantCulture)} saved · live count unverified");
    }
}
