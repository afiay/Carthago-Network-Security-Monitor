// SPDX-License-Identifier: MIT
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class ActiveSensorKpiProjectionTests
{
    [Fact]
    public void ZeroGuiSchedulesIsObservedZeroOnlyWithSchedulerOwnership()
    {
        var result = ActiveSensorKpiProjection.FromGuiScheduler(0, 0);
        Assert.Equal("0", result.Value);
        Assert.Contains("GUI scheduler", result.Caption);
        Assert.Contains("0 scheduled", result.Caption);
    }

    [Fact]
    public void CountsScheduledProfilesButNotBlockedProfiles()
    {
        var result = ActiveSensorKpiProjection.FromGuiScheduler(5, 2);
        Assert.Equal("3", result.Value);
        Assert.Contains("3 scheduled", result.Caption);
        Assert.Contains("2 blocked", result.Caption);
    }

    [Fact]
    public void SavedProfilesDoNotImplyLiveSensors()
    {
        var result = ActiveSensorKpiProjection.FromStoredProfiles(7, null);
        Assert.Equal("—", result.Value);
        Assert.Contains("7 saved", result.Caption);
        Assert.Contains("unverified", result.Caption);
    }

    [Fact]
    public void EmptySavedInventoryDoesNotProveNoExternalScheduler()
    {
        var result = ActiveSensorKpiProjection.FromStoredProfiles(0, null);
        Assert.Equal("—", result.Value);
        Assert.Contains("0 saved", result.Caption);
    }

    [Fact]
    public void StorageFailureIsNotConvertedToZero()
    {
        var result = ActiveSensorKpiProjection.FromStoredProfiles(0, "Storage unavailable");
        Assert.Equal("—", result.Value);
        Assert.Contains("unavailable", result.Caption);
        Assert.Contains("unknown", result.Caption);
    }

    [Fact]
    public void InvalidSchedulerCountersFailClosed()
    {
        Assert.Throws<System.ArgumentOutOfRangeException>(() => ActiveSensorKpiProjection.FromGuiScheduler(1, 2));
        Assert.Throws<System.ArgumentOutOfRangeException>(() => ActiveSensorKpiProjection.FromGuiScheduler(-1, 0));
    }
}
