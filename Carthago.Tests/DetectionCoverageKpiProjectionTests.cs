// SPDX-License-Identifier: MIT
using System;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public sealed class DetectionCoverageKpiProjectionTests
{
    [Fact]
    public void RatioRepresentsEvaluatedAlertModeRulesInThisProcess()
    {
        var sample = DetectionCoverageKpiProjection.FromCounts(1000, 850, 220, 3);
        Assert.Equal("220/850", sample.Value);
        Assert.Contains("1000 registered", sample.Caption);
        Assert.Contains("3 catalog errors", sample.Caption);
        Assert.Contains("in process", sample.Caption);
    }

    [Fact]
    public void ZeroEvaluatedIsRealWhenCatalogWasRead()
        => Assert.Equal("0/20", DetectionCoverageKpiProjection.FromCounts(25, 20, 0, 0).Value);

    [Fact]
    public void EmptyCatalogDoesNotInventCoverage()
        => Assert.Equal("—", DetectionCoverageKpiProjection.FromCounts(0, 0, 0, 0).Value);

    [Fact]
    public void FailureIsUnavailableNotZero()
        => Assert.Equal("—", DetectionCoverageKpiProjection.Unavailable().Value);

    [Fact]
    public void InvalidInputsAreRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => DetectionCoverageKpiProjection.FromCounts(5, 6, 0, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => DetectionCoverageKpiProjection.FromCounts(5, 2, 3, 0));
    }
}
