using System;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public class CaptureFlowHealthTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 25, 14, 0, 0, TimeSpan.Zero);

    [Fact]
    public void CapturedTrafficWithQueueDropsReportsLossWithoutCallingCaptureStalled()
    {
        var assessment = CaptureFlowHealth.Assess(true, Now.AddSeconds(-30), 100, 90, 10,
            Now.AddSeconds(-1), Now.AddSeconds(-1), Now);

        Assert.Equal(CaptureFlowState.Flowing, assessment.State);
        Assert.Equal("UI_QUEUE_DROPS", assessment.Reason);
    }

    [Fact]
    public void MissingUiDeliveryIdentifiesStalledPipeline()
    {
        var assessment = CaptureFlowHealth.Assess(true, Now.AddSeconds(-30), 20, 0, 0,
            Now.AddSeconds(-1), null, Now);

        Assert.Equal(CaptureFlowState.Stalled, assessment.State);
        Assert.Equal("UI_DELIVERY_STALLED", assessment.Reason);
    }

    [Fact]
    public void QuietNetworkDoesNotReportUiStall()
    {
        var assessment = CaptureFlowHealth.Assess(true, Now.AddSeconds(-30), 0, 0, 0,
            null, null, Now);

        Assert.Equal(CaptureFlowState.Idle, assessment.State);
        Assert.Equal("WAITING_FOR_TRAFFIC", assessment.Reason);
    }

    [Fact]
    public void NoObservedEventsAreIdleNotStalled()
    {
        var result = CaptureFlowHealth.Evaluate(true, Now.AddSeconds(-30), 0, 0, null, null, Now);
        Assert.Equal(CaptureFlowState.Idle, result);
    }

    [Fact]
    public void RecentCaptureWithNoUiDeliveryIsStalledAfterGrace()
    {
        var result = CaptureFlowHealth.Evaluate(true, Now.AddSeconds(-30), 42, 0,
            Now.AddSeconds(-2), null, Now);
        Assert.Equal(CaptureFlowState.Stalled, result);
    }

    [Fact]
    public void RecentDeliveryIsFlowing()
    {
        var result = CaptureFlowHealth.Evaluate(true, Now.AddSeconds(-30), 42, 40,
            Now.AddSeconds(-2), Now.AddSeconds(-1), Now);
        Assert.Equal(CaptureFlowState.Flowing, result);
    }

    [Fact]
    public void CaptureWithoutEventsDuringInitialGraceIsStarting()
    {
        var result = CaptureFlowHealth.Evaluate(true, Now.AddSeconds(-2), 0, 0, null, null, Now);
        Assert.Equal(CaptureFlowState.Starting, result);
    }

    [Fact]
    public void RecentCaptureAfterEarlierDeliveryIsNotImmediatelyStalled()
    {
        var result = CaptureFlowHealth.Evaluate(true, Now.AddSeconds(-30), 43, 40,
            Now.AddSeconds(-1), Now.AddSeconds(-5), Now);
        Assert.Equal(CaptureFlowState.Flowing, result);
    }
}
