using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public class UiRefreshCoalescerTests
{
    [Fact]
    public void BurstyUpdatesScheduleOnePendingRefresh()
    {
        var gate = new UiRefreshCoalescer();
        Assert.True(gate.Request());
        Assert.False(gate.Request());
        Assert.False(gate.Request());
        Assert.Equal(3, gate.Version);
        Assert.False(gate.Complete(3));
        Assert.True(gate.Request());
    }

    [Fact]
    public void UpdateDuringRefreshSchedulesOneFollowup()
    {
        var gate = new UiRefreshCoalescer();
        Assert.True(gate.Request());
        var inProgress = gate.Version;
        Assert.False(gate.Request());
        Assert.True(gate.Complete(inProgress));
        Assert.False(gate.Request());
        Assert.False(gate.Complete(gate.Version));
    }
}
