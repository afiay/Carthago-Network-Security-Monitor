using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public class UiOperationTimingCounterTests
{
    [Fact]
    public void RecordsCountTotalAndMaximumIndependently()
    {
        var counter = new UiOperationTimingCounter();
        counter.RecordMilliseconds(4);
        counter.RecordMilliseconds(11);
        counter.RecordMilliseconds(2);
        var snapshot = counter.Snapshot();
        Assert.Equal(3, snapshot.Count);
        Assert.Equal(17, snapshot.TotalMilliseconds);
        Assert.Equal(11, snapshot.MaxMilliseconds);
    }
}
