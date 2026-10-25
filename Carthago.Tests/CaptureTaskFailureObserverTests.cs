using Carthago.Services;

namespace Carthago.Tests;

public sealed class CaptureTaskFailureObserverTests
{
    [Fact]
    public async Task Observe_ReportsBackgroundCaptureFailure()
    {
        var capture = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var notified = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);

        CaptureTaskFailureObserver.Observe(capture.Task, error => notified.TrySetResult(error));
        capture.SetException(new InvalidOperationException("ETW capture failed"));

        var observed = await notified.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.IsType<InvalidOperationException>(observed);
        Assert.Equal("ETW capture failed", observed.Message);
    }
}
