using Carthago.Capture;
using Carthago.Services.Monitoring;

namespace Carthago.Tests;

public sealed class CaptureSessionCoordinatorTests
{
    [Fact]
    public async Task StartAsync_ReportsRunning_OnlyAfterBackendConfirmsStartup()
    {
        var now = new DateTime(2026, 10, 23, 9, 0, 0, DateTimeKind.Utc);
        var lifecycle = new MonitorLifecycle(TimeSpan.FromSeconds(5));
        var source = new ControllableCaptureSource();
        var coordinator = new CaptureSessionCoordinator(lifecycle, () => now);

        var start = coordinator.StartAsync(source, "test-source", "Test source");

        Assert.Equal(MonitorState.Starting, lifecycle.Current.State);

        source.ConfirmStarted();
        await start;

        Assert.Equal(MonitorState.Running, lifecycle.Current.State);
        Assert.True(source.IsRunning);
    }

    [Fact]
    public async Task StartAsync_WhenBackendFails_ReportsFailureAndReleasesSource()
    {
        var now = new DateTime(2026, 10, 23, 9, 5, 0, DateTimeKind.Utc);
        var lifecycle = new MonitorLifecycle(TimeSpan.FromSeconds(5));
        var source = new ControllableCaptureSource();
        var coordinator = new CaptureSessionCoordinator(lifecycle, () => now);

        var start = coordinator.StartAsync(source, "failing-source", "Failing source");
        source.FailStart(new InvalidOperationException("Capture backend could not initialize."));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => start);

        Assert.Equal("Capture backend could not initialize.", error.Message);
        Assert.Equal(MonitorState.Failed, lifecycle.Current.State);
        Assert.Equal(error.Message, lifecycle.Current.LastError);
        Assert.Equal(1, source.StopCount);
        Assert.Equal(1, source.DisposeCount);
    }

    [Fact]
    public async Task StopAsync_TransitionsThroughStoppingAndReleasesRunningSource()
    {
        var now = new DateTime(2026, 10, 23, 9, 10, 0, DateTimeKind.Utc);
        var lifecycle = new MonitorLifecycle(TimeSpan.FromSeconds(5));
        var source = new ControllableCaptureSource();
        var coordinator = new CaptureSessionCoordinator(lifecycle, () => now);

        var start = coordinator.StartAsync(source, "test-source", "Test source");
        source.ConfirmStarted();
        await start;

        now = now.AddMinutes(1);
        await coordinator.StopAsync();

        Assert.Equal(MonitorState.Stopped, lifecycle.Current.State);
        Assert.Equal(now, lifecycle.Current.StateChangedUtc);
        Assert.Equal(1, source.StopCount);
        Assert.Equal(1, source.DisposeCount);

        await coordinator.DisposeAsync();
        Assert.Equal(1, source.StopCount);
        Assert.Equal(1, source.DisposeCount);
    }

    [Fact]
    public async Task BackendFaultAfterStartup_ImmediatelyReportsFailedState()
    {
        var now = new DateTime(2026, 10, 23, 9, 20, 0, DateTimeKind.Utc);
        var lifecycle = new MonitorLifecycle(TimeSpan.FromSeconds(5));
        var source = new ControllableCaptureSource();
        var coordinator = new CaptureSessionCoordinator(lifecycle, () => now);

        var start = coordinator.StartAsync(source, "test-source", "Test source");
        source.ConfirmStarted();
        await start;

        now = now.AddSeconds(10);
        source.FailCapture(new InvalidOperationException("Capture session ended unexpectedly."));

        Assert.Equal(MonitorState.Failed, lifecycle.Current.State);
        Assert.Equal("Capture session ended unexpectedly.", lifecycle.Current.LastError);
        Assert.Equal(now, lifecycle.Current.StateChangedUtc);

        await coordinator.StopAsync();
    }

    private sealed class ControllableCaptureSource : ICaptureSource
    {
        private readonly TaskCompletionSource _started = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public string Name => "Controllable capture";
        public bool IsRunning { get; private set; }
        public int StopCount { get; private set; }
        public int DisposeCount { get; private set; }
        public event Action<Exception>? CaptureFaulted;

        public Task StartAsync() => _started.Task;

        public Task StopAsync()
        {
            StopCount++;
            IsRunning = false;
            return Task.CompletedTask;
        }

        public void ConfirmStarted()
        {
            IsRunning = true;
            _started.TrySetResult();
        }

        public void FailStart(Exception exception) => _started.TrySetException(exception);

        public void FailCapture(Exception exception) => CaptureFaulted?.Invoke(exception);

        public void Dispose()
        {
            DisposeCount++;
        }
    }
}
