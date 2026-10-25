using Carthago.Services.Monitoring;

namespace Carthago.Tests;

public sealed class MonitorLifecycleTests
{
    [Fact]
    public void BeginStart_EntersStarting_WithSelectedSourceAndSession()
    {
        var now = new DateTime(2026, 10, 23, 8, 30, 0, DateTimeKind.Utc);
        var lifecycle = new MonitorLifecycle(TimeSpan.FromSeconds(5));

        var status = lifecycle.BeginStart("npcap:{wifi}", "Wi-Fi", now);

        Assert.Equal(MonitorState.Starting, status.State);
        Assert.Equal("npcap:{wifi}", status.SourceId);
        Assert.Equal("Wi-Fi", status.SourceName);
        Assert.NotEqual(Guid.Empty, status.SessionId);
        Assert.Equal(now, status.StateChangedUtc);
        Assert.Equal(now, status.StartRequestedUtc);
        Assert.Null(status.StartedUtc);
        Assert.Null(status.LastError);
    }

    [Fact]
    public void MarkStarted_ThenQuietThreshold_DistinguishesRunningNoTraffic()
    {
        var requested = new DateTime(2026, 10, 23, 8, 30, 0, DateTimeKind.Utc);
        var lifecycle = new MonitorLifecycle(TimeSpan.FromSeconds(5));
        lifecycle.BeginStart("etw", "ETW Kernel Capture", requested);

        var running = lifecycle.MarkStarted(requested.AddSeconds(1));
        var quiet = lifecycle.EvaluateTrafficState(requested.AddSeconds(7));

        Assert.Equal(MonitorState.Running, running.State);
        Assert.Equal(requested.AddSeconds(1), running.StartedUtc);
        Assert.Equal(MonitorState.RunningNoTraffic, quiet.State);
        Assert.Null(quiet.LastObservedPacketUtc);
        Assert.Equal(requested.AddSeconds(7), quiet.StateChangedUtc);
    }

    [Fact]
    public void RecordPacketObserved_LeavesNoTrafficState_AndUpdatesOperationalCounters()
    {
        var requested = new DateTime(2026, 10, 23, 8, 30, 0, DateTimeKind.Utc);
        var lifecycle = new MonitorLifecycle(TimeSpan.FromSeconds(5));
        lifecycle.BeginStart("npcap:{wifi}", "Wi-Fi", requested);
        lifecycle.MarkStarted(requested.AddSeconds(1));
        lifecycle.EvaluateTrafficState(requested.AddSeconds(7));

        var status = lifecycle.RecordPacketObserved(requested.AddSeconds(8));

        Assert.Equal(MonitorState.Running, status.State);
        Assert.Equal(1, status.PacketsReceived);
        Assert.Equal(requested.AddSeconds(8), status.LastObservedPacketUtc);
        Assert.Equal(requested.AddSeconds(8), status.StateChangedUtc);
    }

    [Fact]
    public void MarkFailed_MapsAccessDenied_ToPermissionRequired()
    {
        var now = new DateTime(2026, 10, 23, 8, 30, 0, DateTimeKind.Utc);
        var lifecycle = new MonitorLifecycle(TimeSpan.FromSeconds(5));
        lifecycle.BeginStart("etw", "ETW Kernel Capture", now);

        var status = lifecycle.MarkFailed(
            new UnauthorizedAccessException("Administrator permission is required."),
            now.AddSeconds(1));

        Assert.Equal(MonitorState.PermissionRequired, status.State);
        Assert.Equal(1, status.ErrorsEncountered);
        Assert.Equal("Administrator permission is required.", status.LastError);
        Assert.Equal(now.AddSeconds(1), status.StateChangedUtc);
    }

    [Fact]
    public void PipelineProgress_TracksEachObservableBoundaryIndependently()
    {
        var now = new DateTime(2026, 10, 23, 8, 30, 0, DateTimeKind.Utc);
        var lifecycle = new MonitorLifecycle(TimeSpan.FromSeconds(5));
        lifecycle.BeginStart("npcap:{wifi}", "Wi-Fi", now);
        lifecycle.MarkStarted(now.AddSeconds(1));
        lifecycle.RecordPacketObserved(now.AddSeconds(2));

        lifecycle.RecordPacketDecoded();
        lifecycle.RecordEventPublished();
        lifecycle.RecordEventDisplayed(2);
        var status = lifecycle.RecordEventExcludedByFilter();

        Assert.Equal(1, status.PacketsReceived);
        Assert.Equal(1, status.PacketsDecoded);
        Assert.Equal(1, status.EventsPublished);
        Assert.Equal(2, status.EventsDisplayed);
        Assert.Equal(1, status.EventsExcludedByFilters);
    }

    [Fact]
    public void StopTransitions_ExposeStoppingBeforeStopped()
    {
        var now = new DateTime(2026, 10, 23, 8, 30, 0, DateTimeKind.Utc);
        var lifecycle = new MonitorLifecycle(TimeSpan.FromSeconds(5));
        lifecycle.BeginStart("npcap:{wifi}", "Wi-Fi", now);
        lifecycle.MarkStarted(now.AddSeconds(1));

        var stopping = lifecycle.BeginStop(now.AddSeconds(2));
        var stopped = lifecycle.MarkStopped(now.AddSeconds(3));

        Assert.Equal(MonitorState.Stopping, stopping.State);
        Assert.Equal(MonitorState.Stopped, stopped.State);
        Assert.Equal(now.AddSeconds(3), stopped.StateChangedUtc);
        Assert.Equal(stopping.SessionId, stopped.SessionId);
    }
}
