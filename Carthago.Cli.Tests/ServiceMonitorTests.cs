// SPDX-License-Identifier: MIT
using System.Text;
using Carthago.Contracts;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class ServiceMonitorTests
{
    [Fact]
    public void ValidConfigDoesNotEnableIpc()
    {
        var options = MonitorServiceConfiguration.Parse(Encoding.UTF8.GetBytes(
            """{"schemaVersion":1,"interfaceId":"npf-id","filter":"tcp port 443","statusSeconds":10}"""));
        Assert.Equal("npf-id", options.InterfaceId);
        Assert.Equal("tcp port 443", options.Filter);
        Assert.Equal(10, options.StatusSeconds);
        Assert.False(options.EnableCliIpc);
        Assert.False(options.AllowCliStop);
    }

    [Theory]
    [InlineData("""{"schemaVersion":2,"interfaceId":"id"}""")]
    [InlineData("""{"schemaVersion":1,"interfaceId":"id","interfaceId":"other"}""")]
    [InlineData("""{"schemaVersion":1,"interfaceId":"id","allowCliStop":true}""")]
    [InlineData("""{"schemaVersion":1,"interfaceId":"id","statusSeconds":0}""")]
    [InlineData("""{"schemaVersion":1,"interfaceId":"--bad"}""")]
    [InlineData("""{"schemaVersion":1,"interfaceId":"id","filter":""}""")]
    [InlineData("""{"schemaVersion":1}""")]
    public void InvalidConfigRejected(string json)
        => Assert.Throws<InvalidDataException>(() => MonitorServiceConfiguration.Parse(Encoding.UTF8.GetBytes(json)));

    [Fact]
    public void ConfigRejectsRelativePathAndOversizedData()
    {
        Assert.Throws<InvalidDataException>(() => MonitorServiceConfiguration.Load("relative.json"));
        Assert.Throws<InvalidDataException>(() => MonitorServiceConfiguration.Parse(new byte[MonitorServiceConfiguration.MaxBytes + 1]));
    }

    [Fact]
    public async Task StartupWaitsForFactoryAndStopDisposesAdapter()
    {
        var gate = new TaskCompletionSource<IForegroundCapture>(TaskCreationOptions.RunContinuationsAsynchronously);
        var adapter = new Fake();
        using var run = new ServiceMonitorRun(new("id", null, 1, false), _ => gate.Task, TextWriter.Null);
        Assert.False(run.Started.IsCompleted);
        gate.SetResult(adapter);
        await run.Started.WaitAsync(TimeSpan.FromSeconds(5));
        run.RequestStop();
        Assert.Equal(130, await run.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.True(adapter.Disposed);
    }

    [Fact]
    public async Task FailedStartDoesNotSignalReady()
    {
        var adapter = new Fake { FailStart = true };
        using var run = new ServiceMonitorRun(new("id", null, 1, false), _ => Task.FromResult<IForegroundCapture>(adapter), TextWriter.Null);
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.Started);
        Assert.Equal(3, await run.Completion);
        Assert.True(adapter.Disposed);
    }

    [Fact]
    public async Task UnconfirmedStartFailsClosed()
    {
        var adapter = new Fake { Confirm = false };
        using var run = new ServiceMonitorRun(new("id", null, 1, false), _ => Task.FromResult<IForegroundCapture>(adapter), TextWriter.Null);
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.Started);
        Assert.Equal(3, await run.Completion);
        Assert.True(adapter.Disposed);
    }

    [Fact]
    public void ServiceCannotEnableForegroundControl()
        => Assert.Throws<ArgumentException>(() => new ServiceMonitorRun(new("id", null, 1, false, true, true),
            _ => Task.FromResult<IForegroundCapture>(new Fake()), TextWriter.Null));

    [Fact]
    public async Task StartupWaitsForFirstHealthPublication()
    {
        var adapter = new Fake();
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var run = new ServiceMonitorRun(new("id", null, 1, false),
            _ => Task.FromResult<IForegroundCapture>(adapter), TextWriter.Null,
            sample: _ =>
            {
                entered.TrySetResult(true);
                release.Task.WaitAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
            });
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(run.Started.IsCompleted);
            Assert.True(adapter.CaptureRequested);
            release.TrySetResult(true);
            await run.Started.WaitAsync(TimeSpan.FromSeconds(5));
        }
        finally
        {
            release.TrySetResult(true);
            run.RequestStop();
            Assert.Equal(130, await run.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
        }
        Assert.True(adapter.Disposed);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task FirstHealthFailureNeverSignalsReady(bool failRead)
    {
        var adapter = new Fake { FailRead = failRead };
        using var run = new ServiceMonitorRun(new("id", null, 1, false),
            _ => Task.FromResult<IForegroundCapture>(adapter), TextWriter.Null,
            sample: _ => { if (!failRead) throw new IOException("Synthetic publication failure."); });
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.Started.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(3, await run.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.True(adapter.Disposed);
    }

    [Fact]
    public async Task StopDuringFirstPublicationDoesNotSignalReady()
    {
        var adapter = new Fake();
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var run = new ServiceMonitorRun(new("id", null, 1, false),
            _ => Task.FromResult<IForegroundCapture>(adapter), TextWriter.Null,
            sample: _ =>
            {
                entered.TrySetResult(true);
                release.Task.WaitAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
            });
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            run.RequestStop();
        }
        finally
        {
            release.TrySetResult(true);
            run.RequestStop();
            Assert.Equal(130, await run.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
        }
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.Started);
        Assert.True(adapter.Disposed);
    }

    private sealed class Fake : IForegroundCapture
    {
        public bool FailStart, FailRead, Disposed;
        public bool Confirm = true;
        public bool CaptureRequested { get; private set; }
        public void Start(string interfaceId, string? filter)
        {
            if (FailStart) throw new InvalidOperationException();
            CaptureRequested = Confirm;
        }
        public ForegroundMonitorCounters ReadCounters()
        {
            if (FailRead) throw new InvalidOperationException("Synthetic counter read failure.");
            return new(0, 0, 0, 0);
        }
        public ValueTask DisposeAsync() { Disposed = true; CaptureRequested = false; return ValueTask.CompletedTask; }
    }
}
