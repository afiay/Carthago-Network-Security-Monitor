// SPDX-License-Identifier: MIT
using Carthago.Contracts;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class ForegroundMonitorTests
{
    [Fact]
    public void ExplicitInterfaceAndFilterParsed()
    {
        Assert.True(ForegroundMonitor.TryParse(new[] { "monitor", "start", "--interface", "npf-id",
            "--filter", "tcp port 443", "--status-seconds", "2", "--json" }, out var opts));
        Assert.Equal("npf-id", opts!.InterfaceId);
        Assert.Equal("tcp port 443", opts.Filter);
        Assert.Equal(2, opts.StatusSeconds);
        Assert.True(opts.Json);
    }

    [Theory]
    [InlineData("monitor start --json")]
    [InlineData("monitor start --interface a --interface b")]
    [InlineData("monitor start --interface a --status-seconds 0")]
    [InlineData("monitor start --interface a --status-seconds 61")]
    [InlineData("monitor start --interface a --unknown x")]
    public void InvalidArgumentsRejected(string input)
        => Assert.False(ForegroundMonitor.TryParse(input.Split(' '), out _));

    [Fact]
    public async Task CancellationStopsAndDisposesActualAdapterBoundary()
    {
        var capture = new Fake();
        using var cts = new CancellationTokenSource();
        using var output = new StringWriter();
        using var error = new StringWriter();
        int code = await ForegroundMonitor.RunAsync(capture, new("id", "tcp", 1, true), output, error, cts.Token,
            (_, _) => { cts.Cancel(); return Task.CompletedTask; });
        Assert.Equal(130, code);
        Assert.Equal("id", capture.Id);
        Assert.True(capture.Disposed);
        Assert.Contains("started_no_packets_observed", output.ToString());
        Assert.Contains("not_assessed", output.ToString());
    }

    [Fact]
    public async Task FailedStartupNeverReportsRunning()
    {
        var capture = new Fake { Fail = true };
        using var output = new StringWriter();
        using var error = new StringWriter();
        int code = await ForegroundMonitor.RunAsync(capture, new("id", null, 1, true), output, error, default);
        Assert.Equal(3, code);
        Assert.True(capture.Disposed);
        Assert.Empty(output.ToString());
    }

    [Fact]
    public async Task ShutdownFailureIsNotReportedAsSuccess()
    {
        var capture = new Fake { FailDispose = true };
        using var cts = new CancellationTokenSource();
        using var output = new StringWriter();
        using var error = new StringWriter();
        int code = await ForegroundMonitor.RunAsync(capture, new("id", null, 1, false), output, error, cts.Token,
            (_, _) => { cts.Cancel(); return Task.CompletedTask; });
        Assert.Equal(3, code);
        Assert.Contains("shutdown did not complete", error.ToString());
    }

    private sealed class Fake : IForegroundCapture
    {
        public bool Fail, FailDispose, Disposed;
        public string? Id;
        public bool CaptureRequested => Id is not null && !Disposed;
        public void Start(string interfaceId, string? filter)
        {
            if (Fail) throw new InvalidOperationException();
            Id = interfaceId;
        }
        public ForegroundMonitorCounters ReadCounters() => new(0, 0, 0, 0);
        public ValueTask DisposeAsync()
        {
            Disposed = true;
            if (FailDispose) throw new InvalidOperationException();
            return ValueTask.CompletedTask;
        }
    }
}
