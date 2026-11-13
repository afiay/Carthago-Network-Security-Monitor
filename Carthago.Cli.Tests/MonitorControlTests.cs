// SPDX-License-Identifier: MIT
using Carthago.Contracts;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class MonitorControlTests
{
    private static MonitorControlRequest Request(MonitorControlKind kind, Guid? session = null)
        => new(MonitorControlProtocol.Version, Guid.NewGuid(), kind, session);

    [Fact]
    public void StopDisabledByDefault()
    {
        int calls = 0;
        var session = new MonitorControlSession(false, () => calls++);
        var request = Request(MonitorControlKind.Stop, session.SessionId);
        var response = session.Query(request);
        Assert.Equal(MonitorControlOutcome.StopDisabled, response.Outcome);
        session.CommitStop(request, response);
        Assert.Equal(0, calls);
    }

    [Fact]
    public void AcceptanceDoesNotCancelUntilCommittedAndOnlyOnce()
    {
        int calls = 0;
        var session = new MonitorControlSession(true, () => calls++);
        session.MarkStarted();
        var q = Request(MonitorControlKind.Stop, session.SessionId);
        var r = session.Query(q);
        Assert.Equal(MonitorControlOutcome.StopAccepted, r.Outcome);
        Assert.Equal(0, calls);
        session.CommitStop(q, r);
        session.CommitStop(q, r);
        Assert.Equal(1, calls);
        Assert.Equal(MonitorControlOutcome.AlreadyStopping, session.Query(q).Outcome);
        Assert.Equal(MonitorControlState.Stopping, session.Query(Request(MonitorControlKind.Status)).State);
    }

    [Fact]
    public void StaleSessionDoesNotStopReplacement()
    {
        int calls = 0;
        var session = new MonitorControlSession(true, () => calls++);
        var q = Request(MonitorControlKind.Stop, Guid.NewGuid());
        var r = session.Query(q);
        Assert.Equal(MonitorControlOutcome.SessionMismatch, r.Outcome);
        session.CommitStop(q, r);
        Assert.Equal(0, calls);
    }

    [Fact]
    public void CountersUnavailableBeforeSampleAndPreservedDuringStop()
    {
        var session = new MonitorControlSession(true, () => { });
        var q = Request(MonitorControlKind.Status);
        Assert.Null(session.Query(q).Counters);
        session.MarkStarted();
        session.Publish(new(10, 8, 2, 3));
        var r = session.Query(q);
        MonitorControlProtocol.ValidateResponse(r, q);
        Assert.Equal(10, r.Counters!.Captured);
        Assert.NotNull(r.SampledUtc);
        session.MarkStopping();
        session.Publish(new(99, 99, 0, 99));
        Assert.Equal(10, session.Query(q).Counters!.Captured);
    }

    [Fact]
    public void ProtocolRejectsWrongCorrelationAndImpossibleAcceptance()
    {
        var session = new MonitorControlSession(true, () => { });
        var q = Request(MonitorControlKind.Stop, session.SessionId);
        var r = session.Query(q);
        Assert.Throws<InvalidDataException>(() => MonitorControlProtocol.ValidateResponse(r with { Correlation = Guid.NewGuid() }, q));
        Assert.Throws<InvalidDataException>(() => MonitorControlProtocol.ValidateResponse(r with { StopAllowed = false }, q));
        Assert.Throws<InvalidDataException>(() => MonitorControlProtocol.ValidateRequest(Request(MonitorControlKind.Stop)));
        Assert.Throws<InvalidDataException>(() => MonitorControlProtocol.ValidateRequest(Request(MonitorControlKind.Status, session.SessionId)));
    }

    [Fact]
    public void StopOptInRequiresIpc()
    {
        Assert.False(ForegroundMonitor.TryParse(new[] { "monitor", "start", "--interface", "id", "--allow-cli-stop" }, out _));
        Assert.True(ForegroundMonitor.TryParse(new[] { "monitor", "start", "--interface", "id", "--enable-cli-ipc" }, out var read));
        Assert.True(read!.EnableCliIpc);
        Assert.False(read.AllowCliStop);
        Assert.True(ForegroundMonitor.TryParse(new[] { "monitor", "start", "--interface", "id", "--enable-cli-ipc", "--allow-cli-stop" }, out var control));
        Assert.True(control!.AllowCliStop);
    }

    [Fact]
    public async Task CliStopTargetsResolvedSessionAndDoesNotClaimShutdown()
    {
        var session = new MonitorControlSession(true, () => { });
        var requests = new List<MonitorControlRequest>();
        using var output = new StringWriter();
        using var error = new StringWriter();
        int code = await CliApplication.RunAsync(new[] { "monitor", "stop", "--json" }, output, error,
            monitorQuery: (q, _) => { requests.Add(q); return Task.FromResult(session.Query(q)); });
        Assert.Equal(0, code);
        Assert.Equal(2, requests.Count);
        Assert.Equal(MonitorControlKind.Status, requests[0].Kind);
        Assert.Equal(session.SessionId, requests[1].SessionId);
        Assert.Contains("stop_requested", output.ToString());
        Assert.DoesNotContain("shutdown_confirmed", output.ToString());
        Assert.Empty(error.ToString());
    }

    [Fact]
    public async Task CliDeniedStopUsesStderr()
    {
        var session = new MonitorControlSession(false, () => { });
        using var output = new StringWriter();
        using var error = new StringWriter();
        int code = await CliApplication.RunAsync(new[] { "monitor", "stop", "--json" }, output, error,
            monitorQuery: (q, _) => Task.FromResult(session.Query(q)));
        Assert.Equal(3, code);
        Assert.Empty(output.ToString());
        Assert.Contains("stopdisabled", error.ToString());
    }

    [Fact]
    public async Task WindowsPipeStopRequiresAcknowledgment()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var stopped = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var session = new MonitorControlSession(true, () => stopped.TrySetResult(true));
        string name = "Carthago.Test.V4." + Guid.NewGuid().ToString("N");
        var server = WindowsLocalReadPipe.ServeMonitorAsync(session, cts.Token, name);
        try
        {
            // Send a valid stop, read acceptance, then disconnect without ACK.
            using (var raw = new System.IO.Pipes.NamedPipeClientStream(".", name,
                System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.Asynchronous))
            {
                await raw.ConnectAsync(cts.Token);
                await LiveQueryProtocol.WriteAsync(raw, Request(MonitorControlKind.Stop, session.SessionId),
                    LiveQueryProtocol.MaxRequestBytes, cts.Token);
                var response = await LiveQueryProtocol.ReadAsync<MonitorControlResponse>(raw,
                    LiveQueryProtocol.MaxResponseBytes, cts.Token);
                Assert.Equal(MonitorControlOutcome.StopAccepted, response.Outcome);
            }
            var status = await WindowsLocalReadPipe.QueryMonitorAsync(Request(MonitorControlKind.Status), cts.Token, name);
            Assert.Equal(MonitorControlState.Starting, status.State);
            Assert.False(stopped.Task.IsCompleted);
            var accepted = await WindowsLocalReadPipe.QueryMonitorAsync(Request(MonitorControlKind.Stop, session.SessionId), cts.Token, name);
            Assert.Equal(MonitorControlOutcome.StopAccepted, accepted.Outcome);
            await stopped.Task.WaitAsync(cts.Token);
        }
        finally
        {
            cts.Cancel();
            try { await server; } catch (OperationCanceledException) when (cts.IsCancellationRequested) { }
        }
    }
}
