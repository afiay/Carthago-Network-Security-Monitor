// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.Text;
using Carthago.Services;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableCaptureRunTests
{
    private static readonly string[] Rules={"R589"};
    private static PortableCaptureFrame Frame()
    {
        var payload=Encoding.ASCII.GetBytes("GET /config/keystore/test.jsp HTTP/1.1\r\nHost: example.test\r\n\r\n");
        var b=new byte[40+payload.Length];
        b[0]=0x45;b[8]=64;b[9]=6;
        new byte[]{192,0,2,1,198,51,100,2}.CopyTo(b,12);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2),(ushort)b.Length);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(20),51000);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(22),7001);
        b[32]=0x50;b[33]=0x18;payload.CopyTo(b,40);
        return new(b,(uint)b.Length,DateTime.UnixEpoch);
    }

    private sealed class Source : IPortableCaptureSource
    {
        internal readonly List<string> Calls=new();
        internal readonly TaskCompletionSource<bool> Reading=new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int Link=101;
        internal bool FailStart,FailRead,FailStop,FailDispose,BlockRead;
        internal PortableCaptureFrame? Next;
        public ValueTask<int> StartAsync(CancellationToken token)
        {
            Calls.Add("start");
            if(FailStart) throw new InvalidOperationException("private startup detail");
            return ValueTask.FromResult(Link);
        }
        public async ValueTask<PortableCaptureFrame?> ReadAsync(CancellationToken token)
        {
            Calls.Add("read");Reading.TrySetResult(true);
            if(FailRead) throw new InvalidOperationException("private read detail");
            if(BlockRead) await Task.Delay(Timeout.InfiniteTimeSpan,token);
            var frame=Next;Next=null;return frame;
        }
        public ValueTask StopAsync()
        {
            Calls.Add("stop");
            if(FailStop) throw new InvalidOperationException("private stop detail");
            return ValueTask.CompletedTask;
        }
        public ValueTask DisposeAsync()
        {
            Calls.Add("dispose");
            if(FailDispose) throw new InvalidOperationException("private dispose detail");
            return ValueTask.CompletedTask;
        }
    }

    [Fact]
    public async Task FiniteSourceDeliversObservationAndCleansUpInOrder()
    {
        var source=new Source{Next=Frame()};
        var observations=new List<PortableMonitorSession.FrameResult>();
        var result=await PortableCaptureRun.RunAsync(source,Rules,default,true,observations.Add);
        Assert.Equal(PortableCaptureRun.Completion.EndOfSource,result.Status);
        Assert.Null(result.Failure);
        Assert.Equal(new[]{"start","read","read","stop","dispose"},source.Calls);
        Assert.Equal("R589",Assert.Single(Assert.Single(observations).Findings).RuleId);
        Assert.Equal(1L,result.Snapshot!.Matches);
    }

    [Fact]
    public async Task LiveEofIsFailureNotSuccessfulShutdown()
    {
        var source=new Source();
        var result=await PortableCaptureRun.RunAsync(source,Rules,default);
        Assert.Equal(PortableCaptureRun.Completion.Failed,result.Status);
        Assert.Equal("unexpected_end_of_source",result.Failure);
        Assert.Equal(new[]{"start","read","stop","dispose"},source.Calls);
    }

    [Fact]
    public async Task PartialStartupFailureStillStopsAndDisposes()
    {
        var source=new Source{FailStart=true};
        var result=await PortableCaptureRun.RunAsync(source,Rules,default);
        Assert.Equal(PortableCaptureRun.Completion.Failed,result.Status);
        Assert.Equal("startup_failed",result.Failure);
        Assert.Null(result.Snapshot);
        Assert.Equal(new[]{"start","stop","dispose"},source.Calls);
    }

    [Fact]
    public async Task UnsupportedLinkFailsBeforeReading()
    {
        var source=new Source{Link=999};
        var result=await PortableCaptureRun.RunAsync(source,Rules,default);
        Assert.Equal("startup_failed",result.Failure);
        Assert.Equal(new[]{"start","stop","dispose"},source.Calls);
    }

    [Fact]
    public async Task ReadFailureRetainsSnapshotAndCleansUp()
    {
        var source=new Source{FailRead=true};
        var result=await PortableCaptureRun.RunAsync(source,Rules,default);
        Assert.Equal("read_failed",result.Failure);
        Assert.Equal(0L,result.Snapshot!.Received);
        Assert.Equal(new[]{"start","read","stop","dispose"},source.Calls);
    }

    [Fact]
    public async Task CancelledReadUnblocksBeforeCleanup()
    {
        var source=new Source{BlockRead=true};
        using var cancel=new CancellationTokenSource();
        var run=PortableCaptureRun.RunAsync(source,Rules,cancel.Token);
        try
        {
            await source.Reading.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancel.Cancel();
            var result=await run.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(PortableCaptureRun.Completion.Cancelled,result.Status);
            Assert.Equal(new[]{"start","read","stop","dispose"},source.Calls);
        }
        finally { cancel.Cancel(); }
    }

    [Fact]
    public async Task PreCancelledSourceIsDisposedWithoutStart()
    {
        var source=new Source();
        using var cancel=new CancellationTokenSource();cancel.Cancel();
        var result=await PortableCaptureRun.RunAsync(source,Rules,cancel.Token);
        Assert.Equal(PortableCaptureRun.Completion.Cancelled,result.Status);
        Assert.Equal(new[]{"dispose"},source.Calls);
    }

    [Fact]
    public async Task InvalidSelectionDoesNotStartSource()
    {
        var source=new Source();
        var result=await PortableCaptureRun.RunAsync(source,new[]{"R1000"},default);
        Assert.Equal("configuration_failed",result.Failure);
        Assert.Equal(new[]{"dispose"},source.Calls);
    }

    [Fact]
    public async Task ObservationFailureRetainsProcessedFrameAndStops()
    {
        var source=new Source{Next=Frame()};
        var result=await PortableCaptureRun.RunAsync(source,Rules,default,true,_=>throw new InvalidOperationException());
        Assert.Equal("observation_failed",result.Failure);
        Assert.Equal(1L,result.Snapshot!.Matches);
        Assert.Equal(new[]{"start","read","stop","dispose"},source.Calls);
    }

    [Fact]
    public async Task CleanupFailuresOverrideSuccessButPreservePrimaryFailure()
    {
        var source=new Source{FailStop=true,FailDispose=true};
        var result=await PortableCaptureRun.RunAsync(source,Rules,default,true);
        Assert.Equal(PortableCaptureRun.Completion.Failed,result.Status);
        Assert.Equal("cleanup_failed",result.Failure);
        Assert.True(result.StopFailed);Assert.True(result.DisposeFailed);
        Assert.Equal(new[]{"start","read","stop","dispose"},source.Calls);
        source=new Source{FailRead=true,FailStop=true};
        result=await PortableCaptureRun.RunAsync(source,Rules,default);
        Assert.Equal("read_failed",result.Failure);
        Assert.True(result.StopFailed);Assert.False(result.DisposeFailed);
    }
}
