// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.Text;
using Carthago.Services;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableBufferedCaptureTests
{
    private static PortableCaptureFrame Frame(int seconds=0)
    {
        var payload=Encoding.ASCII.GetBytes("GET /config/keystore/test.jsp HTTP/1.1\r\nHost: example.test\r\n\r\n");
        var b=new byte[40+payload.Length];
        b[0]=0x45;b[8]=64;b[9]=6;
        new byte[]{192,0,2,1,198,51,100,2}.CopyTo(b,12);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2),(ushort)b.Length);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(20),51000);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(22),7001);
        b[32]=0x50;b[33]=0x18;payload.CopyTo(b,40);
        return new(b,(uint)b.Length,DateTime.UnixEpoch.AddSeconds(seconds));
    }
    private static void Balanced(PortableFrameQueue.Counters s)
    {
        Assert.Equal(s.Captured,s.Accepted+s.DroppedCapacity+s.DroppedInvalid);
        Assert.Equal(s.Accepted,s.Processed+s.Abandoned+s.Pending);
    }

    [Fact]
    public async Task PacketLimitAndOwnershipIncludeInFlight()
    {
        var q=new PortableFrameQueue(1,4096);
        var frame=Frame();
        Assert.True(q.Offer(frame));frame.Data[0]=0;
        await using var reader=q.ReadAllAsync().GetAsyncEnumerator();
        Assert.True(await reader.MoveNextAsync());
        Assert.Equal(0x45,reader.Current.Data[0]);
        Assert.False(q.Offer(Frame(1)));
        Assert.Equal(1,q.ReadCounters().Pending);
        q.Finish(reader.Current,true);
        Assert.True(q.Offer(Frame(2)));q.Complete();
        Assert.True(await reader.MoveNextAsync());
        Assert.Equal(DateTime.UnixEpoch.AddSeconds(2),reader.Current.TimestampUtc);
        q.Finish(reader.Current,false);
        Assert.False(await reader.MoveNextAsync());
        var s=q.ReadCounters();Balanced(s);
        Assert.Equal(1L,s.Processed);Assert.Equal(1L,s.Abandoned);
        Assert.Equal(1L,s.DroppedCapacity);Assert.Equal(0L,s.PendingBytes);
    }

    [Fact]
    public async Task ByteLimitAndInvalidMetadataAreSeparateDrops()
    {
        var frame=Frame();var q=new PortableFrameQueue(10,frame.Data.Length);
        Assert.True(q.Offer(frame));Assert.False(q.Offer(Frame(1)));
        Assert.False(q.Offer(frame with { OriginalLength=0 }));
        Assert.False(q.Offer(frame with { TimestampUtc=DateTime.SpecifyKind(DateTime.UnixEpoch,DateTimeKind.Unspecified) }));
        q.Complete();
        await foreach(var item in q.ReadAllAsync())q.Finish(item,true);
        var s=q.ReadCounters();Balanced(s);
        Assert.Equal(1L,s.DroppedCapacity);Assert.Equal(2L,s.DroppedInvalid);
        Assert.Equal((long)frame.Data.Length,s.PeakPendingBytes);
    }

    private sealed class Source:IPortableCaptureSource
    {
        internal int Count=3;
        internal bool BlockAtEnd,FailStart,FailRead,FailStop,FailDispose;
        internal int ReadCount,Stops,Disposals;
        internal readonly TaskCompletionSource<bool> Blocked=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ValueTask<int> StartAsync(CancellationToken token)
            =>FailStart?ValueTask.FromException<int>(new InvalidOperationException()):ValueTask.FromResult(101);
        public async ValueTask<PortableCaptureFrame?> ReadAsync(CancellationToken token)
        {
            if(ReadCount<Count)return Frame(ReadCount++);
            if(FailRead)throw new InvalidOperationException();
            if(BlockAtEnd){Blocked.TrySetResult(true);await Task.Delay(Timeout.InfiniteTimeSpan,token);}
            return null;
        }
        public ValueTask StopAsync(){Stops++;return FailStop?ValueTask.FromException(new InvalidOperationException()):ValueTask.CompletedTask;}
        public ValueTask DisposeAsync(){Disposals++;return FailDispose?ValueTask.FromException(new InvalidOperationException()):ValueTask.CompletedTask;}
    }

    [Fact]
    public async Task FiniteSourceDrainsAndRetainsOrderedFindings()
    {
        var s=new Source();var seen=new List<long>();
        var r=await PortableBufferedCaptureRun.RunAsync(s,new[]{"R589"},default,10,4096,true,
            f=>seen.Add(f.PacketNumber));
        Assert.Equal(PortableCaptureRun.Completion.EndOfSource,r.Status);
        Assert.Equal(new long[]{1,2,3},seen);
        Assert.Equal(3L,r.Pipeline.Processed);Assert.Equal(0L,r.Pipeline.Abandoned);
        Assert.Equal(1L,r.Snapshot!.Matches);Assert.Equal(2L,r.Snapshot.Suppressed);
        Assert.Equal(1,s.Stops);Assert.Equal(1,s.Disposals);Balanced(r.Pipeline);
    }

    [Fact]
    public async Task CancellationDrainsAcceptedFramesBeforeCleanup()
    {
        var s=new Source{BlockAtEnd=true};using var cancel=new CancellationTokenSource();
        var run=PortableBufferedCaptureRun.RunAsync(s,new[]{"R589"},cancel.Token,10,4096);
        try
        {
            await s.Blocked.Task.WaitAsync(TimeSpan.FromSeconds(5));cancel.Cancel();
            var r=await run.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(PortableCaptureRun.Completion.Cancelled,r.Status);
            Assert.Equal(3L,r.Pipeline.Processed);Assert.Equal(0L,r.Pipeline.Abandoned);
            Assert.Equal(0,r.Pipeline.Pending);Assert.Equal(1,s.Stops);Assert.Equal(1,s.Disposals);
            Balanced(r.Pipeline);
        }
        finally{cancel.Cancel();}
    }

    [Fact]
    public async Task ObserverFailureAbandonsRemainingAcceptedFramesAndStopsReading()
    {
        var s=new Source{BlockAtEnd=true};using var cancel=new CancellationTokenSource();
        // Wait for producer to enqueue all three before failing first observation.
        var run=PortableBufferedCaptureRun.RunAsync(s,new[]{"R589"},cancel.Token,10,4096,
            observe:_=>{s.Blocked.Task.WaitAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();throw new InvalidOperationException();});
        try
        {
            var r=await run.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal(PortableCaptureRun.Completion.Failed,r.Status);
            Assert.Equal("observation_failed",r.Failure);
            Assert.Equal(1L,r.Pipeline.Processed);Assert.Equal(2L,r.Pipeline.Abandoned);
            Assert.Equal(0,r.Pipeline.Pending);Assert.Equal(1,s.Stops);Assert.Equal(1,s.Disposals);
            Balanced(r.Pipeline);
        }
        finally{cancel.Cancel();}
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnexpectedEndOrReadFailureDrainsBeforeReportingFailure(bool failRead)
    {
        var s=new Source{FailRead=failRead};
        var r=await PortableBufferedCaptureRun.RunAsync(s,new[]{"R589"},default,10,4096);
        Assert.Equal(PortableCaptureRun.Completion.Failed,r.Status);
        Assert.Equal(failRead?"read_failed":"unexpected_end_of_source",r.Failure);
        Assert.Equal(3L,r.Pipeline.Processed);Assert.Equal(0L,r.Pipeline.Abandoned);Balanced(r.Pipeline);
    }

    [Fact]
    public async Task StartupAndCleanupFailuresPreservePrimaryReason()
    {
        var s=new Source{FailStart=true,FailStop=true,FailDispose=true};
        var r=await PortableBufferedCaptureRun.RunAsync(s,new[]{"R589"},default);
        Assert.Equal("startup_failed",r.Failure);Assert.True(r.StopFailed);Assert.True(r.DisposeFailed);
        Assert.Equal(1,s.Stops);Assert.Equal(1,s.Disposals);Balanced(r.Pipeline);
    }

    [Theory]
    [InlineData(0,1)]
    [InlineData(4097,1)]
    [InlineData(1,0)]
    [InlineData(1,67108865)]
    public void InvalidQueueBoundsFailClosed(int packets,long bytes)
        =>Assert.Throws<ArgumentOutOfRangeException>(()=>new PortableFrameQueue(packets,bytes));
}
