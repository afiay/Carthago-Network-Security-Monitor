// SPDX-License-Identifier: MIT
using System.Runtime.InteropServices;
using Carthago.Cli;
using Carthago.Services;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class NativePcapCaptureSourceTests
{
    private sealed class Api:NativePcapCaptureSource.IApi
    {
        internal int Link=101,Opens,Reads,Closes,Disposals;
        internal bool FailOpen,FailStats;
        internal int StatsCalls;
        internal readonly List<string> Cleanup=new();
        internal int Code=1;
        internal string? Id;
        internal PortableCaptureFrame? Frame=new(new byte[]{0x45},1,DateTime.UnixEpoch);
        internal readonly TaskCompletionSource<bool> Reading=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Open(string id)
        { Opens++;Id=id;if(FailOpen)throw new InvalidOperationException();return Link; }
        public int Next(out PortableCaptureFrame? frame)
        { Reads++;Reading.TrySetResult(true);frame=Frame;return Code; }
        public NativePcapCaptureSource.DriverStatistics ReadStatistics()
        {
            StatsCalls++;Cleanup.Add("stats");
            if(FailStats)throw new InvalidOperationException();
            return new("available",12,2,null,"not_reported_on_windows");
        }
        public void Close(){Closes++;Cleanup.Add("close");}
        public void Dispose(){Disposals++;Cleanup.Add("dispose");}
    }

    [Fact]
    public async Task StartReadStopDisposeOwnsSourceOnce()
    {
        var api=new Api();var source=new NativePcapCaptureSource("eth0",()=>api);
        Assert.Equal(101,await source.StartAsync(default));
        Assert.Equal("eth0",api.Id);Assert.Equal(1,api.Opens);
        Assert.Same(api.Frame,await source.ReadAsync(default));
        await source.StopAsync();await source.StopAsync();
        await source.DisposeAsync();await source.DisposeAsync();
        Assert.Equal(1,api.Closes);Assert.Equal(1,api.Disposals);
        await Assert.ThrowsAsync<InvalidOperationException>(async()=>{await source.StartAsync(default);});
    }

    [Fact]
    public async Task PartialOpenFailureStillClosesAndDisposes()
    {
        var api=new Api{FailOpen=true};var source=new NativePcapCaptureSource("eth0",()=>api);
        var result=await PortableCaptureRun.RunAsync(source,new[]{"R589"},default);
        Assert.Equal("startup_failed",result.Failure);
        Assert.Equal(1,api.Closes);Assert.Equal(1,api.Disposals);Assert.Equal(0,api.Reads);
    }

    [Fact]
    public async Task UnsupportedLinkNeverReads()
    {
        var api=new Api{Link=999};var source=new NativePcapCaptureSource("eth0",()=>api);
        var result=await PortableCaptureRun.RunAsync(source,new[]{"R589"},default);
        Assert.Equal("startup_failed",result.Failure);
        Assert.Equal(0,api.Reads);Assert.Equal(1,api.Closes);
    }

    [Theory]
    [InlineData(-1,"read_failed")]
    [InlineData(-2,"unexpected_end_of_source")]
    public async Task ReadErrorAndLiveEofFailClosed(int code,string reason)
    {
        var api=new Api{Code=code};var source=new NativePcapCaptureSource("eth0",()=>api);
        var result=await PortableCaptureRun.RunAsync(source,new[]{"R589"},default);
        Assert.Equal(reason,result.Failure);Assert.Equal(1,api.Closes);Assert.Equal(1,api.Disposals);
    }

    [Fact]
    public async Task IdlePollCancellationUnblocks()
    {
        var api=new Api{Code=0};var source=new NativePcapCaptureSource("eth0",()=>api);
        using var cancel=new CancellationTokenSource();
        var run=PortableCaptureRun.RunAsync(source,new[]{"R589"},cancel.Token);
        try
        {
            await api.Reading.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancel.Cancel();
            var result=await run.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(PortableCaptureRun.Completion.Cancelled,result.Status);
            Assert.Equal(1,api.Closes);Assert.Equal(1,api.Disposals);
        }
        finally{cancel.Cancel();}
    }

    [Fact]
    public async Task PreCancelledDoesNotLoadNativeApi()
    {
        var source=new NativePcapCaptureSource("eth0",()=>throw new Exception());
        using var cancel=new CancellationTokenSource();cancel.Cancel();
        var result=await PortableCaptureRun.RunAsync(source,new[]{"R589"},cancel.Token);
        Assert.Equal(PortableCaptureRun.Completion.Cancelled,result.Status);
    }

    [Theory]
    [InlineData("")]
    [InlineData("rpcap://host/eth0")]
    [InlineData("bad\nname")]
    public void RejectsInvalidOrRemoteInterface(string id)
        =>Assert.Throws<ArgumentException>(()=>new NativePcapCaptureSource(id));

    private static void Header(IntPtr h,bool windows,long seconds,long micros,uint captured,uint original)
    {
        if(windows){Marshal.WriteInt32(h,0,(int)seconds);Marshal.WriteInt32(h,4,(int)micros);}
        else{Marshal.WriteInt64(h,0,seconds);Marshal.WriteInt64(h,8,micros);}
        int offset=windows?8:16;
        Marshal.WriteInt32(h,offset,unchecked((int)captured));
        Marshal.WriteInt32(h,offset+4,unchecked((int)original));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void NativeHeaderLayoutsCopyDataAndPreserveTruncation(bool windows)
    {
        var h=Marshal.AllocHGlobal(24);var p=Marshal.AllocHGlobal(2);
        try
        {
            Header(h,windows,100,123456,2,4);
            Marshal.WriteByte(p,0,0x45);Marshal.WriteByte(p,1,0x01);
            var frame=NativePcapCaptureSource.DecodePacket(h,p,windows);
            Marshal.WriteByte(p,0,0);
            Assert.Equal(new byte[]{0x45,0x01},frame.Data);
            Assert.Equal(4u,frame.OriginalLength);
            Assert.Equal(DateTime.UnixEpoch.AddSeconds(100).AddTicks(1234560),frame.TimestampUtc);
            Assert.Equal(DateTimeKind.Utc,frame.TimestampUtc.Kind);
        }
        finally{Marshal.FreeHGlobal(p);Marshal.FreeHGlobal(h);}
    }

    [Theory]
    [InlineData(-1,0,1,1)]
    [InlineData(1,1000000,1,1)]
    [InlineData(1,0,2,1)]
    [InlineData(1,0,262145,262145)]
    public void InvalidHeaderRejectedBeforeDereferencingData(long seconds,long micros,int captured,int original)
    {
        var h=Marshal.AllocHGlobal(24);
        try
        {
            Header(h,false,seconds,micros,(uint)captured,(uint)original);
            Assert.Throws<InvalidDataException>(()=>NativePcapCaptureSource.DecodePacket(h,IntPtr.Zero,false));
        }
        finally{Marshal.FreeHGlobal(h);}
    }

    [Fact]
    public async Task StatisticsSampledOnceBeforeCloseAndRetainedAfterDispose()
    {
        var api=new Api();var source=new NativePcapCaptureSource("eth0",()=>api);
        Assert.Equal("not_attempted",source.FinalStatistics.Status);
        await source.StartAsync(default);
        await source.StopAsync();await source.DisposeAsync();await source.DisposeAsync();
        Assert.Equal(new[]{"stats","close","dispose"},api.Cleanup);
        Assert.Equal("available",source.FinalStatistics.Status);
        Assert.Equal(12u,source.FinalStatistics.Received);
        Assert.Equal(2u,source.FinalStatistics.BufferDropped);
        Assert.Null(source.FinalStatistics.InterfaceDropped);
    }

    [Fact]
    public async Task StatisticsFailureDoesNotPreventCleanup()
    {
        var api=new Api{FailStats=true};var source=new NativePcapCaptureSource("eth0",()=>api);
        await source.StartAsync(default);await source.DisposeAsync();
        Assert.Equal("unavailable",source.FinalStatistics.Status);
        Assert.Null(source.FinalStatistics.Received);
        Assert.Equal(new[]{"stats","close","dispose"},api.Cleanup);
    }

    [Fact]
    public async Task FailedStartupDoesNotSampleInactiveHandle()
    {
        var api=new Api{FailOpen=true};var source=new NativePcapCaptureSource("eth0",()=>api);
        await PortableCaptureRun.RunAsync(source,new[]{"R589"},default);
        Assert.Equal("not_attempted",source.FinalStatistics.Status);
        Assert.Equal(0,api.StatsCalls);
        Assert.Equal(new[]{"close","dispose"},api.Cleanup);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void StatisticsDecodeUnsignedCountersAndProviderLimitations(bool windows)
    {
        var p=Marshal.AllocHGlobal(24);
        try
        {
            Marshal.WriteInt32(p,0,-1);Marshal.WriteInt32(p,4,3);Marshal.WriteInt32(p,8,7);
            var sample=NativePcapCaptureSource.DecodeStatistics(p,windows);
            Assert.Equal(uint.MaxValue,sample.Received);
            Assert.Equal(3u,sample.BufferDropped);
            Assert.Equal(windows?(uint?)null:7u,sample.InterfaceDropped);
        }
        finally{Marshal.FreeHGlobal(p);}
    }

    [Fact]
    public void NullDataWithNonzeroLengthRejected()
    {
        var h=Marshal.AllocHGlobal(24);
        try
        {
            Header(h,false,1,0,1,1);
            Assert.Throws<InvalidDataException>(()=>NativePcapCaptureSource.DecodePacket(h,IntPtr.Zero,false));
        }
        finally{Marshal.FreeHGlobal(h);}
    }
}
